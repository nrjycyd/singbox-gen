package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
)

type Server struct {
	dataDir string
	mu      sync.Mutex
}

func (s *Server) loadCfg() (*Config, error) { return LoadConfig(s.dataDir + "/homelab.yaml") }

// 本工具面向可信内网自用，不含鉴权；如需暴露公网请在反向代理层加认证

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func errOut(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) HandleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/config", s.apiConfig)
	mux.HandleFunc("/api/status", s.apiStatus)
	mux.HandleFunc("/api/rules", s.apiRules)
	mux.HandleFunc("/api/modes", s.apiModes)
	mux.HandleFunc("/api/modules", s.apiModules)
	mux.HandleFunc("/api/extra", s.apiExtra)
	mux.HandleFunc("/api/preview", s.apiPreview)
	mux.HandleFunc("/api/push", s.apiPush)
	mux.HandleFunc("/download/SFL", s.dlSFL)
	mux.HandleFunc("/download/SFA", func(w http.ResponseWriter, r *http.Request) { s.dlPhone(w, r, TgtSFA) })
	mux.HandleFunc("/download/SFI", func(w http.ResponseWriter, r *http.Request) { s.dlPhone(w, r, TgtSFI) })
	mux.HandleFunc("/p/", s.serveProfile)
	mux.HandleFunc("/ui_rules.js", func(w http.ResponseWriter, r *http.Request) {
		b, _ := uiFS.ReadFile("ui_rules.js")
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, _ := uiFS.ReadFile("ui.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
	})
}

func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 直接回原文件文本（保留注释），不做重排
		b, err := os.ReadFile(s.dataDir + "/homelab.yaml")
		if err != nil {
			errOut(w, 500, fmt.Sprintf("读取配置失败（%s/homelab.yaml）: %v", s.dataDir, err))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		if _, err := LoadConfig2(string(body)); err != nil {
			errOut(w, 400, err.Error())
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := os.WriteFile(s.dataDir+"/homelab.yaml", body, 0600); err != nil {
			errOut(w, 500, err.Error())
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	default:
		errOut(w, 405, "method")
	}
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]any{"sample": IsSampleConfig(s.dataDir)})
}

// renderAll：SFL（按模式分组）+ SFA / SFI 单文件
func renderAll(c *Config, dataDir string) (sfl map[string]map[string]string, phones map[string]string, err error) {
	sfl, err = RenderSFLModes(c, dataDir)
	if err != nil {
		return
	}
	phones = map[string]string{}
	for _, t := range PhoneTargets {
		p, e := RenderPhone(c, t, dataDir)
		if e != nil {
			return nil, nil, fmt.Errorf("目标端 %s: %w", t, e)
		}
		phones[t] = p
	}
	return
}

// apiPreview：按需生成（GET /api/preview?target=SFL&mode=tun 或 target=SFA|SFI）
func (s *Server) apiPreview(w http.ResponseWriter, r *http.Request) {
	c, err := s.loadCfg()
	if err != nil {
		errOut(w, 500, fmt.Sprintf("配置加载失败（%s/homelab.yaml）: %v", s.dataDir, err))
		return
	}
	switch r.URL.Query().Get("target") {
	case TgtSFL:
		mode := r.URL.Query().Get("mode")
		ms, ok := c.SFL.Modes[mode]
		if !ok {
			errOut(w, 400, fmt.Sprintf("SFL 无此模式: %q（可用: tun/ebpf/tproxy）", mode))
			return
		}
		if !ms.Enabled {
			errOut(w, 400, fmt.Sprintf("SFL 模式 %s 未启用（可在上方勾选启用）", mode))
			return
		}
		files, err := RenderSFL(c, mode, s.dataDir)
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		if err := ValidateFiles(files); err != nil {
			errOut(w, 400, "产物校验失败: "+err.Error())
			return
		}
		jsonOut(w, map[string]any{"label": "SFL/" + mode, "files": files, "warnings": c.RuleWarnings()})
	case TgtSFA, TgtSFI:
		target := r.URL.Query().Get("target")
		p, err := RenderPhone(c, target, s.dataDir)
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		files := map[string]string{"v1.14-mobile-" + target + ".json": p}
		if err := ValidateFiles(files); err != nil {
			errOut(w, 400, "产物校验失败: "+err.Error())
			return
		}
		jsonOut(w, map[string]any{"label": target, "files": files, "warnings": c.RuleWarnings()})
	default:
		errOut(w, 400, "target 需要 SFL / SFA / SFI")
	}
}

func (s *Server) apiPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method")
		return
	}
	if IsSampleConfig(s.dataDir) {
		errOut(w, 400, "当前是自动生成的示例配置（占位节点），请先在 UI 中替换为真实配置再推送")
		return
	}
	c, err := s.loadCfg()
	if err != nil {
		errOut(w, 500, err.Error())
		return
	}
	// 推送模式：body {"mode":"tun"} 或 ?mode=，默认 default_mode
	var raw struct {
		Mode string `json:"mode"`
	}
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		_ = json.Unmarshal(b, &raw)
	}
	mode := raw.Mode
	if mode == "" {
		mode = r.URL.Query().Get("mode")
	}
	if mode == "" {
		mode = c.SFL.DefaultMode
	}
	enabled := false
	for _, m := range c.EnabledModes() {
		if m == mode {
			enabled = true
		}
	}
	if !enabled {
		errOut(w, 400, fmt.Sprintf("模式 %q 未启用（已启用: %v）", mode, c.EnabledModes()))
		return
	}
	gw, _, err := renderAll(c, s.dataDir)
	if err != nil {
		errOut(w, 400, "生成失败: "+err.Error())
		return
	}
	files := gw[mode]
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "推送模式: %s（%d 个文件）\n", mode, len(files))
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	p := &Pusher{spec: c.Push, dataDir: s.dataDir, logf: func(l string) {
		fmt.Fprintln(w, l)
		if flusher != nil {
			flusher.Flush()
		}
	}}
	if err := p.Deploy(files); err != nil {
		fmt.Fprintln(w, "失败: "+err.Error())
	}
}

func zipFiles(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := zw.Create(n)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write([]byte(files[n])); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) dlSFL(w http.ResponseWriter, r *http.Request) {
	c, err := s.loadCfg()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sfl, _, err := renderAll(c, s.dataDir)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	zipIn := map[string]string{}
	for mode, files := range sfl {
		for n, body := range files {
			zipIn[mode+"/"+n] = body
		}
	}
	b, err := zipFiles(zipIn)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="singbox-gen-SFL.zip"`)
	w.Write(b)
}

func (s *Server) dlPhone(w http.ResponseWriter, r *http.Request, target string) {
	c, err := s.loadCfg()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_, phones, err := renderAll(c, s.dataDir)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	body, ok := phones[target]
	if !ok {
		http.Error(w, "未知目标端: "+target, 400)
		return
	}
	b, err := zipFiles(map[string]string{"v1.14-mobile-" + target + ".json": body})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"singbox-gen-"+target+".zip\"")
	w.Write(b)
}

func (s *Server) serveProfile(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/p/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	target := ""
	switch strings.ToLower(parts[1]) {
	case "sfa.json":
		target = TgtSFA
	case "sfi.json":
		target = TgtSFI
	default:
		http.NotFound(w, r)
		return
	}
	c, err := s.loadCfg()
	if err != nil {
		http.Error(w, "config error", 500)
		return
	}
	if c.Secret.ProfileToken == "" || parts[0] != c.Secret.ProfileToken {
		http.Error(w, "forbidden", 403)
		return
	}
	_, phones, err := renderAll(c, s.dataDir)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(phones[target]))
}
