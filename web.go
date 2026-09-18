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

// authOK: secret.ui_token 为空 = 内网免鉴权；非空则要求 X-Token 匹配
func (s *Server) authOK(r *http.Request) bool {
	c, err := s.loadCfg()
	if err != nil {
		return false
	}
	if c.Secret.UIToken == "" {
		return true
	}
	return r.Header.Get("X-Token") == c.Secret.UIToken
}

// needAuth: 查询当前是否启用了鉴权
func (s *Server) needAuth() bool {
	c, err := s.loadCfg()
	return err == nil && c.Secret.UIToken != ""
}

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func errOut(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/status" && !s.authOK(r) {
			errOut(w, 401, "token 缺失或不正确（留空 secret.ui_token 可关闭鉴权）")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) HandleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/config", s.apiConfig)
	mux.HandleFunc("/api/status", s.apiStatus)
	mux.HandleFunc("/api/rules", s.apiRules)
	mux.HandleFunc("/api/preview", s.apiPreview)
	mux.HandleFunc("/api/push", s.apiPush)
	mux.HandleFunc("/download/gateway", s.dlGateway)
	mux.HandleFunc("/download/phone", s.dlPhone)
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
		b, err := os.ReadFile(s.dataDir + "/homelab.yaml")
		if err != nil {
			errOut(w, 500, err.Error())
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
	jsonOut(w, map[string]any{"sample": IsSampleConfig(s.dataDir), "auth": s.needAuth()})
}

func renderAll(c *Config, dataDir string) (gw map[string]string, phoneFull, phoneNoCmt string, err error) {
	gw, err = RenderGateway(c, dataDir)
	if err != nil {
		return
	}
	phoneFull, phoneNoCmt, err = RenderPhone(c, dataDir)
	return
}

func (s *Server) apiPreview(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var raw struct{ YAML string }
	if err := json.Unmarshal(body, &raw); err != nil || raw.YAML == "" {
		errOut(w, 400, "body 需要 {\"yaml\": ...}")
		return
	}
	c, err := LoadConfig2(raw.YAML)
	if err != nil {
		errOut(w, 400, err.Error())
		return
	}
	gw, full, nc, err := renderAll(c, s.dataDir)
	if err != nil {
		errOut(w, 400, err.Error())
		return
	}
	out := map[string]map[string]string{"gateway": gw, "phone": map[string]string{"v1.14-mobile-config.json": full, "v1.14-mobile-config.nocomment.json": nc}}
	// 自校验：产物必须可解析且引用闭环
	if err := ValidateFiles(out["phone"]); err != nil {
		errOut(w, 400, "phone 产物校验失败: "+err.Error())
		return
	}
	if err := ValidateFiles(gw); err != nil {
		errOut(w, 400, "gateway 产物校验失败: "+err.Error())
		return
	}
	jsonOut(w, out)
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
	gw, _, _, err := renderAll(c, s.dataDir)
	if err != nil {
		errOut(w, 400, "生成失败: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	flusher, _ := w.(http.Flusher)
	p := &Pusher{spec: c.Push, dataDir: s.dataDir, logf: func(l string) {
		fmt.Fprintln(w, l)
		if flusher != nil {
			flusher.Flush()
		}
	}}
	if err := p.Deploy(gw); err != nil {
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

func (s *Server) dlGateway(w http.ResponseWriter, r *http.Request) {
	c, err := s.loadCfg()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if c.Secret.UIToken != "" && r.URL.Query().Get("token") != c.Secret.UIToken {
		http.Error(w, "forbidden", 403)
		return
	}
	gw, _, _, err := renderAll(c, s.dataDir)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	b, err := zipFiles(gw)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="sfl-tun-conf.zip"`)
	w.Write(b)
}

func (s *Server) dlPhone(w http.ResponseWriter, r *http.Request) {
	c, err := s.loadCfg()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if c.Secret.UIToken != "" && r.URL.Query().Get("token") != c.Secret.UIToken {
		http.Error(w, "forbidden", 403)
		return
	}
	_, full, nc, err := renderAll(c, s.dataDir)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	b, err := zipFiles(map[string]string{"v1.14-mobile-config.json": full, "v1.14-mobile-config.nocomment.json": nc})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="sfi-phone.zip"`)
	w.Write(b)
}

func (s *Server) serveProfile(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/p/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[1] != "mobile.json" {
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
	_, full, _, err := renderAll(c, s.dataDir)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(full))
}
