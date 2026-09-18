package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

// RulesDoc: 规则编辑页的结构化载荷
type RulesDoc struct {
	RuleSets   []RuleSet `json:"rule_sets"`
	DnsRules   []Rule    `json:"dns_rules"`
	RouteRules []Rule    `json:"route_rules"`
}

func (s *Server) apiRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c, err := s.loadCfg()
		if err != nil {
			errOut(w, 500, err.Error())
			return
		}
		jsonOut(w, RulesDoc{RuleSets: c.RuleSets, DnsRules: c.DnsRules, RouteRules: c.RouteRules})
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		var doc RulesDoc
		if err := json.Unmarshal(body, &doc); err != nil {
			errOut(w, 400, "JSON 解析失败: "+err.Error())
			return
		}
		if len(doc.DnsRules) == 0 || len(doc.RouteRules) == 0 {
			errOut(w, 400, "dns_rules / route_rules 不能为空")
			return
		}
		if err := s.spliceRules(doc); err != nil {
			errOut(w, 500, err.Error())
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	default:
		errOut(w, 405, "method")
	}
}

// ---------- YAML 定点改写基础设施 ----------

// findValue 在映射节点中查找键的值节点
func findValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// setValue 设置映射节点的键值（存在则替换值节点，保持键节点注释；不存在则追加）
func setValue(m *yaml.Node, key string, v any) error {
	if m == nil || m.Kind != yaml.MappingNode {
		return fmt.Errorf("目标不是映射节点（key=%s）", key)
	}
	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		return fmt.Errorf("%s 编码失败: %w", key, err)
	}
	val := n
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		val = n.Content[0]
	}
	switch val.Kind {
	case yaml.SequenceNode, yaml.MappingNode, yaml.ScalarNode:
	default:
		return fmt.Errorf("%s 编码结果异常（kind=%d）", key, val.Kind)
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return nil
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
	return nil
}

// mutateConfig 定点改写 homelab.yaml：写前干跑校验、写前备份、2 空格缩进
func (s *Server) mutateConfig(fn func(root *yaml.Node) error) error {
	path := s.dataDir + "/homelab.yaml"
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return err
	}
	if len(root.Content) == 0 {
		return fmt.Errorf("配置文件为空")
	}
	if err := fn(root.Content[0]); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if _, err := LoadConfig2(buf.String()); err != nil {
		return fmt.Errorf("拒绝写入：生成结果无法加载（已保留原文件）: %w", err)
	}
	if err := os.WriteFile(path+".bak", b, 0600); err != nil {
		return fmt.Errorf("备份失败: %w", err)
	}
	return os.WriteFile(path, buf.Bytes(), 0600)
}

// spliceRules 仅替换 rule_sets / dns_rules / route_rules 三个节点，其余内容（含注释）原样保留
func (s *Server) spliceRules(doc RulesDoc) error {
	return s.mutateConfig(func(root *yaml.Node) error {
		if err := setValue(root, "rule_sets", doc.RuleSets); err != nil {
			return err
		}
		if err := setValue(root, "dns_rules", doc.DnsRules); err != nil {
			return err
		}
		return setValue(root, "route_rules", doc.RouteRules)
	})
}

// apiModes：读取/设置模式启用状态与默认模式（定点改写 SFL.modes.<m>.enabled / SFL.default_mode）
func (s *Server) apiModes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c, err := s.loadCfg()
		if err != nil {
			errOut(w, 500, err.Error())
			return
		}
		en := map[string]bool{}
		for _, m := range gatewayModes {
			if ms, ok := c.SFL.Modes[m]; ok && ms.Enabled {
				en[m] = true
			}
		}
		jsonOut(w, map[string]any{"enabled": en, "default_mode": c.SFL.DefaultMode})
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		var req struct {
			Mode        string `json:"mode"`
			Enabled     *bool  `json:"enabled"`
			DefaultMode string `json:"default_mode"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			errOut(w, 400, "JSON 解析失败: "+err.Error())
			return
		}
		if req.Mode != "" {
			if req.Enabled == nil {
				errOut(w, 400, "需要 enabled 字段")
				return
			}
			err = s.mutateConfig(func(root *yaml.Node) error {
				m := findValue(findValue(findValue(root, "SFL"), "modes"), req.Mode)
				if m == nil {
					return fmt.Errorf("SFL.modes.%s 不存在", req.Mode)
				}
				return setValue(m, "enabled", *req.Enabled)
			})
		} else if req.DefaultMode != "" {
			err = s.mutateConfig(func(root *yaml.Node) error {
				return setValue(findValue(root, "SFL"), "default_mode", req.DefaultMode)
			})
		} else {
			errOut(w, 400, "需要 mode+enabled 或 default_mode")
			return
		}
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	default:
		errOut(w, 405, "method")
	}
}

// ensureMap：取得（必要时创建）嵌套映射节点
func ensureMap(m *yaml.Node, key string) *yaml.Node {
	if v := findValue(m, key); v != nil {
		if v.Kind == yaml.MappingNode {
			return v
		}
		return nil
	}
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, n)
	return n
}

// ModuleInfo：模块状态（供 UI 渲染勾选框）
type ModuleInfo struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Builtin    bool   `json:"builtin"`
	HasContent bool   `json:"has_content"`
}

// apiModules：GET 列出各目标端模块状态；PUT {target,module,enabled} 定点写回
func (s *Server) apiModules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c, err := s.loadCfg()
		if err != nil {
			errOut(w, 500, fmt.Sprintf("配置加载失败（%s/homelab.yaml）: %v", s.dataDir, err))
			return
		}
		targets := map[string][]ModuleInfo{}
		for _, t := range AllTargets {
			list := make([]ModuleInfo, 0, len(AllModules))
			for _, m := range AllModules {
				_, hasExtra := c.ExtraOf(t, m)
				list = append(list, ModuleInfo{
					Name:       m,
					Enabled:    c.ModuleEnabled(t, m),
					Builtin:    builtinModules[m],
					HasContent: builtinModules[m] || hasExtra,
				})
			}
			targets[t] = list
		}
		jsonOut(w, map[string]any{"targets": targets, "all": AllModules, "order": c.OrderedModules()})
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		var req struct {
			Target  string   `json:"target"`
			Module  string   `json:"module"`
			Enabled *bool    `json:"enabled"`
			Order   []string `json:"order"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			errOut(w, 400, "JSON 解析失败: "+err.Error())
			return
		}
		if len(req.Order) > 0 {
			valid := map[string]bool{}
			for _, m := range AllModules {
				valid[m] = true
			}
			for _, m := range req.Order {
				if !valid[m] {
					errOut(w, 400, "order 含未知模块: "+m)
					return
				}
			}
			if err := s.mutateConfig(func(root *yaml.Node) error {
				return setValue(root, "module_order", req.Order)
			}); err != nil {
				errOut(w, 400, err.Error())
				return
			}
			jsonOut(w, map[string]bool{"ok": true})
			return
		}
		known := false
		for _, m := range AllModules {
			if m == req.Module {
				known = true
			}
		}
		if !known || req.Enabled == nil {
			errOut(w, 400, "需要 target + 合法 module + enabled")
			return
		}
		valid := false
		for _, t := range AllTargets {
			if t == req.Target {
				valid = true
			}
		}
		if !valid {
			errOut(w, 400, "target 需要 SFL/SFA/SFI")
			return
		}
		err = s.mutateConfig(func(root *yaml.Node) error {
			mods := ensureMap(root, "modules")
			if mods == nil {
				return fmt.Errorf("modules 不是映射")
			}
			tm := ensureMap(mods, req.Target)
			if tm == nil {
				return fmt.Errorf("modules.%s 不是映射", req.Target)
			}
			return setValue(tm, req.Module, *req.Enabled)
		})
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	default:
		errOut(w, 405, "method")
	}
}

// apiExtra：读取/写入非建模模块的原样内容（extra.<target>.<module>）
func (s *Server) apiExtra(w http.ResponseWriter, r *http.Request) {
	c, err := s.loadCfg()
	if err != nil {
		errOut(w, 500, fmt.Sprintf("配置加载失败（%s/homelab.yaml）: %v", s.dataDir, err))
		return
	}
	switch r.Method {
	case http.MethodGet:
		target := r.URL.Query().Get("target")
		module := r.URL.Query().Get("module")
		known := false
		for _, m := range AllModules {
			if m == module {
				known = true
			}
		}
		if !known {
			errOut(w, 400, "未知模块: "+module)
			return
		}
		content, has := c.ExtraOf(target, module)
		jsonOut(w, map[string]any{"target": target, "module": module, "content": content, "has": has, "builtin": builtinModules[module]})
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		var req struct {
			Target  string `json:"target"`
			Module  string `json:"module"`
			Content any    `json:"content"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			errOut(w, 400, "JSON 解析失败: "+err.Error())
			return
		}
		known := false
		for _, m := range AllModules {
			if m == req.Module {
				known = true
			}
		}
		okTarget := false
		for _, t := range AllTargets {
			if t == req.Target {
				okTarget = true
			}
		}
		if !known || !okTarget {
			errOut(w, 400, "需要合法 target + module")
			return
		}
		if builtinModules[req.Module] {
			errOut(w, 400, "模块 "+req.Module+" 为内置模块，内容由 YAML 结构化字段生成（不支持 extra 编辑）")
			return
		}
		if req.Content == nil {
			errOut(w, 400, "content 不能为空")
			return
		}
		err = s.mutateConfig(func(root *yaml.Node) error {
			ext := ensureMap(root, "extra")
			if ext == nil {
				return fmt.Errorf("extra 不是映射")
			}
			tm := ensureMap(ext, req.Target)
			if tm == nil {
				return fmt.Errorf("extra.%s 不是映射", req.Target)
			}
			if err := setValue(tm, req.Module, req.Content); err != nil {
				return err
			}
			// 顺带启用该模块，勾选即生效
			mods := ensureMap(root, "modules")
			if mods != nil {
				if tm2 := ensureMap(mods, req.Target); tm2 != nil {
					return setValue(tm2, req.Module, true)
				}
			}
			return nil
		})
		if err != nil {
			errOut(w, 400, err.Error())
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	default:
		errOut(w, 405, "method")
	}
}
