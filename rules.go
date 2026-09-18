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

// spliceRules 仅替换 rule_sets / dns_rules / route_rules 三个节点，其余内容（含注释）原样保留
func (s *Server) spliceRules(doc RulesDoc) error {
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
	m := root.Content[0]
	setNode := func(key string, v any) error {
		n := &yaml.Node{}
		if err := n.Encode(v); err != nil {
			return fmt.Errorf("%s 编码失败: %w", key, err)
		}
		// Node.Encode 的结果本身即值节点；若被包成 Document，则取唯一子节点
		val := n
		if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
			val = n.Content[0]
		}
		switch val.Kind {
		case yaml.SequenceNode, yaml.MappingNode, yaml.ScalarNode:
		default:
			return fmt.Errorf("%s 编码结果异常（kind=%d，期望序列/映射/标量）", key, val.Kind)
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key {
				m.Content[i+1] = val // 只换值节点，键节点的注释保留
				return nil
			}
		}
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
		return nil
	}
	if err := setNode("rule_sets", doc.RuleSets); err != nil {
		return err
	}
	if err := setNode("dns_rules", doc.DnsRules); err != nil {
		return err
	}
	if err := setNode("route_rules", doc.RouteRules); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2) // 与手写配置保持一致的 2 空格缩进
	if err := enc.Encode(&root); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	// 写入前干跑一遍完整加载校验：避免写出"节点合法但类型化解码失败"的配置
	if _, err := LoadConfig2(buf.String()); err != nil {
		return fmt.Errorf("拒绝写入：生成结果无法加载（已保留原文件）: %w", err)
	}
	// 保留上一版可用配置，便于回滚
	if err := os.WriteFile(path+".bak", b, 0600); err != nil {
		return fmt.Errorf("备份失败: %w", err)
	}
	return os.WriteFile(path, buf.Bytes(), 0600)
}
