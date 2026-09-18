package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ValidateFiles 对产物做结构校验：每个文件可解析；
// route.rule_set / outbounds 定义 与 dns.rules/route.rules 引用闭环。
func ValidateFiles(files map[string]string) error {
	parsed := map[string]map[string]any{}
	for name, text := range files {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(StripComments(text)), &m); err != nil {
			return fmt.Errorf("%s 解析失败: %w", name, err)
		}
		parsed[name] = m
	}
	definedRS := map[string]bool{}
	definedOB := map[string]bool{}
	var refsRS, refsOB []string
	for _, m := range parsed {
		if rt, ok := m["route"].(map[string]any); ok {
			if list, ok := rt["rule_set"].([]any); ok {
				for _, e := range list {
					if mm, ok := e.(map[string]any); ok {
						definedRS[fmt.Sprint(mm["tag"])] = true
					}
				}
			}
			collectRuleRefs(rt["rules"], &refsRS, &refsOB)
		}
		if dn, ok := m["dns"].(map[string]any); ok {
			collectRuleRefs(dn["rules"], &refsRS, nil)
		}
		if ob, ok := m["outbounds"].([]any); ok {
			for _, e := range ob {
				if mm, ok := e.(map[string]any); ok {
					definedOB[fmt.Sprint(mm["tag"])] = true
				}
			}
		}
	}
	var miss []string
	for _, t := range refsRS {
		if !definedRS[t] {
			miss = append(miss, "rule_set:"+t)
		}
	}
	for _, t := range refsOB {
		if !definedOB[t] {
			miss = append(miss, "outbound:"+t)
		}
	}
	if fin, ok := parsed["05_route.json"]; ok {
		if rt, ok := fin["route"].(map[string]any); ok {
			if f, ok := rt["final"].(string); ok && !definedOB[f] {
				miss = append(miss, "final:"+f)
			}
		}
	}
	for _, ph := range parsed {
		if rt, ok := ph["route"].(map[string]any); ok {
			if f, ok := rt["final"].(string); ok && len(definedOB) > 0 && !definedOB[f] {
				miss = append(miss, "final:"+f)
			}
		}
	}
	if len(miss) > 0 {
		sort.Strings(miss)
		return fmt.Errorf("引用缺失: %s", strings.Join(dedupe(miss), ", "))
	}
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func collectRuleRefs(rules any, rs, ob *[]string) {
	list, ok := rules.([]any)
	if !ok {
		return
	}
	for _, e := range list {
		mm, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if v, ok := mm["rule_set"].([]any); ok && rs != nil {
			for _, t := range v {
				*rs = append(*rs, fmt.Sprint(t))
			}
		}
		if v, ok := mm["outbound"].(string); ok && ob != nil {
			*ob = append(*ob, v)
		}
		if sub, ok := mm["rules"].([]any); ok {
			collectRuleRefs(sub, rs, ob)
		}
	}
}
