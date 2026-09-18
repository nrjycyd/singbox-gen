package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"text/template"
)

//go:embed templates
var templatesFS embed.FS

type Ctx struct {
	Target       string
	Mode         string
	C            *Config
	Sp           *TargetSpec
	F            map[string]bool
	ProxyDNS     string
	Ecs          string
	GhLan        string
	TunAddrs     string
	PinnedSets     []string
	PinnedOutbound string
	RuleSetLines   string
	DnsRules       string
	RouteRules     string
	Inbounds       string
	RouteExtra     string
	ApiPort        int
	Vars           map[string]any
	DnsSteps       []int
	RouteSteps     []int
	DataDir        string
}

func BuildCtx(c *Config, target, mode, dataDir string) (*Ctx, error) {
	sp := c.targetSpec(target)
	f := map[string]bool{}
	for _, k := range []string{"pinned", "cn_extra", "clash", "fakeip", "telegram", "gh"} {
		f[k] = c.flagOf(k, target)
	}
	if f["pinned"] && (len(c.Pinned.Sets) == 0 || c.Pinned.Outbound == "") {
		return nil, fmt.Errorf("policy.pinned 已对 %s 开启，但 pinned.sets / pinned.outbound 未配置", target)
	}
	var entries []string
	for _, rs := range c.RuleSets {
		if rs.Scope != "both" && rs.Scope != target {
			continue
		}
		tag := rs.Group + "-" + rs.Item
		if target == TgtSFL {
			entries = append(entries, fmt.Sprintf(
				`      {"type": "local", "tag": %q, "format": "binary", "path": %q}`,
				tag, c.RuleDir+"/"+rs.Group+"/"+rs.Item+".srs"))
		} else {
			entries = append(entries, fmt.Sprintf(
				"      { \"type\": \"remote\", \"tag\": %q, \"format\": \"binary\",\n        \"url\": \"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/%s/%s.srs\",\n        \"update_interval\": \"24h\" }",
				tag, rs.Group, rs.Item))
		}
	}
	entries = append(entries, cusdomEntries(c.cusdomOf(target))...)
	ruleSetLines := strings.Join(entries, ",\n")

	vars := map[string]any{
		"proxy_dns":       sp.ProxyDNS,
		"local_dns":       "local-dns",
		"remote_dns":      "remote-dns",
		"ecs":             c.Ecs,
		"pinned_outbound": c.Pinned.Outbound,
	}
	listVars := map[string][]string{
		"pinned_sets": c.Pinned.Sets,
		"gh_cidr":     sp.GhCidr,
	}
	dnsSteps, routeSteps := c.StepNumbers()
	dnsRules, err := RenderRuleList(c.DnsRules, target, f, vars, listVars, dnsSteps)
	if err != nil {
		return nil, fmt.Errorf("dns_rules: %w", err)
	}
	routeRules, err := RenderRuleList(c.RouteRules, target, f, vars, listVars, routeSteps)
	if err != nil {
		return nil, fmt.Errorf("route_rules: %w", err)
	}
	inbounds, routeExtra := "", ""
	if target == TgtSFL {
		inbounds, err = BuildInbounds(c, mode)
		if err != nil {
			return nil, err
		}
		routeExtra = BuildRouteOptions(c.SFL.Modes[mode])
	}

	return &Ctx{
		Target: target, Mode: mode, C: c, Sp: sp, F: f,
		ProxyDNS: sp.ProxyDNS, Ecs: `"` + c.Ecs + `"`,
		GhLan:        quotedJoin(sp.GhCidr),
		TunAddrs:     quotedJoin(sp.TunAddress),
		PinnedSets:     c.Pinned.Sets,
		PinnedOutbound: c.Pinned.Outbound,
		RuleSetLines:   ruleSetLines,
		DnsRules:       dnsRules,
		RouteRules:     routeRules,
		Inbounds:       inbounds,
		RouteExtra:     routeExtra,
		ApiPort:        c.SFL.Ports.API,
		Vars:           vars,
		DnsSteps:       dnsSteps,
		RouteSteps:     routeSteps,
		DataDir:        dataDir,
	}, nil
}

// BuildInbounds 生成网关入站段：公共入站(mixed/socks/fake-in) + 模式特有入站
func BuildInbounds(c *Config, mode string) (string, error) {
	g := &c.SFL
	ms, ok := g.Modes[mode]
	if !ok {
		return "", fmt.Errorf("未启用的模式: %s", mode)
	}
	vars := map[string]any{
		"listen": g.Listen,
		"mixed":  g.Ports.Mixed, "socks": g.Ports.Socks, "fake_in": g.Ports.FakeIn,
		"api": g.Ports.API, "redirect": g.Ports.Redirect, "tproxy": g.Ports.Tproxy,
	}
	listVars := map[string][]string{}
	inbound := func(typ, tag string, port int) map[string]any {
		return map[string]any{"type": typ, "tag": tag, "listen": g.Listen, "listen_port": port}
	}
	items := []any{
		inbound("mixed", "mixed-in", g.Ports.Mixed),
		inbound("socks", "socks-in", g.Ports.Socks),
	}
	for _, in := range ms.Inbounds {
		items = append(items, map[string]any(in))
	}
	items = append(items, inbound("direct", "fake-in", g.Ports.FakeIn))

	var parts []string
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			return "", fmt.Errorf("入站定义必须是映射")
		}
		sub := substAny(m, vars, listVars)
		mm, _ := sub.(map[string]any)
		note := ""
		if n, ok := mm["_note"].(string); ok && n != "" {
			note = "    // " + n + "\n"
		}
		parts = append(parts, note+"    "+renderObj(mm, 4, inboundKeyOrder, vars, listVars))
	}
	return strings.Join(parts, ",\n"), nil
}

// BuildRouteOptions 生成模式特有的 route 级选项（如 tproxy 的 default_mark）
func BuildRouteOptions(ms ModeSpec) string {
	if len(ms.RouteOptions) == 0 {
		return ""
	}
	keys := make([]string, 0, len(ms.RouteOptions))
	for k := range ms.RouteOptions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var lines []string
	for _, k := range keys {
		b, _ := json.Marshal(ms.RouteOptions[k])
		lines = append(lines, "    "+`"`+k+`": `+string(b)+",")
	}
	return strings.Join(lines, "\n")
}

func cusdomEntries(cu Cusdom) []string {
	var e []string
	if len(cu.Reject) > 0 {
		e = append(e, fmt.Sprintf(`      {"type": "inline", "tag": "cusdom-reject", "rules": [{"domain": [%s]}]}`, quotedJoin(cu.Reject)))
	}
	if len(cu.Proxy) > 0 {
		e = append(e, fmt.Sprintf(`      {"type": "inline", "tag": "cusdom-proxy", "rules": [{"domain": [%s]}]}`, quotedJoin(cu.Proxy)))
	}
	if len(cu.Direct) > 0 || len(cu.DirectSuffix) > 0 {
		var inner []string
		if len(cu.Direct) > 0 {
			inner = append(inner, `"domain": [`+quotedJoin(cu.Direct)+`]`)
		}
		if len(cu.DirectSuffix) > 0 {
			inner = append(inner, `"domain_suffix": [`+quotedJoin(cu.DirectSuffix)+`]`)
		}
		e = append(e, fmt.Sprintf(`      {"type": "inline", "tag": "cusdom-direct", "rules": [{%s}]}`, strings.Join(inner, ", ")))
	}
	return e
}

func loadTemplates() (*template.Template, error) {
	t := template.New("singbox-gen")
	names, err := fs.Glob(templatesFS, "templates/*.tmpl")
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		b, err := templatesFS.ReadFile(n)
		if err != nil {
			return nil, err
		}
		t, err = t.Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
	}
	return t, nil
}

func execTmpl(t *template.Template, name string, ctx *Ctx) (string, error) {
	var sb strings.Builder
	if err := t.ExecuteTemplate(&sb, name, ctx); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// ---------- 结构化生成 outbounds ----------

type selOut struct {
	Type      string   `json:"type"`
	Tag       string   `json:"tag"`
	Outbounds []string `json:"outbounds"`
	Default   string   `json:"default,omitempty"`
}

type drDef struct {
	Server   string `json:"server"`
	Strategy string `json:"strategy"`
}

type utlsDef struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type tlsDef struct {
	Enabled         bool     `json:"enabled"`
	DisableSni      bool     `json:"disable_sni,omitempty"`
	ServerName      string   `json:"server_name,omitempty"`
	Insecure        bool     `json:"insecure,omitempty"`
	Alpn            []string `json:"alpn,omitempty"`
	CertificatePath string   `json:"certificate_path,omitempty"`
	Certificate     []string `json:"certificate,omitempty"`
	Utls            *utlsDef `json:"utls,omitempty"`
}

type obfsDef struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type hy2Out struct {
	Type           string   `json:"type"`
	Tag            string   `json:"tag"`
	Server         string   `json:"server"`
	ServerPorts    []string `json:"server_ports,omitempty"`
	ServerPort     int      `json:"server_port,omitempty"`
	Password       string   `json:"password"`
	UpMbps         int      `json:"up_mbps,omitempty"`
	DownMbps       int      `json:"down_mbps,omitempty"`
	Obfs           *obfsDef `json:"obfs,omitempty"`
	DomainResolver *drDef   `json:"domain_resolver,omitempty"`
	TLS            tlsDef   `json:"tls"`
}

type vlessOut struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	Server         string `json:"server"`
	ServerPort     int    `json:"server_port"`
	UUID           string `json:"uuid"`
	Flow           string `json:"flow,omitempty"`
	PacketEncoding string `json:"packet_encoding,omitempty"`
	TLS            tlsDef `json:"tls"`
}

type directOut struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

func nodeIn(n Node, target string) bool {
	for _, t := range n.Targets {
		if t == target || (t == TgtMobile && IsPhone(target)) {
			return true
		}
	}
	return false
}

func certLines(dataDir, file string) ([]string, error) {
	b, err := readFileString(dataDir + "/" + file)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(b, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out, nil
}

func BuildOutbounds(c *Config, ctx *Ctx) (string, error) {
	var items []any
	items = append(items, selOut{Type: "selector", Tag: "proxy",
		Outbounds: c.Selectors.Proxy.Members.For(ctx.Target),
		Default:   c.Selectors.Proxy.Default.For(ctx.Target)})
	items = append(items, selOut{Type: "selector", Tag: "select", Outbounds: []string{"proxy", "direct"}})
	if ctx.F["gh"] {
		items = append(items, selOut{Type: "selector", Tag: "gh",
			Outbounds: c.Selectors.Gh.Members.For(ctx.Target),
			Default:   c.Selectors.Gh.Default.For(ctx.Target)})
	}
	for _, n := range c.Nodes {
		if !nodeIn(n, ctx.Target) {
			continue
		}
		switch n.Kind {
		case "hysteria2":
			h := hy2Out{Type: "hysteria2", Tag: n.Tag, Server: n.Server,
				ServerPorts: n.Ports, ServerPort: n.Port, Password: n.Password,
				UpMbps: n.Up, DownMbps: n.Down}
			if n.ObfsPass != "" {
				h.Obfs = &obfsDef{Type: "salamander", Password: n.ObfsPass}
			}
			if n.IPv6OnlyDNS {
				h.DomainResolver = &drDef{Server: "local-dns", Strategy: "ipv6_only"}
			}
			h.TLS = tlsDef{Enabled: true, ServerName: n.SNI, Insecure: false, Alpn: []string{"h3"}}
			if ctx.Target == TgtSFL && n.CertPath != "" {
				h.TLS.CertificatePath = n.CertPath
			} else if n.CertFile != "" {
				cl, err := certLines(ctx.DataDir, n.CertFile)
				if err != nil {
					return "", err
				}
				h.TLS.Certificate = cl
			}
			items = append(items, h)
		case "vless":
			items = append(items, vlessOut{Type: "vless", Tag: n.Tag, Server: n.Server, ServerPort: n.Port,
				UUID: n.UUID, Flow: "xtls-rprx-vision", PacketEncoding: "xudp",
				TLS: tlsDef{Enabled: true, ServerName: n.SNI, Insecure: false,
					Utls: &utlsDef{Enabled: true, Fingerprint: "chrome"}}})
		default:
			return "", fmt.Errorf("未知节点类型: %s", n.Kind)
		}
	}
	items = append(items, directOut{Type: "direct", Tag: "direct"})

	var parts []string
	for _, it := range items {
		b, err := json.MarshalIndent(it, "    ", "  ")
		if err != nil {
			return "", err
		}
		parts = append(parts, "    "+string(b))
	}
	return "\"outbounds\": [\n" + strings.Join(parts, ",\n") + "\n  ]", nil
}

// ---------- 渲染入口 ----------

// 模块 -> SFL 产物文件名（前缀仅影响目录内可读性，sing-box 按 key 合并）
var sflFileNames = map[string]string{
	"log": "00_log.json", "experimental": "01_experimental.json", "dns": "02_dns.json",
	"inbounds": "03_inbounds.json", "outbounds": "04_outbound.json", "route": "05_route.json",
	"http_clients": "06_http_clients.json", "services": "07_services.json",
	"ntp": "08_ntp.json", "certificate": "09_certificate.json",
	"certificate_providers": "10_certificate_providers.json",
	"network_namespaces": "11_network_namespaces.json", "endpoints": "12_endpoints.json",
}

// 非建模模块（extra 透传）的键序
var moduleKeyOrder = []string{
	"type", "tag", "enabled", "server", "server_port", "domain", "email",
	"provider", "interface", "address", "listen", "listen_port", "peers", "private_key",
	"public_key", "pre_shared_key", "allowed_ips", "mtu", "detour", "tls", "password", "username",
}

const marker = "// !! 本文件由 singbox-gen 生成（homelab.yaml -> 模板装配），勿手改 !!"

func wrap(body string) string {
	return "{\n  \"$schema\": \"https://sing-box.sagernet.org/schema.json\",\n  " + body + "\n}\n"
}

// renderModule 生成单个模块的正文（不含 {} 包裹）；模块未启用返回 ok=false
func renderModule(c *Config, t *template.Template, ctx *Ctx, name string) (string, bool, error) {
	if !c.ModuleEnabled(ctx.Target, name) {
		return "", false, nil
	}
	// extra 覆盖优先（内置模块亦适用）：一旦提供内容，即替代生成结果
	if v, ok := c.ExtraOf(ctx.Target, name); ok {
		body := renderVal(substAny(v, ctx.Vars, nil), 2, moduleKeyOrder, ctx.Vars, nil)
		return `"` + name + `": ` + body, true, nil
	}
	switch name {
	case "log":
		b, err := execTmpl(t, "b00", ctx); return b, true, err
	case "experimental":
		b, err := execTmpl(t, "b01", ctx); return b, true, err
	case "dns":
		b, err := execTmpl(t, "b02", ctx); return b, true, err
	case "inbounds":
		b, err := execTmpl(t, "b03", ctx); return b, true, err
	case "outbounds":
		b, err := BuildOutbounds(c, ctx); return b, true, err
	case "route":
		b, err := execTmpl(t, "b05", ctx); return b, true, err
	case "http_clients":
		b, err := execTmpl(t, "b06", ctx); return b, true, err
	case "services":
		if ctx.Target != TgtSFL {
			return "", false, fmt.Errorf("模块 services 不适用于 %s", ctx.Target)
		}
		b, err := execTmpl(t, "b07", ctx); return b, true, err
	}
	return "", false, fmt.Errorf("模块 %s 无内容：请在 YAML 写入 extra.%s.%s", name, ctx.Target, name)
}

// RenderSFL 生成 SFL 某一模式的产物（conf 目录内容）
func RenderSFL(c *Config, mode, dataDir string) (map[string]string, error) {
	t, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	ctx, err := BuildCtx(c, TgtSFL, mode, dataDir)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, name := range c.OrderedModules() {
		body, ok, err := renderModule(c, t, ctx, name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		file, has := sflFileNames[name]
		if !has {
			file = "99_" + name + ".json"
		}
		files[file] = marker + "\n" + wrap(body)
	}
	svc, err := templatesFS.ReadFile("templates/systemd-unit.txt")
	if err != nil {
		return nil, err
	}
	files["sing-box.service"] = string(svc)
	return files, nil
}

// RenderSFLModes 生成 SFL 全部启用模式的产物（mode -> 文件名 -> 内容）
func RenderSFLModes(c *Config, dataDir string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, m := range c.EnabledModes() {
		files, err := RenderSFL(c, m, dataDir)
		if err != nil {
			return nil, fmt.Errorf("模式 %s: %w", m, err)
		}
		out[m] = files
	}
	return out, nil
}

// RenderPhone 生成手机端单文件 profile（仅注释版）
func RenderPhone(c *Config, target, dataDir string) (string, error) {
	t, err := loadTemplates()
	if err != nil {
		return "", err
	}
	ctx, err := BuildCtx(c, target, "", dataDir)
	if err != nil {
		return "", err
	}
	var bodies []string
	for _, name := range c.OrderedModules() {
		body, ok, err := renderModule(c, t, ctx, name)
		if err != nil {
			return "", err
		}
		if ok {
			bodies = append(bodies, body)
		}
	}
	hb, err := templatesFS.ReadFile("templates/phone-header.txt")
	if err != nil {
		return "", err
	}
	return "{\n" + strings.TrimRight(string(hb), "\n") + "\n  " + strings.Join(bodies, ",\n") + "\n}\n", nil
}

func StripComments(text string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "//") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// ---------- 规则渲染（规则来自 YAML 的 dns_rules / route_rules） ----------

var ruleKeyOrder = []string{
	"type", "mode", "rules", "inbound", "protocol", "network", "port", "port_range",
	"query_type", "ip_version", "invert", "clash_mode", "rule_set",
	"ip_cidr", "ip_is_private", "domain", "domain_suffix", "domain_keyword", "domain_regex",
	"action", "outbound", "server", "method", "rcode", "rewrite_ttl",
	"match_response", "response_rcode", "client_subnet", "tag", "disable_cache",
}

var inboundKeyOrder = []string{
	"type", "tag", "listen", "listen_port", "interface_name", "address", "mtu",
	"dns_mode", "auto_route", "auto_redirect", "strict_route", "stack",
	"mode", "network", "udp_timeout", "bypass_rule_set", "shared", "advanced",
}

func isMetaKey(k string) bool {
	switch k {
	case "_note", "_scope", "_if", "_for_each", "_group":
		return true
	}
	return false
}

func orderedKeys(m map[string]any, order []string) []string {
	var keys []string
	seen := map[string]bool{}
	for _, k := range order {
		if _, ok := m[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range m {
		if seen[k] || isMetaKey(k) {
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	return append(keys, rest...)
}

func trimVar(s string) (string, bool) {
	if strings.HasPrefix(s, "{{") && strings.HasSuffix(s, "}}") && len(s) > 4 {
		return s[2 : len(s)-2], true
	}
	return "", false
}

// substAny：字符串中的 {{变量}} 替换为（可类型化的）值；数组元素为整项 {{变量}} 且命中 listVars 时展开
func substAny(v any, vars map[string]any, listVars map[string][]string) any {
	switch t := v.(type) {
	case string:
		if name, hit := trimVar(t); hit {
			if val, ok := vars[name]; ok {
				return val
			}
			return t
		}
		for k, val := range vars {
			if s, ok := val.(string); ok {
				t = strings.ReplaceAll(t, "{{"+k+"}}", s)
			}
		}
		return t
	case []any:
		var out []any
		for _, e := range t {
			if s, ok := e.(string); ok {
				if name, hit := trimVar(s); hit {
					if lst, ok := listVars[name]; ok { // 整项替换为列表
						for _, it := range lst {
							out = append(out, it)
						}
						continue
					}
				}
				out = append(out, substAny(s, vars, listVars))
				continue
			}
			out = append(out, substAny(e, vars, listVars))
		}
		return out
	case map[string]any:
		m := map[string]any{}
		for k, vv := range t {
			m[k] = substAny(vv, vars, listVars)
		}
		return m
	}
	return v
}

func renderVal(v any, indent int, order []string, vars map[string]any, listVars map[string][]string) string {
	switch t := v.(type) {
	case map[string]any:
		return renderObj(t, indent, order, vars, listVars)
	case []any:
		onlyScalar := true
		for _, e := range t {
			switch e.(type) {
			case map[string]any, []any:
				onlyScalar = false
			}
		}
		if onlyScalar {
			b, _ := json.Marshal(t)
			return string(b)
		}
		var items []string
		for _, e := range t {
			items = append(items, strings.Repeat(" ", indent+2)+renderVal(e, indent+2, order, vars, listVars))
		}
		return "[\n" + strings.Join(items, ",\n") + "\n" + strings.Repeat(" ", indent) + "]"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func renderObj(m map[string]any, indent int, order []string, vars map[string]any, listVars map[string][]string) string {
	var lines []string
	for _, k := range orderedKeys(m, order) {
		v := substAny(m[k], vars, listVars)
		lines = append(lines, strings.Repeat(" ", indent+2)+`"`+k+`": `+renderVal(v, indent+2, order, vars, listVars))
	}
	return "{\n" + strings.Join(lines, ",\n") + "\n" + strings.Repeat(" ", indent) + "}"
}

// RenderRuleList 渲染规则数组正文（不含 [] 括号，元素已含逗号分隔与注释）
// steps：每条规则对应的"步骤行序号"（-1 表示无），注释编号由生成器重写，忽略 _note 中手写的开头编号
func RenderRuleList(rules []Rule, target string, f map[string]bool, vars map[string]any, listVars map[string][]string, steps []int) (string, error) {
	var out []string
	for i, r := range rules {
		if sc, ok := r["_scope"].(string); ok && !ScopeMatch(sc, target) {
			continue
		}
		if ifn, ok := r["_if"].(string); ok && ifn != "" && !f[ifn] {
			continue
		}
		note := ""
		if n, ok := r["_note"].(string); ok && n != "" {
			txt := stripLeadingNum(n)
			if i < len(steps) && steps[i] > 0 {
				prefix := fmt.Sprintf("%d", steps[i])
				if g, _ := r["_group"].(string); strings.TrimSpace(g) != "" && strings.TrimSpace(g) != prefix {
					prefix = prefix + " (组" + strings.TrimSpace(g) + ")"
				}
				txt = prefix + " " + txt
			}
			note = "      // " + txt + "\n"
		}
		if fe, ok := r["_for_each"].(string); ok && fe != "" {
			items, known := listVars[fe]
			if !known {
				return "", fmt.Errorf("_for_each 未知列表 %q", fe)
			}
			for _, it := range items {
				v2 := map[string]any{}
				for k, vv := range vars {
					v2[k] = vv
				}
				v2["item"] = it
				out = append(out, note+renderObj(r, 6, ruleKeyOrder, v2, listVars))
			}
			continue
		}
		out = append(out, note+renderObj(r, 6, ruleKeyOrder, vars, listVars))
	}
	return strings.Join(out, ",\n"), nil
}

// ---------- 步骤行序号（与 UI"行=步骤"算法一致；DNS/Route 同号配对） ----------

// ruleGroup：_group 优先，其次 _note 前缀编号（如 "2b xxx" → "2b"）
func ruleGroup(r Rule) string {
	if v, ok := r["_group"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	n, _ := r["_note"].(string)
	return leadNum(n)
}

func leadNum(s string) string {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return ""
	}
	if i < len(s) && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')) {
		i++
	}
	return strings.ToLower(s[:i])
}

func stripLeadingNum(s string) string {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i < len(s) && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')) {
		i++
	}
	if i > 0 && (i >= len(s) || s[i] == ' ' || s[i] == '\t') {
		return strings.TrimSpace(s[i:])
	}
	return s
}

type ruleItem struct {
	key   string
	group string
	side  string
	idx   int
	zone  string
}

// StepNumbers：返回 dns/route 每条规则的"行序号"（1 起；与界面显示顺序一致）
func (c *Config) StepNumbers() ([]int, []int) {
	dns, rts := c.DnsRules, c.RouteRules
	groupOrder := []string{}
	seen := map[string]bool{}
	scan := func(arr []Rule) {
		for _, r := range arr {
			g := ruleGroup(r)
			if g != "" && !seen[g] {
				seen[g] = true
				groupOrder = append(groupOrder, g)
			}
		}
	}
	scan(dns)
	scan(rts)
	zoneOf := func(arr []Rule, i int) string {
		for k := i + 1; k < len(arr); k++ {
			if g := ruleGroup(arr[k]); g != "" {
				return g
			}
		}
		return "@end"
	}
	items := []ruleItem{}
	for i, r := range dns {
		g := ruleGroup(r)
		z := g
		if z == "" {
			z = zoneOf(dns, i)
		}
		items = append(items, ruleItem{key: g, group: g, side: "dns", idx: i, zone: z})
		if g == "" {
			items[len(items)-1].key = fmt.Sprintf("@dns%d", i)
		}
	}
	for i, r := range rts {
		g := ruleGroup(r)
		z := g
		if z == "" {
			z = zoneOf(rts, i)
		}
		items = append(items, ruleItem{key: g, group: g, side: "route", idx: i, zone: z})
		if g == "" {
			items[len(items)-1].key = fmt.Sprintf("@route%d", i)
		}
	}
	zIdx := func(z string) int {
		if z == "@end" {
			return len(groupOrder) + 1
		}
		for i, g := range groupOrder {
			if g == z {
				return i
			}
		}
		return len(groupOrder) + 1
	}
	sort.SliceStable(items, func(a, b int) bool {
		x, y := items[a], items[b]
		zx, zy := zIdx(x.zone), zIdx(y.zone)
		if zx != zy {
			return zx < zy
		}
		gx, gy := x.group == "", y.group == ""
		if gx != gy {
			return gx // 未分组（前置规则）排在本组之前
		}
		if x.side != y.side {
			return x.side == "dns"
		}
		return x.idx < y.idx
	})
	dnsSteps := make([]int, len(dns))
	routeSteps := make([]int, len(rts))
	rowNum := 0
	prevKey := ""
	for _, it := range items {
		if it.key != prevKey {
			rowNum++
			prevKey = it.key
		}
		if it.side == "dns" {
			dnsSteps[it.idx] = rowNum
		} else {
			routeSteps[it.idx] = rowNum
		}
	}
	return dnsSteps, routeSteps
}
