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
	dnsRules, err := RenderRuleList(c.DnsRules, target, f, vars, listVars)
	if err != nil {
		return nil, fmt.Errorf("dns_rules: %w", err)
	}
	routeRules, err := RenderRuleList(c.RouteRules, target, f, vars, listVars)
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

var gwSections = []struct{ tmpl, file string }{
	{"b00", "00_log.json"}, {"b01", "01_experimental.json"}, {"b02", "02_dns.json"},
	{"b03", "03_inbounds.json"}, {"OUTBOUNDS", "04_outbound.json"},
	{"b05", "05_route.json"}, {"b06", "06_http_clients.json"}, {"b07", "07_services.json"},
}

const marker = "// !! 本文件由 singbox-gen 生成（homelab.yaml -> 模板装配），勿手改 !!"

func wrap(body string) string {
	return "{\n  \"$schema\": \"https://sing-box.sagernet.org/schema.json\",\n  " + body + "\n}\n"
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
	for _, s := range gwSections {
		var body string
		if s.tmpl == "OUTBOUNDS" {
			body, err = BuildOutbounds(c, ctx)
		} else {
			body, err = execTmpl(t, s.tmpl, ctx)
		}
		if err != nil {
			return nil, err
		}
		files[s.file] = marker + "\n" + wrap(body)
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
	order := []string{"b00", "b02", "b06", "b03", "OUTBOUNDS", "b05", "b01"}
	for _, name := range order {
		var body string
		if name == "OUTBOUNDS" {
			body, err = BuildOutbounds(c, ctx)
		} else {
			body, err = execTmpl(t, name, ctx)
		}
		if err != nil {
			return "", err
		}
		bodies = append(bodies, body)
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
func RenderRuleList(rules []Rule, target string, f map[string]bool, vars map[string]any, listVars map[string][]string) (string, error) {
	var out []string
	for _, r := range rules {
		if sc, ok := r["_scope"].(string); ok && !ScopeMatch(sc, target) {
			continue
		}
		if ifn, ok := r["_if"].(string); ok && ifn != "" && !f[ifn] {
			continue
		}
		note := ""
		if n, ok := r["_note"].(string); ok && n != "" {
			note = "      // " + n + "\n"
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
