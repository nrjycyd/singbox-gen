package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type DNSep struct {
	Type   string `yaml:"type"`
	Tag    string `yaml:"tag"`
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
}

// 目标端：SFL（Linux 网关）/ SFA（Android）/ SFI（iOS）；mobile = 两台手机的共同基座
const (
	TgtSFL    = "SFL"
	TgtSFA    = "SFA"
	TgtSFI    = "SFI"
	TgtMobile = "mobile"
)

var AllTargets = []string{TgtSFL, TgtSFA, TgtSFI}
var PhoneTargets = []string{TgtSFA, TgtSFI}

func IsPhone(target string) bool { return target == TgtSFA || target == TgtSFI }

// ScopeMatch：作用域匹配（空/both=全端；mobile=两台手机）
func ScopeMatch(scope, target string) bool {
	switch scope {
	case "", "both":
		return true
	case TgtMobile:
		return IsPhone(target)
	default:
		return scope == target
	}
}

type TargetSpec struct {
	ProxyDNS      string   `yaml:"proxy_dns"`
	DnsLocal      DNSep    `yaml:"dns_local"`
	DnsBootstrap  DNSep    `yaml:"dns_bootstrap"`
	DnsRemote     DNSep    `yaml:"dns_remote"`
	FakeIPV4      string   `yaml:"fakeip_v4"`
	FakeIPV6      string   `yaml:"fakeip_v6"`
	GhCidr        []string `yaml:"gh_cidr"`
	DomainResolv  string   `yaml:"domain_resolver_server"`
	TunIface      string   `yaml:"tun_interface"`
	TunAddress    []string `yaml:"tun_address"`
	TunMTU        int      `yaml:"tun_mtu"`
	Stack         string   `yaml:"stack"`
	MixedPort     int      `yaml:"mixed_port"`
	SocksPort     int      `yaml:"socks_port"`
	FakeInPort    int      `yaml:"fake_in_port"`
	ApiPort       int      `yaml:"api_port"`
	DashboardPath string   `yaml:"dashboard_path"`
	LogLevel      string   `yaml:"log_level"`
	LogOutput     string   `yaml:"log_output"`
	CachePath     string   `yaml:"cache_path"`
	StoreFakeIP   bool     `yaml:"store_fakeip"`
	StoreDNS      bool     `yaml:"store_dns"`
	ClashAPI      bool     `yaml:"clash_api"`
}

// PhoneSpec：手机端平台块（SFA / SFI）。所有字段缺省继承 mobile 基座。
type PhoneSpec struct {
	TargetSpec `yaml:",inline"`
}

// mergeFrom：用基座回填零值字段（平台块只写差异）
func (p *PhoneSpec) mergeFrom(base PhoneSpec) {
	mergeStr(&p.ProxyDNS, base.ProxyDNS)
	mergeStr(&p.FakeIPV4, base.FakeIPV4)
	mergeStr(&p.FakeIPV6, base.FakeIPV6)
	mergeStr(&p.DomainResolv, base.DomainResolv)
	mergeStr(&p.TunIface, base.TunIface)
	mergeStr(&p.Stack, base.Stack)
	mergeStr(&p.DashboardPath, base.DashboardPath)
	mergeStr(&p.LogLevel, base.LogLevel)
	mergeStr(&p.LogOutput, base.LogOutput)
	mergeStr(&p.CachePath, base.CachePath)
	if len(p.GhCidr) == 0 {
		p.GhCidr = base.GhCidr
	}
	if len(p.TunAddress) == 0 {
		p.TunAddress = base.TunAddress
	}
	if p.TunMTU == 0 {
		p.TunMTU = base.TunMTU
	}
	mergePort(&p.MixedPort, base.MixedPort)
	mergePort(&p.SocksPort, base.SocksPort)
	mergePort(&p.FakeInPort, base.FakeInPort)
	mergePort(&p.ApiPort, base.ApiPort)
	if !p.StoreFakeIP {
		p.StoreFakeIP = base.StoreFakeIP
	}
	if !p.StoreDNS {
		p.StoreDNS = base.StoreDNS
	}
	if !p.ClashAPI {
		p.ClashAPI = base.ClashAPI
	}
	mergeDNSep(&p.DnsLocal, base.DnsLocal)
	mergeDNSep(&p.DnsBootstrap, base.DnsBootstrap)
	mergeDNSep(&p.DnsRemote, base.DnsRemote)
}

func mergeStr(dst *string, base string) {
	if *dst == "" {
		*dst = base
	}
}
func mergePort(dst *int, base int) {
	if *dst == 0 {
		*dst = base
	}
}
func mergeDNSep(dst *DNSep, base DNSep) {
	if dst.Type == "" {
		dst.Type = base.Type
	}
	if dst.Tag == "" {
		dst.Tag = base.Tag
	}
	if dst.Server == "" {
		dst.Server = base.Server
	}
	if dst.Port == 0 {
		dst.Port = base.Port
	}
}

// Ports：网关入站端口（公共入站 + tproxy 专用），生成前校验范围与重复
type Ports struct {
	Mixed    int `yaml:"mixed"`
	Socks    int `yaml:"socks"`
	FakeIn   int `yaml:"fake_in"`
	API      int `yaml:"api"`
	Redirect int `yaml:"redirect"`
	Tproxy   int `yaml:"tproxy"`
}

// ModeSpec：一种透明代理模式（tun / ebpf / tproxy）
type ModeSpec struct {
	Enabled      bool           `yaml:"enabled"`
	Inbounds     []Rule         `yaml:"inbounds"`      // 模式特有入站（公共入站自动生成）
	RouteOptions map[string]any `yaml:"route_options"` // 本模式的 route 级选项（如 default_mark）
}

// GatewaySpec：SFL 端配置（含模式与端口）
type GatewaySpec struct {
	TargetSpec  `yaml:",inline"`
	DefaultMode string              `yaml:"default_mode"`
	Listen      string              `yaml:"listen"`
	Ports       Ports               `yaml:"ports"`
	Modes       map[string]ModeSpec `yaml:"modes"`
}

type RuleSet struct {
	Group string `yaml:"group" json:"group"` // geosite|geoip
	Item  string `yaml:"item" json:"item"`
	Scope string `yaml:"scope" json:"scope"` // both|SFL|SFA|SFI|mobile
}

type Cusdom struct {
	Reject       []string `yaml:"reject"`
	Proxy        []string `yaml:"proxy"`
	Direct       []string `yaml:"direct"`
	DirectSuffix []string `yaml:"direct_suffix"`
}

type Node struct {
	Tag         string   `yaml:"tag"`
	Kind        string   `yaml:"kind"` // hysteria2|vless
	Targets     []string `yaml:"targets"`
	Server      string   `yaml:"server"`
	Ports       []string `yaml:"ports"` // server_ports（hysteria2 端口跳跃）
	Port        int      `yaml:"port"`  // 单端口
	Password    string   `yaml:"password"`
	Up          int      `yaml:"up_mbps"`
	Down        int      `yaml:"down_mbps"`
	ObfsPass    string   `yaml:"obfs_password"`
	UUID        string   `yaml:"uuid"`
	SNI         string   `yaml:"sni"`
	CertPath    string   `yaml:"cert_path"`  // SFL 用 certificate_path
	CertFile    string   `yaml:"cert_file"`  // 手机用内联证书（相对 data 目录）
	IPv6OnlyDNS bool     `yaml:"ipv6_only_dns"`
}

// Members: YAML 序列（全端相同）或映射 {SFL: [], mobile: [], SFA: [], SFI: []}
type Members struct {
	Shared   []string
	ByTarget map[string][]string
}

func (m *Members) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		return value.Decode(&m.Shared)
	}
	var raw map[string][]string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	m.ByTarget = raw
	return nil
}

func (m *Members) For(target string) []string {
	if m.ByTarget != nil {
		if v, ok := m.ByTarget[target]; ok && len(v) > 0 {
			return v
		}
		if v, ok := m.ByTarget[TgtMobile]; ok && len(v) > 0 && IsPhone(target) {
			return v
		}
	}
	return m.Shared
}

// Default2：选择器默认出口 {SFL: X, mobile: Y}
type Default2 struct {
	ByTarget map[string]string
}

func (d *Default2) UnmarshalYAML(value *yaml.Node) error {
	var raw map[string]string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	d.ByTarget = raw
	return nil
}

func (d Default2) For(target string) string {
	if d.ByTarget != nil {
		if v, ok := d.ByTarget[target]; ok && v != "" {
			return v
		}
		if IsPhone(target) {
			if v, ok := d.ByTarget[TgtMobile]; ok && v != "" {
				return v
			}
		}
	}
	return ""
}

type SelectorDef struct {
	Members Members  `yaml:"members"`
	Default Default2 `yaml:"default"`
}

type PushSpec struct {
	Host     string `yaml:"host"`
	User     string `yaml:"user"`
	KeyFile  string `yaml:"key_file"`
	Password string `yaml:"password"`
	ConfDir  string `yaml:"conf_dir"`
	Service  string `yaml:"service"`
}

// Rule: 一条分流规则。除元键外，所有键原样进入 sing-box 规则对象。
// 元键：_note 注释 | _group 步骤编号（UI 配对/联动排序） | _scope both|SFL|SFA|SFI|mobile
//       _if 策略开关名 | _for_each 列表名（pinned_sets）
// 字符串值支持变量：{{proxy_dns}} {{local_dns}} {{remote_dns}} {{ecs}} {{pinned_outbound}} {{item}}
// 列表值支持整项替换：["{{gh_cidr}}"] → 展开为目标端的 gh 网段列表
type Rule map[string]any

// PinnedSpec: 钉定块（指定规则集强制走指定出口）
type PinnedSpec struct {
	Sets     []string `yaml:"sets"`     // 规则集 tag 列表（需在 rule_sets 中定义）
	Outbound string   `yaml:"outbound"` // 钉定出口 tag
}

var knownFlags = map[string]bool{
	"pinned": true, "cn_extra": true, "clash": true,
	"fakeip": true, "telegram": true, "gh": true,
}

// 模块：sing-box 顶层配置段（顺序即输出顺序）
var AllModules = []string{
	"log", "dns", "ntp", "certificate", "certificate_providers", "http_clients",
	"network_namespaces", "endpoints", "inbounds", "outbounds", "route", "services", "experimental",
}

// 生成器"原生建模"的模块（其余需用 extra: 原样提供内容）
var builtinModules = map[string]bool{
	"log": true, "dns": true, "http_clients": true, "inbounds": true,
	"outbounds": true, "route": true, "services": true, "experimental": true,
}

// 各目标端的默认启用模块
func defaultModules(target string) map[string]bool {
	out := map[string]bool{}
	for _, m := range AllModules {
		out[m] = builtinModules[m]
	}
	if target != TgtSFL {
		out["services"] = false
	}
	return out
}

// ModuleEnabled：模块开关（modules.<target>.<name>，缺省取默认）
func (c *Config) ModuleEnabled(target, name string) bool {
	if tm, ok := c.Modules[target]; ok {
		if v, ok := tm[name]; ok {
			return v
		}
	}
	if IsPhone(target) {
		if tm, ok := c.Modules[TgtMobile]; ok {
			if v, ok := tm[name]; ok {
				return v
			}
		}
	}
	return defaultModules(target)[name]
}

// ModuleOrder：全局模块输出顺序（未列出的按 AllModules 顺序补在后面）
func (c *Config) OrderedModules() []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range c.ModuleOrder {
		for _, ok := range AllModules {
			if ok == m && !seen[m] {
				out = append(out, m)
				seen[m] = true
			}
		}
	}
	for _, m := range AllModules {
		if !seen[m] {
			out = append(out, m)
		}
	}
	return out
}

// ExtraOf：非建模模块的原样内容（extra.<target>.<name>）
func (c *Config) ExtraOf(target, name string) (any, bool) {
	if tm, ok := c.Extra[target]; ok {
		if v, ok := tm[name]; ok {
			return v, true
		}
	}
	if IsPhone(target) {
		if tm, ok := c.Extra[TgtMobile]; ok {
			if v, ok := tm[name]; ok {
				return v, true
			}
		}
	}
	return nil, false
}

type Config struct {
	Secret struct {
		ProfileToken string `yaml:"profile_token"` // 手机订阅 URL 路径凭证（/p/<此值>/sfa.json|sfi.json）
	} `yaml:"secret"`
	Ecs     string `yaml:"ecs"`
	RuleDir string `yaml:"rule_dir"` // SFL 的 .srs 根目录
	// 三个目标端
	SFL    GatewaySpec       `yaml:"SFL"`
	Mobile PhoneSpec         `yaml:"mobile"` // SFA/SFI 共享基座
	SFA    PhoneSpec         `yaml:"SFA"`
	SFI    PhoneSpec         `yaml:"SFI"`
	Policy map[string]string `yaml:"policy"` // pinned/cn_extra/clash/fakeip/telegram/gh -> both|SFL|SFA|SFI|mobile
	RuleSets []RuleSet       `yaml:"rule_sets"`
	Cusdom   map[string]Cusdom `yaml:"cusdom"` // key: SFL|SFA|SFI|mobile
	Pinned   PinnedSpec      `yaml:"pinned"`
	// 模块开关：modules.<target>.<module> = true/false（缺省见 defaultModules）
	Modules map[string]map[string]bool `yaml:"modules"`
	// 非建模模块的原样内容：extra.<target>.<module>（如 ntp / endpoints / certificate）
	Extra map[string]map[string]any `yaml:"extra"`
	// 模块输出顺序（缺省按 AllModules）
	ModuleOrder []string `yaml:"module_order"`
	Selectors struct {
		Proxy SelectorDef `yaml:"proxy"`
		Gh    SelectorDef `yaml:"gh"`
	} `yaml:"selectors"`
	Nodes []Node   `yaml:"nodes"`
	Push  PushSpec `yaml:"push"`

	// 分流规则（单一事实源；顺序即优先级，首条命中即停）
	DnsRules   []Rule `yaml:"dns_rules"`
	RouteRules []Rule `yaml:"route_rules"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadConfig2(string(b))
}

func LoadConfig2(text string) (*Config, error) {
	c := &Config{}
	if err := yaml.Unmarshal([]byte(text), c); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	if c.Ecs == "" {
		return nil, fmt.Errorf("缺少 ecs 配置")
	}
	for name, v := range c.Policy {
		if !knownFlags[name] {
			return nil, fmt.Errorf("policy 含未知开关 %q（可用: pinned/cn_extra/clash/fakeip/telegram/gh）", name)
		}
		switch v {
		case "both", TgtSFL, TgtSFA, TgtSFI, TgtMobile:
		default:
			return nil, fmt.Errorf("policy.%s=%q 非法（可用: both/SFL/SFA/SFI/mobile）", name, v)
		}
	}
	if len(c.DnsRules) == 0 || len(c.RouteRules) == 0 {
		return nil, fmt.Errorf("缺少 dns_rules / route_rules（可从 templates/homelab.example.yaml 复制规则段）")
	}
	for i, rs := range c.RuleSets {
		switch rs.Scope {
		case "", "both", TgtSFL, TgtSFA, TgtSFI, TgtMobile:
		default:
			return nil, fmt.Errorf("rule_sets[%d].scope=%q 非法（可用: both/SFL/SFA/SFI/mobile）", i, rs.Scope)
		}
	}
	for _, m := range c.ModuleOrder {
		ok := false
		for _, name := range AllModules {
			if name == m {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("module_order 含未知模块 %q", m)
		}
	}
	if err := c.validateSFL(); err != nil {
		return nil, err
	}
	if err := c.validatePhone(TgtSFA); err != nil {
		return nil, err
	}
	if err := c.validatePhone(TgtSFI); err != nil {
		return nil, err
	}
	return c, nil
}

var gatewayModes = []string{"tun", "ebpf", "tproxy"}

// EnabledModes 返回启用的模式（按 tun/ebpf/tproxy 固定顺序）
func (c *Config) EnabledModes() []string {
	var out []string
	for _, m := range gatewayModes {
		if ms, ok := c.SFL.Modes[m]; ok && ms.Enabled {
			out = append(out, m)
		}
	}
	return out
}

func modeHasInbound(ms ModeSpec, typ string) bool {
	for _, in := range ms.Inbounds {
		if t, ok := in["type"].(string); ok && t == typ {
			return true
		}
	}
	return false
}

func (c *Config) validateSFL() error {
	g := &c.SFL
	if len(g.Modes) == 0 {
		return fmt.Errorf("SFL.modes 未配置（可用: tun / ebpf / tproxy）")
	}
	for m := range g.Modes {
		if m != "tun" && m != "ebpf" && m != "tproxy" {
			return fmt.Errorf("SFL.modes 含未知模式 %q（可用: tun / ebpf / tproxy）", m)
		}
	}
	enabled := map[string]bool{}
	for _, m := range c.EnabledModes() {
		enabled[m] = true
	}
	if len(enabled) == 0 {
		return fmt.Errorf("SFL.modes 至少启用一个模式（enabled: true）")
	}
	if g.Listen == "" {
		g.Listen = "::"
	}
	if g.DefaultMode == "" {
		g.DefaultMode = c.EnabledModes()[0]
	}
	if !enabled[g.DefaultMode] {
		return fmt.Errorf("SFL.default_mode=%s 未被启用", g.DefaultMode)
	}
	portOf := map[string]int{
		"mixed": g.Ports.Mixed, "socks": g.Ports.Socks, "fake_in": g.Ports.FakeIn,
		"api": g.Ports.API, "redirect": g.Ports.Redirect, "tproxy": g.Ports.Tproxy,
	}
	need := []string{"mixed", "socks", "fake_in", "api"}
	if enabled["tproxy"] {
		need = append(need, "redirect", "tproxy")
	}
	used := map[int]string{}
	for _, n := range need {
		v := portOf[n]
		if v == 0 {
			return fmt.Errorf("SFL.ports.%s 未配置（启用 %v 模式需要）", n, c.EnabledModes())
		}
		if v < 1 || v > 65535 {
			return fmt.Errorf("SFL.ports.%s=%d 超出 1-65535", n, v)
		}
		if prev, ok := used[v]; ok {
			return fmt.Errorf("端口冲突：SFL.ports.%s 与 %s 都是 %d", prev, n, v)
		}
		used[v] = n
	}
	if enabled["tun"] && !modeHasInbound(g.Modes["tun"], "tun") {
		return fmt.Errorf("SFL.modes.tun.inbounds 缺少 type=tun 入站")
	}
	if enabled["ebpf"] && !modeHasInbound(g.Modes["ebpf"], "ebpf") {
		return fmt.Errorf("SFL.modes.ebpf.inbounds 缺少 type=ebpf 入站")
	}
	if enabled["tproxy"] && (!modeHasInbound(g.Modes["tproxy"], "redirect") || !modeHasInbound(g.Modes["tproxy"], "tproxy")) {
		return fmt.Errorf("SFL.modes.tproxy.inbounds 需要 type=redirect 与 type=tproxy 两个入站")
	}
	return nil
}

func (c *Config) validatePhone(target string) error {
	sp := c.effectivePhone(target)
	if sp.TunIface == "" {
		return fmt.Errorf("%s/mobile 缺少 tun_interface", target)
	}
	if len(sp.TunAddress) == 0 {
		return fmt.Errorf("%s/mobile 缺少 tun_address", target)
	}
	if sp.TunMTU == 0 {
		return fmt.Errorf("%s/mobile 缺少 tun_mtu", target)
	}
	if sp.ProxyDNS == "" {
		return fmt.Errorf("%s/mobile 缺少 proxy_dns", target)
	}
	return nil
}

// effectivePhone：平台块 + mobile 基座合并结果
func (c *Config) effectivePhone(target string) *PhoneSpec {
	out := &PhoneSpec{}
	switch target {
	case TgtSFA:
		out.TargetSpec = c.SFA.TargetSpec
	case TgtSFI:
		out.TargetSpec = c.SFI.TargetSpec
	}
	out.mergeFrom(c.Mobile)
	if out.TargetSpec.Stack == "" {
		out.TargetSpec.Stack = "mixed"
	}
	return out
}

// flagOf: 策略块对当前 target 是否启用
func (c *Config) flagOf(name, target string) bool {
	return ScopeMatch(c.Policy[name], target)
}

// targetSpec: SFL 直接返回；手机端返回合并后的副本
func (c *Config) targetSpec(target string) *TargetSpec {
	if target == TgtSFL {
		return &c.SFL.TargetSpec
	}
	return &c.effectivePhone(target).TargetSpec
}

// cusdomOf: 自定义域名集（平台未定义时回退 mobile）
func (c *Config) cusdomOf(target string) Cusdom {
	if cu, ok := c.Cusdom[target]; ok {
		return cu
	}
	if IsPhone(target) {
		if cu, ok := c.Cusdom[TgtMobile]; ok {
			return cu
		}
	}
	return Cusdom{}
}

func quotedJoin(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = `"` + s + `"`
	}
	return strings.Join(q, ", ")
}

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
