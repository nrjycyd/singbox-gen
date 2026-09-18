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

type TargetSpec struct {
	ProxyDNS      string    `yaml:"proxy_dns"`
	DnsLocal      DNSep     `yaml:"dns_local"`
	DnsBootstrap  DNSep     `yaml:"dns_bootstrap"`
	DnsRemote     DNSep     `yaml:"dns_remote"`
	FakeIPV4      string    `yaml:"fakeip_v4"`
	FakeIPV6      string    `yaml:"fakeip_v6"`
	GhCidr        []string  `yaml:"gh_cidr"`
	DomainResolv  string    `yaml:"domain_resolver_server"`
	TunIface      string    `yaml:"tun_interface"`
	TunAddress    []string  `yaml:"tun_address"`
	TunMTU        int       `yaml:"tun_mtu"`
	MixedPort     int       `yaml:"mixed_port"`
	SocksPort     int       `yaml:"socks_port"`
	FakeInPort    int       `yaml:"fake_in_port"`
	ApiPort       int       `yaml:"api_port"`
	DashboardPath string    `yaml:"dashboard_path"`
	LogLevel      string    `yaml:"log_level"`
	LogOutput     string    `yaml:"log_output"`
	CachePath     string    `yaml:"cache_path"`
	StoreFakeIP   bool      `yaml:"store_fakeip"`
	StoreDNS      bool      `yaml:"store_dns"`
	ClashAPI      bool      `yaml:"clash_api"`
}

type RuleSet struct {
	Group string `yaml:"group"` // geosite|geoip
	Item  string `yaml:"item"`
	Scope string `yaml:"scope"` // both|gateway|phone
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
	CertPath    string   `yaml:"cert_path"`  // 网关用 certificate_path
	CertFile    string   `yaml:"cert_file"`  // 手机用内联证书（相对 data 目录）
	IPv6OnlyDNS bool     `yaml:"ipv6_only_dns"`
}

// Members: 支持 YAML 序列（两端相同）或映射 {gateway:[], phone:[]}
type Members struct {
	Shared  []string
	Gateway []string
	Phone   []string
}

func (m *Members) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		return value.Decode(&m.Shared)
	}
	var s struct {
		Gateway []string `yaml:"gateway"`
		Phone   []string `yaml:"phone"`
	}
	if err := value.Decode(&s); err != nil {
		return err
	}
	m.Gateway, m.Phone = s.Gateway, s.Phone
	return nil
}

func (m *Members) For(target string) []string {
	var s []string
	if target == "gateway" {
		s = m.Gateway
	} else {
		s = m.Phone
	}
	if len(s) == 0 {
		s = m.Shared
	}
	return s
}

type Default2 struct {
	Gateway string `yaml:"gateway"`
	Phone   string `yaml:"phone"`
}

func (d Default2) For(target string) string {
	if target == "gateway" {
		return d.Gateway
	}
	return d.Phone
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

// PinnedSpec: 钉定块（指定规则集强制走指定出口）
type PinnedSpec struct {
	Sets     []string `yaml:"sets"`     // 规则集 tag 列表（需在 rule_sets 中定义）
	Outbound string   `yaml:"outbound"` // 钉定出口 tag
}

var knownFlags = map[string]bool{
	"pinned": true, "cn_extra": true, "clash": true,
	"fakeip": true, "telegram": true, "gh": true,
}

type Config struct {
	Secret struct {
		UIToken      string `yaml:"ui_token"`
		ProfileToken string `yaml:"profile_token"`
	} `yaml:"secret"`
	Ecs       string            `yaml:"ecs"`
	RuleDir   string            `yaml:"rule_dir"` // 网关 .srs 根目录
	Gateway   TargetSpec        `yaml:"gateway"`
	Phone     TargetSpec        `yaml:"phone"`
	Policy    map[string]string `yaml:"policy"` // pinned/cn_extra/clash/fakeip/telegram/gh -> both|gateway|phone
	RuleSets  []RuleSet         `yaml:"rule_sets"`
	Cusdom    map[string]Cusdom `yaml:"cusdom"` // key: gateway|phone
	Pinned    PinnedSpec        `yaml:"pinned"` // 钉定块（policy.pinned 开启时必填）
	Selectors struct {
		Proxy SelectorDef `yaml:"proxy"`
		Gh    SelectorDef `yaml:"gh"`
	} `yaml:"selectors"`
	Nodes  []Node   `yaml:"nodes"`
	Push   PushSpec `yaml:"push"`
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
	for k := range c.Policy {
		if !knownFlags[k] {
			return nil, fmt.Errorf("policy 含未知开关 %q（可用: pinned/cn_extra/clash/fakeip/telegram/gh）", k)
		}
	}
	return c, nil
}

// flagOf: 策略块对当前 target 是否启用
func (c *Config) flagOf(name, target string) bool {
	s := c.Policy[name]
	return s == "both" || s == target
}

func (c *Config) targetSpec(target string) *TargetSpec {
	if target == "gateway" {
		return &c.Gateway
	}
	return &c.Phone
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
