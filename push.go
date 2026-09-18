package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Pusher struct {
	spec    PushSpec
	dataDir string
	logf    func(string)
}

func (p *Pusher) dial() (*ssh.Client, error) {
	var auth []ssh.AuthMethod
	if p.spec.KeyFile != "" {
		path := p.spec.KeyFile
		if !strings.HasPrefix(path, "/") {
			path = p.dataDir + "/" + path
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取私钥失败: %w", err)
		}
		key, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(key))
	}
	if p.spec.Password != "" {
		auth = append(auth, ssh.Password(p.spec.Password))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("push 配置缺少 key_file 或 password")
	}
	cfg := &ssh.ClientConfig{
		User:            p.spec.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", p.spec.Host+":22", cfg)
}

func (p *Pusher) run(c *ssh.Client, cmd string) (string, error) {
	s, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	out, err := s.CombinedOutput(cmd)
	txt := strings.TrimSpace(string(out))
	if err != nil {
		return txt, fmt.Errorf("%w\n%s", err, txt)
	}
	return txt, nil
}

// Deploy 按门禁流程发布网关配置：temp 合并 → check → 备份 → 应用 → 重启
func (p *Pusher) Deploy(files map[string]string) error {
	c, err := p.dial()
	if err != nil {
		return err
	}
	defer c.Close()
	tmp := "/tmp/singbox-gen.push"
	conf := strings.TrimRight(p.spec.ConfDir, "/")
	log := p.logf

	logf := func(format string, a ...any) { log(fmt.Sprintf(format, a...)) }

	logf("[1/6] 准备临时目录（现行配置副本）")
	if _, err := p.run(c, "rm -rf "+tmp+" && mkdir -p "+tmp+" && cp -a "+conf+"/. "+tmp+"/"); err != nil {
		return fmt.Errorf("准备临时目录失败: %w", err)
	}

	logf("[2/6] 上传新配置到临时目录")
	sc, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer sc.Close()
	var names []string
	for n := range files {
		if n == "sing-box.service" { // systemd 单元不属于 conf 目录，跳过
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := sc.Create(tmp + "/" + n)
		if err != nil {
			return fmt.Errorf("写入 %s 失败: %w", n, err)
		}
		if _, err := f.Write([]byte(files[n])); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	logf("[3/6] sing-box check（门禁）")
	if out, err := p.run(c, "sing-box check -C "+tmp); err != nil {
		p.run(c, "rm -rf "+tmp)
		return fmt.Errorf("check 未通过，已放弃推送:\n%s", out)
	}
	logf("      check 通过")

	logf("[4/6] 备份现行配置")
	bk, err := p.run(c, "set -e; B="+conf+".bak.$(date +%Y%m%d%H%M%S); cp -a "+conf+" \"$B\"; echo $B")
	if err != nil {
		return fmt.Errorf("备份失败: %w", err)
	}
	logf("      备份于 " + bk)

	logf("[5/6] 应用新配置")
	if _, err := p.run(c, "cp -a "+tmp+"/. "+conf+"/ && rm -rf "+tmp); err != nil {
		return fmt.Errorf("应用失败（配置未变）: %w", err)
	}

	logf("[6/6] 重启服务")
	out, err := p.run(c, "systemctl restart "+p.spec.Service+" && sleep 1 && systemctl is-active "+p.spec.Service)
	if err != nil || !strings.Contains(out, "active") {
		logf("      启动异常，自动回滚: " + out)
		if _, rerr := p.run(c, "rm -rf "+conf+" && cp -a "+bk+" "+conf+" && systemctl restart "+p.spec.Service); rerr != nil {
			return fmt.Errorf("!!! 回滚也失败，需人工处理 (%s): %w", bk, rerr)
		}
		return fmt.Errorf("推送失败，已回滚到 " + bk)
	}
	logf("完成：" + p.spec.Service + " " + out)
	return nil
}
