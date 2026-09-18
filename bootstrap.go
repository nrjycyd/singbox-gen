package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 示例配置标记（首行注释），用于 UI 提示"当前为占位配置"
const sampleMarker = "示例配置（自动生成）"

// Bootstrap 首次运行引导：确保 data 目录可用，避免容器启动即失败。
// 仅在 homelab.yaml 不存在时生成示例配置与占位自签证书（真实配置缺失的证书不自动生成，
// 否则会掩盖错误并导致 TLS 校验失败）。
func Bootstrap(dataDir string) error {
	for _, d := range []string{"certs", "keys"} {
		if err := os.MkdirAll(filepath.Join(dataDir, d), 0755); err != nil {
			return err
		}
	}
	cfgPath := filepath.Join(dataDir, "homelab.yaml")
	fresh := false
	if _, err := os.Stat(cfgPath); err != nil {
		b, err := templatesFS.ReadFile("templates/homelab.example.yaml")
		if err != nil {
			return fmt.Errorf("内置示例配置缺失: %w", err)
		}
		content := "# " + sampleMarker + "：节点/凭据/ECS 均为占位值，真实部署请替换本文件内容并删除本行\n" + string(b)
		if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
			return err
		}
		fresh = true
		log.Printf("首次运行：已生成示例配置 %s（占位值，需替换为真实配置）", cfgPath)
	}
	if !fresh {
		return nil
	}
	c, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	for _, n := range c.Nodes {
		if n.CertFile == "" {
			continue
		}
		p := filepath.Join(dataDir, n.CertFile)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		if err := genSelfSignedCert(p, n.SNI); err != nil {
			return fmt.Errorf("生成占位自签证书 %s 失败: %w", p, err)
		}
		log.Printf("已生成占位自签证书 %s (CN=%s)，仅供示例配置渲染；真实部署请放入服务器实际证书", p, n.SNI)
	}
	return nil
}

// IsSampleConfig 判断当前是否仍在使用自动生成的示例配置
func IsSampleConfig(dataDir string) bool {
	b, err := os.ReadFile(filepath.Join(dataDir, "homelab.yaml"))
	if err != nil {
		return false
	}
	first := strings.SplitN(string(b), "\n", 2)[0]
	return strings.Contains(first, sampleMarker)
}

func genSelfSignedCert(path, sni string) error {
	if sni == "" {
		sni = "localhost"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}
