package main

import (
	"embed"
	"flag"
	"log"
	"net/http"
)

//go:embed ui.html
var uiFS embed.FS

func main() {
	data := flag.String("data", "./data", "数据目录（homelab.yaml / certs / keys）")
	addr := flag.String("addr", ":8090", "监听地址")
	flag.Parse()

	if err := Bootstrap(*data); err != nil {
		log.Fatalf("数据目录初始化失败: %v", err)
	}
	if IsSampleConfig(*data) {
		log.Printf("警告: 当前使用自动生成的示例配置（占位节点），请在 Web UI 中替换为真实配置")
	}
	c, err := LoadConfig(*data + "/homelab.yaml")
	if err != nil {
		log.Fatalf("配置加载失败: %v", err)
	}
	if c.Secret.UIToken == "" {
		log.Println("警告: secret.ui_token 为空，API 将拒绝所有请求，请在 homelab.yaml 设置 token")
	}

	srv := &Server{dataDir: *data}
	mux := http.NewServeMux()
	srv.HandleRoutes(mux)
	log.Printf("singbox-gen listening on %s, data=%s", *addr, *data)
	log.Fatal(http.ListenAndServe(*addr, srv.Middleware(mux)))
}
