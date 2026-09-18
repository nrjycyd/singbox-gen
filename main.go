package main

import (
	"embed"
	"flag"
	"log"
	"net/http"
	"os"
)

//go:embed ui.html
var uiFS embed.FS

func main() {
	data := flag.String("data", "./data", "数据目录（homelab.yaml / certs / keys）")
	addr := flag.String("addr", ":8090", "监听地址")
	flag.Parse()

	if _, err := os.Stat(*data + "/homelab.yaml"); err != nil {
		log.Fatalf("找不到 %s/homelab.yaml（volume 是否正确挂载？）", *data)
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
