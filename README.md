# singbox-gen — sing-box 双端配置生成器

单一事实源 `data/homelab.yaml` → 装配两端产物：

- **gateway（Linux / SFL）**：目录型 conf（00~07 + systemd 单元），Web 下载 zip 或 SSH 推送
- **phone（SFA / SFI）**：单文件 profile（注释版 + nocomment 版），经订阅 URL 分发给手机客户端

分流骨架为 DNS/route 同源的瀑布流（`templates/waterfalls.tmpl`），按 `policy.*` 作用域开关；
模板细节全部封装在 `templates/`，日常只改 YAML。

## 首次运行（自动引导）

容器启动时会自动准备数据目录，**空卷也能直接起来**：

1. 创建 `data/certs`、`data/keys`
2. 若无 `data/homelab.yaml` → 从内置示例生成一份（占位节点/凭据）并打印警告
3. 为示例配置中的手机端证书自动生成**占位自签证书**（仅示例用）

此时 Web UI 顶部会显示醒目的"当前使用示例配置"横幅。真实部署只需把真实配置与证书放进去：

```bash
cd <部署目录>
# 方式一：整体替换
cp <真实>/homelab.yaml  data/homelab.yaml
cp <真实>/certs/*.crt   data/certs/
cp <SSH私钥>            data/keys/id_ed25519
docker compose restart

# 方式二：打开 UI 直接改 YAML → 保存（token 见 secret.ui_token，示例为 demo-ui）
```

> ⚠️ 真实配置缺失的证书**不会**被自动生成（否则会掩盖错误、导致 TLS 校验失败）——
> 生成逻辑只在首次引导示例配置时执行。

## 编译与发布（GitHub Actions）

1. 建仓库并推送本目录：

   ```bash
   git init -b main && git add . && git commit -m "singbox-gen"
   git remote add origin git@github.com:<user>/singbox-gen.git
   git push -u origin main
   ```

   > 仓库只带脱敏示例 `templates/homelab.example.yaml`；
   > 真实 `data/`（homelab.yaml、证书、SSH 私钥）被 .gitignore 排除，永不进仓库。
2. Actions 自动执行：`go vet + build`（编译门禁）→ 冒烟（**空目录引导** + 手机端/网关端完整渲染，
   产物过 JSON 解析 + 引用闭环校验）→ 推送镜像 `ghcr.io/<user>/<repo>:latest`
3. GHCR 包设为 public（Settings → Packages → 该包 → Make public），部署机免登录拉取：

   ```bash
   cd <部署目录>                 # 含 docker-compose.yml
   docker compose pull && docker compose up -d
   ```

   > 先把 compose `image:` 改成你的 GHCR 路径（必须全小写）。
   > DSM Container Manager「项目」方式部署时，`./data` 按 DSM 选定的项目目录解析；
   > 若怀疑解析错位，把 volume 改成绝对路径 `- /<绝对路径>/data:/data`。
4. 浏览器打开 `http://<部署机IP>:8090`，右上角输入 `secret.ui_token` 即可使用

   > **鉴权模型**：`secret.ui_token` **留空 = 内网免鉴权**（示例配置默认如此，UI 会自动隐藏 token 输入框）；
   > 填入任意字符串则 `/api/*` 与下载接口需 `X-Token`。手机订阅 URL 由 `secret.profile_token` 独立保护。

## 手机订阅

SFA/SFI 添加远程配置（改完 YAML 保存后，手机端刷新即生效，服务端每次请求实时渲染）：

```
http://<部署机IP>:8090/p/<secret.profile_token>/mobile.json
```

## 推送到网关（check 门禁）

1. 放一把能登录网关主机（`push.host`）的私钥到 `data/keys/`（`chmod 600`）
2. UI 点"推送到网关"，流程：现行 conf 副本 → 写入新文件到 /tmp → `sing-box check -C`
   （**不过则中止，线上零改动**）→ 时间戳备份 → 应用 → `systemctl restart` → is-active 验证；
   异常自动回滚备份并重启。

> 首次使用先在 UI 预览比对（右侧文件树逐项看），确认与现行 conf 等价再推。

## 仓库 vs 部署数据（边界）

| | 内容 | 位置 |
|---|---|---|
| 仓库 | Go 源码、`templates/` 骨架（含脱敏示例）、Dockerfile、CI | GitHub |
| 部署数据 | 真实 homelab.yaml、`certs/*.crt` 内联证书、`keys/` SSH 私钥 | 部署机 `data/`（bind mount，不进镜像、不进 git） |

## 目录

```
templates/homelab.example.yaml   脱敏示例（首次引导生成配置的模板 + 字段文档）
templates/sections.tmpl          固定段模板（log/dns/inbounds/route 头尾/experimental…）
templates/waterfalls.tmpl        分流瀑布流（DNS + route，两端同源）
templates/phone-header.txt       手机 profile 头部注释
templates/systemd-unit.txt       systemd 单元
*.go                             装配（config/render/validate/bootstrap）+ 服务（web/push/main）
ui.html                          内置 Web UI
```

## 修改配置的正确姿势

1. 开关类 → `policy:`（作用域 both/gateway/phone）、`rule_sets:`、`cusdom:`
2. 钉定站点（指定规则集强制走指定出口）→ `pinned.sets`（规则集 tag，需在 `rule_sets` 定义）+ `pinned.outbound`
3. 改瀑布流本体 → 编辑 `templates/waterfalls.tmpl`（两端同步生效），提交前"生成预览"看两端产物
4. 加节点 → `nodes:` + 对应 `selectors.members`
