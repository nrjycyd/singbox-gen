# singbox-gen — sing-box 双端配置生成器

单一事实源 `data/homelab.yaml` → 装配两端产物：

- **gateway（Linux / SFL）**：三种透明代理模式（**tun / ebpf / tproxy**，UI 勾选多选 + 端口自定义），
  每种模式一套 conf 目录（00~07 + systemd 单元）；可 Web 下载 zip 或按模式 SSH 推送
- **phone（SFA / SFI）**：单文件 profile，经订阅 URL 分发给手机客户端

分流规则（DNS 与 route 同源瀑布流）全部定义在 `data/homelab.yaml` 的 `dns_rules` / `route_rules` 中，
顺序即优先级、可按 `_scope` 分端、按 `_if` 受策略开关控制；模板只保留固定段骨架。

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

# 方式二：打开 UI 直接改 YAML → 保存
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
4. 浏览器打开 `http://<部署机IP>:8090` 直接使用（**无鉴权**）

   > ⚠️ 本工具不含鉴权：任何能访问该端口的内网设备都能改配置、下载产物、
   > 触发"推送到网关"（等价于登录网关执行 systemd 操作）。**只部署在可信内网**；
   > 如需暴露到公网或不可信网络，请自行在反向代理层加认证。
   > 手机订阅 URL 由 `secret.profile_token` 作为路径凭证（可改任意字符串）。

## 手机订阅

手机端添加远程配置（改完 YAML 保存后，刷新即生效，服务端每次请求实时渲染）：

```
Android（SFA）: http://<部署机IP>:8090/p/<secret.profile_token>/sfa.json
iOS（SFI）    : http://<部署机IP>:8090/p/<secret.profile_token>/sfi.json
```

## 推送到网关（check 门禁）

1. 放一把能登录网关主机（`push.host`）的私钥到 `data/keys/`（`chmod 600`）
2. UI 点"推送到网关"，流程：现行 conf 副本 → 写入新文件到 /tmp → `sing-box check -C`
   （**不过则中止，线上零改动**）→ 时间戳备份 → 应用 → `systemctl restart` → is-active 验证；
   异常自动回滚备份并重启。

> 首次使用先在 UI 预览比对（右侧文件树逐项看），确认与现行 conf 等价再推。

## 目标端模型

| 目标端 | 说明 | 产物 |
|---|---|---|
| **SFL** | Linux 网关（三种模式：tun/ebpf/tproxy） | `SFL/<mode>/00..07 + systemd` |
| **SFA** | Android（SFA 客户端） | 单文件 profile |
| **SFI** | iOS（SFI 客户端） | 单文件 profile |
| `mobile` | SFA/SFI 的共享基座 | — |

- `SFA:` / `SFI:` 只写与 `mobile` 不同的字段（缺省全部继承）；作用域字段（policy / rule_sets.scope / 规则 `_scope` / cusdom / selectors / nodes.targets）取值 **both | SFL | SFA | SFI | mobile**（`mobile` = 两台手机）

## 仓库 vs 部署数据（边界）

| | 内容 | 位置 |
|---|---|---|
| 仓库 | Go 源码、`templates/` 骨架（含脱敏示例）、Dockerfile、CI | GitHub |
| 部署数据 | 真实 homelab.yaml、`certs/*.crt` 内联证书、`keys/` SSH 私钥 | 部署机 `data/`（bind mount，不进镜像、不进 git） |

## 目录

```
templates/homelab.example.yaml   脱敏示例（首次引导模板 + 字段/规则文档）
templates/sections.tmpl          固定段模板（log/dns 服务器/inbounds/route 选项/experimental…）
templates/phone-header.txt       手机 profile 头部注释
templates/systemd-unit.txt       systemd 单元
*.go                             装配（config/render/validate/bootstrap）+ 服务（web/push/main）
ui.html                          内置 Web UI
```

## Web UI（左右双栏，按需加载）

```
产物预览（左）                                  │ 规则编辑（右）
[SFA][SFI]  [☑SFL:tun][☑SFL:ebpf][☑SFL:tproxy]  │ rule_sets / DNS 规则 / Route 规则
文件树 + 内容                                    │ 拖动排序、向导添加、保存
```

- **按需生成**：点哪个按钮只渲染那一个（`SFA` / `SFI` / `SFL:tun|ebpf|tproxy`），不再一次性列出全部
- 模式前的勾选框 = 启用/停用（定点写入 `homelab.yaml` 的 `SFL.modes.<mode>.enabled`，无需重启）
- 右上 `默认: xxx` 下拉 = `SFL.default_mode`；推送按钮旁的下拉选择推送哪个模式
- 规则编辑保存后**自动刷新左侧当前预览**
- 界面不再提供 YAML 文本编辑区：**非规则部分**（节点/端口/模式入参/ECS 等）直接编辑部署目录的
  `data/homelab.yaml`，然后在界面点一次按钮即可生效（配置每次请求实时读取，无需重启）

### 模式与端口

- 勾选框对应 YAML 的 `SFL.modes.<mode>.enabled`；勾选即改写左侧 YAML 文本（点"保存 YAML"生效）
- 端口统一在 `SFL.ports`（mixed / socks / fake_in / api / redirect / tproxy），生成前校验范围与重复
- 各模式前置条件（推送时弹窗提示）：

| 模式 | 前置条件 |
|---|---|
| tun | `net.ipv4.ip_forward=1`；nftables 由 sing-box（auto_redirect）自管 |
| ebpf | **reF1nd fork**（`with_ebpf`）+ `CAP_BPF`；TC 挂下游接口，**不需要 ip_forward** |
| tproxy | `ip_forward=1`；宿主侧需 `nftables.conf` + `singbox_tproxy.service`（fwmark 策略路由）——本项目**不生成**这两个高危物件 |

### 规则编辑页（方案 B：同屏三栏 + 行级联动）

```
┌ 规则集栏 ──────────────┬ DNS 规则列 ────────────┬ Route 规则列 ───────────┐
│ geosite-private  ×2    │ 步骤0 DNS×2            │ 步骤0 Route×8           │
│ geosite-telegram ×2    │ 步骤1 局域网→local-dns │ 步骤1 局域网→direct     │
│ [生成规则对]           │ 步骤clash ...          │ 步骤clash ...           │
└────────────────────────┴───────────────────────┴─────────────────────────┘
```

- **行 = 步骤**：按 `_group`（或 `_note` 前缀编号）把两侧规则配对到同一行；单侧缺失显示"—"，可点"+"**补一条**
- **拖动整行 = 两侧联动排序**（也可用 ↑↓ 在组内微调）；顺序即"首条命中即停"的优先级
- **规则集**：增删改 + 引用计数；`生成规则对` 一键插入同名 `_group` 的 DNS+Route 规则；
  点规则集标签**高亮**所有引用它的行
- 点规则摘要 → 行内表单（注释/步骤/作用端/开关/动作/规则集/ip_cidr/inbound/protocol/clash_mode/server/outbound/rcode/method/client_subnet + 高级 JSON）
- 保存只改写 YAML 中 `rule_sets` / `dns_rules` / `route_rules` 三个节点，其余内容与注释原样保留（`yaml.Node` 定点替换、2 空格缩进）；保存后左侧 YAML 自动刷新

> 规则改动 → 保存 → 「生成预览」确认两端产物 → 「推送到网关」（check 门禁）。

## 修改配置的正确姿势（全部在 YAML 里，无需改代码）

1. **分流规则** → `dns_rules:` / `route_rules:`：**顺序即优先级，首条命中即停**。
   每条形如：

   ```yaml
   - _note: 6 Telegram → 代理 DNS        # 生成到产物里的注释
     _if: telegram                        # 可选：受 policy.telegram 开关控制
     _scope: both                         # 可选：both|gateway|phone（默认 both）
     _for_each: pinned_sets               # 可选：按列表循环展开（内置 pinned_sets）
     rule_set: [geosite-telegram]         # 其余键原样进入 sing-box 规则对象
     action: route
     server: "{{proxy_dns}}"
   ```

   可用变量：`{{proxy_dns}}`（fakeip-dns/remote-dns）`{{local_dns}}` `{{remote_dns}}` `{{ecs}}`
   `{{pinned_outbound}}` `{{item}}`（循环项）；列表整项展开：`ip_cidr: ["{{gh_cidr}}"]`
2. 开关类 → `policy:`（作用域 both/gateway/phone）、`rule_sets:`（含 scope）、`cusdom:`
3. 钉定站点 → `pinned.sets` + `pinned.outbound`
4. 节点 → `nodes:` + 对应 `selectors.members`
5. 只有改"固定段结构"（如 DNS 服务器列表、route 选项块）才需要动 `templates/sections.tmpl`
