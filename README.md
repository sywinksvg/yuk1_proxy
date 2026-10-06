# yuk1_proxy v1.1

一个**给 AI Agent 用的代理池**：把「换 IP 出网」这件事做成 MCP 工具，模型可以自己调。
自带存活自愈、WAF 感知轮转、被封一键换出口，并提供本地统一出口入口供 `curl` 直接使用。

> 打包内容：脚本 + 完整文档 + 配置样例 + 安装脚本，解压即用。

## 它能解决什么

| 场景 | 工具 | 说明 |
|---|---|---|
| 目标封锁了我的 IP（403/429/验证码/连接重置） | `yuk1_escape` | **一键换出口**：池内轮转 → 针对该目标验活 → 自动补池再试，直到拿到目标页 |
| 需要国内 IP（打国内站点走境外 IP 常被 RST） | `yuk1_check(cn_only=true)` | 按**经代理看到的出口 IP** 判归属，不是看代理主机 |
| 让请求走代理 | `yuk1_fetch` | 池内轮转出枪；遇 WAF 拦截自动换下一个；同目标优先复用上次可用出口 |
| 想用 `curl` 走池 | `yuk1_serve` + `127.0.0.1:10001` | 本地统一入口，失败自动换上游，对调用方透明 |
| 持续稳定可用 | 内置自愈 | 存活巡检（定时复验）+ 失败拉黑 + 池子见底自动补池 |

## 快速开始（3 步）

```bash
# 1) 装依赖（Python 3.10+ 与 uv）
pip install uv

# 2) 起一个 MCP 服务（先验证能跑）
cd server
uv run python mcp_yuk1_proxy.py      # 出现 stdio 等待即正常，Ctrl+C 退出

# 3) 接进你的 MCP 客户端（见 docs/01-安装配置.md）
```

命令行也可以直接用（不经过 AI）：

```bash
cd server
uv run python yuk1_proxy.py fetch                          # 拉免费代理源
uv run python yuk1_proxy.py check https://example.com --limit 40   # 对目标验活
uv run python yuk1_proxy.py serve                          # 起统一入口 127.0.0.1:10001
curl -x http://127.0.0.1:10001 https://example.com        # 之后所有请求走池
```

## 目录结构

```
yuk1_proxy/
├── README.md                  本文件（总览 + 快速开始）
├── LICENSE                    MIT
├── install.ps1                Windows 一键安装（建 venv + 装依赖）
├── docs/
│   ├── 01-安装配置.md         依赖安装、接入各类 MCP 客户端
│   ├── 02-使用说明.md         6 个工具的用法与典型场景（含被封处理）
│   ├── 03-配置参考.md         数据目录、付费代理、环境变量、池文件说明
│   └── 04-常见问题.md         FAQ 与排障
├── server/                    实际运行的 MCP 工程
│   ├── yuk1_proxy.py          代理池引擎（命令行入口）
│   ├── mcp_yuk1_proxy.py      MCP 服务包装（6 个工具）
│   ├── pyproject.toml         依赖声明（mcp / requests[socks]）
│   └── .gitignore
└── examples/
    ├── mcp-config.json        各 MCP 客户端的配置样例（复制即用）
    └── paid.txt.example       付费代理文件格式样例
```

## 六个工具

| 工具 | 作用 |
|---|---|
| `yuk1_status` | 看池子规模、统一入口状态、出口归属摘要 |
| `yuk1_check(url, cn_only, waf)` | 对目标验活；`cn_only` 只留国内出口；`waf=true` 把拦截页也算失败 |
| `yuk1_fetch(url, ...)` | 经池出枪（WAF 拦截自动换出口；同目标复用上次可用出口） |
| `yuk1_escape(url, ...)` | **被封一键换出口**，返回各阶段 trace |
| `yuk1_serve(action)` | 管理本地统一入口（status / start / restart） |
| `yuk1_nps_harvest(...)` | 高级可选源（默认关闭，见下） |

## 环境变量

| 变量 | 作用 | 默认 |
|---|---|---|
| `YUK1_PROXY_DATA` | 数据目录（池文件 / 缓存 / 元数据） | `~/.yuk1_proxy/data` |
| `YUK1_PROXY_UPSTREAM` | 本地上游代理（GitHub 类源用，如 `http://127.0.0.1:7890`） | 自动探测常见端口 |
| `YUK1_PROXY_ALLOW_DIRECT` | 池空时是否允许**直连兜底**；置 `0` → 回 502，绝不漏本机 IP | `1` |
| `YUK1_PROXY_ENABLE_NPS` | 启用 nps 采集源（高级，见下） | 空（关闭） |
| `YUK1_PROXY_FOFA_Q` | `fofa_q.py` 路径（nps 源需要，**本包不含**） | 与脚本同目录 |

## 统一入口怎么判断「到底走没走代理」

入口在 `CONNECT` 应答里回一个标识头，调用方可以直接确认：

```bash
curl -sv -x http://127.0.0.1:10001 https://example.com 2>&1 | grep -i x-yuk1-egress
# < X-Yuk1-Egress: proxy     走了池里的代理
# < X-Yuk1-Egress: direct    池空/全挂，用了本机 IP（本机 IP 已暴露）
```

也可以访问显 IP 的页面比对：`curl -x http://127.0.0.1:10001 https://api.ipify.org`。

## 关于「nps 源」（默认关闭，请自行判断）

工具包内含一个**可选**的额外代理来源：利用 nps（ehang-io 内网穿透）默认配置的认证缺陷
（CVE-2022-40494，官方版本未修复）从其管理面板枚举 socks5 隧道作为代理出口。

- **默认关闭**（环境变量 `YUK1_PROXY_ENABLE_NPS=1` 才启用），需要额外的 FOFA 账号配置；
- **依赖未随包分发**：启用还需自备 `fofa_q.py`（负责把 FOFA 查询落到本地 JSON），
  用 `YUK1_PROXY_FOFA_Q` 指向它；没有它时该源不可用，其余功能不受影响；
- 该功能的性质是**使用他人服务器的资源**：面板流量计数会变化、连接元数据对 nps 控制者可见；
- **仅在你有明确授权的安全研究场景自行启用**，使用后果自负；
- 不开启时，工具包是一个纯净的公开代理池，功能完全正常。

## 代理纪律（重要）

1. **登录态 Cookie / 长期凭据禁过免费代理**（不可信中间人）；一次性测试凭据可以
2. 同一代理别反复打（默认轮转，单轮同代理 ≤3 枪）
3. 验证用首页/静态资源等轻量请求
4. **先判防护类型再换出口**：整站 000、几十秒自愈多为频率防护，降频即可；换代理反而可能更糟

## 依赖

- **Python 3.10+**（必须）
- **uv**（推荐，`pip install uv`；用于隔离依赖，也可直接用 pip 装 `mcp` 与 `requests[socks]`）
- 网络：能出网即可

## 许可与免责

MIT（见 `LICENSE`）。脚本可自由使用与修改。使用者需自行确保其使用方式符合当地法律法规与目标授权范围。
