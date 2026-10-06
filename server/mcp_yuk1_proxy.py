#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp_yuk1_proxy.py — yuk1_proxy 的 MCP 常驻服务（stdio · uv 管理）

把同目录 yuk1_proxy.py（代理池引擎）的核心能力暴露为 MCP tools：
  yuk1_status       池子总览（各池条数 / 10001 监听 / nps 出口归属）
  yuk1_nps_harvest  nps 源采集（CVE-2022-40494 绕过 → socks5 端到端验证 → 入池）
  yuk1_check        对目标验活（写 ok 池；cn_only 含出口归属判定）
  yuk1_fetch        经池出枪（进程内轮转，结构化返回）
  yuk1_serve        统一入口(10001)管理：status / start / restart

纪律：stdio 传输层禁写 stdout——代理池函数调用期的一切 print 被重定向捕获。
"""
import contextlib
import io
import json
import random
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Optional

# 自包含：引擎 yuk1_proxy.py 与本文件同目录（插件分发形态）
BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(BIN))

import yuk1_proxy as pp  # noqa: E402

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("yuk1_proxy")


def _quiet(fn, *args, **kwargs):
    """执行会 print 的原函数：stdout 重定向，保 MCP stdio 协议纯净。"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        out = fn(*args, **kwargs)
    return out, buf.getvalue()


def _tail(text: str, n: int = 14):
    return [l for l in (text or "").strip().splitlines() if l.strip()][-n:]


def _listening(port: int = 10001) -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def _pid_on(port: int) -> Optional[int]:
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                             errors="replace", timeout=15).stdout
    except Exception:
        return None
    for line in (out or "").splitlines():
        if f":{port} " in line and "LISTENING" in line.upper():
            parts = line.split()
            if parts and parts[-1].isdigit():
                return int(parts[-1])
    return None


def _spawn_serve(port: int) -> dict:
    log = pp.POOL_DIR / f"_serve{port}.log"
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    fh = open(log, "a", encoding="utf-8")
    p = subprocess.Popen([sys.executable, str(BIN / "yuk1_proxy.py"), "serve",
                          "--port", str(port), "--entry-port", str(port)],
                         cwd=str(BIN), stdout=fh, stderr=subprocess.STDOUT,
                         creationflags=flags)
    fh.close()   # 子进程已继承句柄，父侧关掉防句柄泄漏
    time.sleep(2)
    return {"pid": p.pid, "listening": _listening(port), "log": str(log)}


@mcp.tool()
def yuk1_status() -> dict:
    """代理池总览：各池文件条数、统一入口(10001)监听与 PID、nps 源条目与出口归属摘要。"""
    try:
        meta = json.load(open(pp.NPS_META_FILE, encoding="utf-8"))
    except Exception:
        meta = {}
    pid = _pid_on(10001)
    return {
        "raw": len(pp.load_file(pp.RAW_FILE)),
        "ok": len(pp.load_file(pp.OK_FILE)),
        "cn_ok": len(pp.load_file(pp.CN_OK_FILE)),
        "ok_10001": len(pp.load_file(pp.POOL_DIR / "ok_10001.txt")),
        "paid": len(pp.load_file(pp.PAID_FILE)),
        "nps_raw": pp.load_file(pp.NPS_RAW_FILE),
        "nps_egress": {k: {"egress_ip": v.get("egress_ip"), "isp": v.get("isp"),
                           "client_remark": v.get("client_remark")} for k, v in meta.items()},
        "serve_10001": {"listening": pid is not None, "pid": pid},
        "blacklist": len(pp._BLACK),
        "hint": "打国内目标先 yuk1_check(cn_only=True)；缺国内 IP 跑 yuk1_nps_harvest",
    }


@mcp.tool()
def yuk1_nps_harvest(probe: int = 300, skip_fofa: bool = True, keep_all: bool = False,
                     via: Optional[str] = None) -> dict:
    """nps 源采集：FOFA 候选 → 鉴权绕过探测 → socks5 隧道枚举 → 端到端验证 → 并入池。
    probe=本轮探测候选主机数（300≈40s）；skip_fofa=True 复用已落盘候选（省 FOFA 额度，
    候选位置自动轮转、多轮覆盖新面）；keep_all=True 保留非 CN 出口（默认只收国内出口）；
    via=采集链出口（如 "127.0.0.1:10001" 用本地入口转出 / "socks5h://…"），设置后扫描流量
    不暴露本机 IP（推荐填 127.0.0.1:10001，经已有出口扫下一批）。"""
    entries, log = _quiet(pp.nps_harvest, fofa_size=10000, probe=probe, workers=60,
                          ep_cap=400, keep_all=keep_all, skip_fofa=skip_fofa, via=via)
    try:
        meta = json.load(open(pp.NPS_META_FILE, encoding="utf-8"))
    except Exception:
        meta = {}
    return {
        "this_run_usable": entries,
        "nps_raw_total": len(pp.load_file(pp.NPS_RAW_FILE)),
        "egress_of_pool": {k: {"egress_ip": v.get("egress_ip"), "isp": v.get("isp")}
                           for k, v in meta.items()},
        "log_tail": _tail(log, 16),
    }


@mcp.tool()
def yuk1_check(url: str, cn_only: bool = True, limit: int = 20,
               timeout: int = 6, port: int = 10001, waf: bool = False) -> dict:
    """对目标验证池内代理能否打（验活结果写 ok 池供统一入口使用）。
    url 用目标站首页/静态资源等轻量页；cn_only=True 时校验出口归属——
    socks5 条目按「经代理看到的出口 IP」判定，不看代理主机 IP；
    waf=True 时把拦截页（403/429/验证码等）也算失败——找「真能打该目标」的出口。"""
    alive, log = _quiet(pp.check, url, limit, timeout, 30, cn_only, None, waf)
    if alive and port:
        (pp.POOL_DIR / f"ok_{port}.txt").write_text("\n".join(alive), encoding="utf-8")
    return {"alive": alive, "count": len(alive),
            "written": f"ok_{port}.txt" if alive else None, "log_tail": _tail(log)}


_HOST_PREF = {}   # host -> 最近可用条目（同目标优先复用，连接更稳）
_USE = {}         # 条目 -> 本轮已用次数（同一代理 ≤3 枪）


def _fetch_core(url: str, method: str = "GET", data=None, headers=None, max_tries: int = 8) -> dict:
    """核心出枪：分层池 → 用量/主机偏好排序 → 轮转；WAF 拦截自动换出口。"""
    host = urllib.parse.urlsplit(url).hostname or url
    # 分层优先：入口池(最新验活) → 中国池 → 通用池；层内打乱
    pool, seen = [], set()
    for tier in (pp.POOL_DIR / "ok_10001.txt", pp.CN_OK_FILE, pp.OK_FILE):
        rows = pp.load_file(tier)
        random.shuffle(rows)
        for p in rows:
            if p not in seen:
                seen.add(p)
                pool.append(p)
    pool = pp.filter_pool(pool)
    if not pool:
        return {"ok": False, "error": "池为空或全在拉黑期：先 yuk1_check(url) 或 yuk1_nps_harvest()"}
    if all(_USE.get(p, 0) >= 3 for p in pool):
        _USE.clear()   # 全部用满 3 枪 → 新一轮
    pool.sort(key=lambda p: _USE.get(p, 0))
    pref = _HOST_PREF.get(host)
    if pref and pref in pool:
        pool.remove(pref)
        pool.insert(0, pref)
    hdrs = {"User-Agent": pp.UA}
    for h in headers or []:
        k, _, v = str(h).partition(":")
        hdrs[k.strip()] = v.strip()
    tried, blocked = [], []
    for p in pool[: max(1, max_tries)]:
        try:
            t0 = time.time()
            s = pp._session()
            s.proxies.update(pp.entry_to_proxies(p))
            r = s.request(method, url, data=data, headers=hdrs, timeout=(4, 12))
            _USE[p] = _USE.get(p, 0) + 1
            if pp.looks_blocked(r.status_code, r.text):
                blocked.append(f"{p} -> HTTP {r.status_code}")
                continue
            pp.blacklist_clear(p)
            if len(_HOST_PREF) > 500:
                _HOST_PREF.clear()
            _HOST_PREF[host] = p
            return {"ok": True, "proxy": p, "status": r.status_code,
                    "elapsed": round(time.time() - t0, 2),
                    "headers": dict(list(r.headers.items())[:12]),
                    "body_head": r.text[:800], "tried": tried, "blocked_by": blocked}
        except Exception as e:
            pp.blacklist_add(p)
            tried.append(f"{p} -> {type(e).__name__}")
    return {"ok": False, "tried": tried, "blocked_by": blocked,
            "error": "全部出口失败或被拦：重跑 yuk1_check(url, waf=True) 或 yuk1_nps_harvest()"}


@mcp.tool()
def yuk1_fetch(url: str, method: str = "GET", data: Optional[str] = None,
               headers: Optional[list] = None, max_tries: int = 8) -> dict:
    """从池里挑活代理直接出枪（进程内轮转，不经 10001）。WAF 感知：403/429/验证码页
    等拦截响应自动换出口重试；同一目标优先复用上次可用出口；单轮内同一代理 ≤3 枪。
    返回所用代理、状态码、响应头与 body 头部（≤800 字符）；失败返回尝试/被拦清单。"""
    return _fetch_core(url, method, data, headers, max_tries)


@mcp.tool()
def yuk1_escape(url: str, method: str = "GET", data: Optional[str] = None,
                headers: Optional[list] = None, allow_harvest: bool = True) -> dict:
    """【被封锁/换出口 · 一键】发现目标封锁本机 IP（403/429/验证码/连接重置/封禁页）时调用：
    自动换出口直到拿到目标页——① 现有池轮转（WAF 拦截自动换下一个出口）；
    ② 都不行 → 对目标跑 waf 模式验活（筛出「真能打这个目标」的出口）再轮转；
    ③ 仍不行且 allow_harvest=True → 自动补采一批国内 nps socks5（经本地入口出网）再试。
    返回命中出口/状态码/响应头 + trace 阶段明细（便于判断频率防护 vs IP 封禁）。"""
    trace = []
    r = _fetch_core(url, method, data, headers)
    trace.append({"stage": "pool_rotate", "ok": r.get("ok"), "status": r.get("status"),
                  "blocked": r.get("blocked_by", [])[:5], "failed": r.get("tried", [])[:5]})
    if r.get("ok"):
        r["trace"] = trace
        return r
    alive, _ = _quiet(pp.check, url, 12, 6, 30, True, None, True)
    trace.append({"stage": "waf_check", "alive_for_target": len(alive)})
    if alive:
        (pp.POOL_DIR / "ok_10001.txt").write_text("\n".join(alive), encoding="utf-8")
        r = _fetch_core(url, method, data, headers)
        trace.append({"stage": "pool_rotate_2", "ok": r.get("ok"), "status": r.get("status")})
        if r.get("ok"):
            r["trace"] = trace
            return r
    if allow_harvest:
        via = "127.0.0.1:10001" if _listening(10001) else None
        entries, _ = _quiet(pp.nps_harvest, fofa_size=10000, probe=200, workers=60,
                            ep_cap=200, keep_all=False, skip_fofa=True, via=via)
        trace.append({"stage": "harvest", "via": via or "直连", "usable": len(entries)})
        if entries:
            alive2, _ = _quiet(pp.check, url, 12, 6, 30, True, None, True)
            trace.append({"stage": "harvest_check", "alive_for_target": len(alive2)})
            if alive2:
                (pp.POOL_DIR / "ok_10001.txt").write_text("\n".join(alive2), encoding="utf-8")
                r = _fetch_core(url, method, data, headers)
    r["trace"] = trace
    return r


@mcp.tool()
def yuk1_serve(action: str = "status", port: int = 10001) -> dict:
    """统一出口入口管理：status 查监听 / start 用当前代码后台起一个（已占用则不重复起）/
    restart 杀掉占用进程后用当前代码重起（升级过 yuk1_proxy.py 后用它让入口生效）。"""
    if action == "status":
        pid = _pid_on(port)
        return {"port": port, "listening": pid is not None, "pid": pid}
    if action == "start":
        if _pid_on(port) is not None:
            return {"port": port, "listening": True, "note": "已占用；如是旧代码进程用 restart 升级"}
        return {"port": port, **_spawn_serve(port)}
    if action == "restart":
        pid = _pid_on(port)
        if pid:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=15)
            else:
                import os
                import signal
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
            time.sleep(1)
        return {"port": port, "killed": pid, **_spawn_serve(port)}
    return {"error": "action 只支持 status / start / restart"}


if __name__ == "__main__":
    mcp.run()
