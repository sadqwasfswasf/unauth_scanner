#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 UnAuthHunter —— 多目标端口扫描 + 未授权访问漏洞检测器 (v1.0)
================================================================================
用途:
    1. 对多个 IP / CIDR 网段进行 TCP 端口扫描;
    2. 自动识别开放端口上的服务协议 (HTTP/HTTPS/Banner);
    3. 使用多重特征严格匹配, 检测各类服务/中间件/框架/AI 组件的
       【未授权访问 / 匿名访问 / 默认口令】漏洞;
    4. 输出控制台结果 + JSON / CSV / HTML 报告。

依赖: 仅 Python 3.8+ 标准库, 无第三方依赖。
================================================================================
"""

import argparse
import base64
import concurrent.futures
import csv
import datetime
import html as html_mod
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, List, Tuple

__version__ = "1.0"
TOOL_NAME = "UnAuthHunter"

# ==============================================================================
# 0. 全局配置与工具函数
# ==============================================================================

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_COLOR = {
    "Critical": "\033[41;37m", "High": "\033[31m", "Medium": "\033[33m",
    "Low": "\033[36m", "Info": "\033[90m",
}
RST = "\033[0m"
G = "\033[32m"
Y = "\033[33m"
C = "\033[36m"
D = "\033[90m"

USE_COLOR = True


def c(text, color):
    if not USE_COLOR:
        return str(text)
    return "%s%s%s" % (color, text, RST)


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_name(ts=None):
    ts = ts or datetime.datetime.now()
    return ts.strftime("%Y%m%d_%H%M%S")


def b2s(data: bytes, limit=300) -> str:
    """bytes 转可读字符串(用于证据输出)"""
    try:
        text = data[:limit].decode("utf-8", "replace")
    except Exception:
        text = repr(data[:limit])
    return re.sub(r"\s+", " ", text).strip()


class Resp:
    """轻量 HTTP 响应"""

    def __init__(self, status: int, headers: dict, body: bytes, https: bool = False):
        self.status = status
        self.headers = headers          # 小写 key
        self.body = body
        self.https = https
        self._json = None
        self._json_parsed = False

    def header(self, name, default=""):
        return self.headers.get(name.lower(), default)

    def text(self, limit=100000) -> str:
        return self.body[:limit].decode("utf-8", "replace")

    def json(self):
        if not self._json_parsed:
            self._json_parsed = True
            try:
                self._json = json.loads(self.body[:512000].decode("utf-8", "replace"))
            except Exception:
                self._json = None
        return self._json

    def has(self, *subs) -> bool:
        low = self.body[:262144].lower()
        return all(s.lower().encode("utf-8", "replace") in low for s in subs)


# ==============================================================================
# 1. 基础网络层: TCP / UDP / 原始 HTTP 客户端
# ==============================================================================

def tcp_connect(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, port))
    return s


def recv_all(sock, timeout=3.0, limit=1048576) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < limit:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            except ConnectionResetError:
                break
            if not chunk:
                break
            buf += chunk
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return buf


def tcp_probe(ip, port, data: bytes, timeout=4.0, read_timeout=3.0,
              pre_read: bool = False, limit=262144) -> Tuple[bytes, bytes]:
    """发送原始 TCP 数据并读取响应。返回 (banner, response)。
    pre_read=True 时先等服务端主动下发的 banner。"""
    banner = b""
    resp = b""
    try:
        s = tcp_connect(ip, port, timeout)
        if pre_read:
            s.settimeout(min(2.0, timeout))
            try:
                banner = s.recv(4096)
            except Exception:
                banner = b""
        s.sendall(data)
        resp = recv_all(s, read_timeout, limit)
        return banner, resp
    except Exception:
        return banner, resp


def http_request(ip, port, path, timeout=4.0, https=False, method="GET",
                 headers=None, body=None, auth=None, limit=262144,
                 follow_redirect=False) -> Optional[Resp]:
    """极简 raw HTTP(S) 客户端(不跟随重定向、不缓存), 返回 Resp 或 None"""
    s = None
    try:
        s = tcp_connect(ip, port, timeout)
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(s)
            except Exception:
                return None
        host = "%s:%d" % (ip, port)
        hdrs = {
            "Host": host,
            "User-Agent": "Mozilla/5.0 (compatible; UnAuthHunter/%s; SecurityAudit)" % __version__,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)
        if auth:
            token = base64.b64encode(
                ("%s:%s" % auth).encode("utf-8")).decode()
            hdrs["Authorization"] = "Basic " + token
        payload = ("%s %s HTTP/1.1\r\n" % (method, path)).encode("utf-8")
        for k, v in hdrs.items():
            payload += ("%s: %s\r\n" % (k, v)).encode("utf-8")
        if body is not None:
            payload += ("Content-Length: %d\r\n" % len(body)).encode()
        payload += b"\r\n"
        if body is not None:
            payload += body if isinstance(body, bytes) else body.encode()
        s.sendall(payload)
        raw = recv_all(s, timeout, limit + 65536)
        return parse_http(raw, limit)
    except Exception:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def parse_http(raw: bytes, limit=262144) -> Optional[Resp]:
    if not raw or not raw.startswith(b"HTTP/"):
        return None
    try:
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.decode("latin-1").strip().lower()] = \
                    v.decode("latin-1").strip()
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = _dechunk(body)
        return Resp(status, headers, body[:limit])
    except Exception:
        return None


def _dechunk(data: bytes) -> bytes:
    out = b""
    i = 0
    try:
        while i < len(data):
            j = data.find(b"\r\n", i)
            if j < 0:
                break
            size = int(data[i:j].split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            out += data[j + 2: j + 2 + size]
            i = j + 2 + size + 2
            if len(out) > 5242880:
                break
    except Exception:
        return out
    return out


# ==============================================================================
# 2. 扫描目标封装
# ==============================================================================

class Target:
    """一个 (ip, port) 目标, 带懒加载的服务识别缓存"""

    def __init__(self, ip, port, timeout=4.0):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.banner = b""          # 服务主动下发的 banner
        self.banner_done = False
        self.proto = None          # 'http' / 'https' / None
        self.identify_done = False
        self.server_header = ""
        self.extra = {}

    # ---- banner ----
    def get_banner(self) -> bytes:
        if self.banner_done:
            return self.banner
        self.banner_done = True
        try:
            s = tcp_connect(self.ip, self.port, self.timeout)
            s.settimeout(min(2.0, self.timeout))
            self.banner = s.recv(2048)
            s.close()
        except Exception:
            self.banner = b""
        return self.banner

    # ---- HTTP 识别: 先 http 后 https ----
    def identify(self):
        if self.identify_done:
            return self.proto
        self.identify_done = True
        r = http_request(self.ip, self.port, "/", timeout=self.timeout)
        if r is not None:
            self.proto = "http"
            self.server_header = r.header("server")
            return self.proto
        r = http_request(self.ip, self.port, "/", timeout=self.timeout, https=True)
        if r is not None:
            self.proto = "https"
            self.server_header = r.header("server")
            return self.proto
        return None

    # ---- HTTP 请求(用识别出的协议) ----
    def http(self, path, **kw) -> Optional[Resp]:
        kw.setdefault("timeout", self.timeout)
        if self.proto is None:
            self.identify()
        if self.proto is None:
            return None
        return http_request(self.ip, self.port, path, https=(self.proto == "https"), **kw)

    def http_url(self, path="/") -> str:
        scheme = self.proto or "http"
        host = "[%s]" % self.ip if ":" in self.ip else self.ip
        return "%s://%s:%d%s" % (scheme, host, self.port, path)

    def http_json_200(self, path, **kw) -> Optional[Resp]:
        r = self.http(path, **kw)
        if r is not None and r.status == 200 and r.json() is not None:
            return r
        return None

    # ---- 原始 TCP ----
    def send(self, data, pre_read=False, read_timeout=3.0) -> bytes:
        _, resp = tcp_probe(self.ip, self.port, data,
                            timeout=self.timeout, read_timeout=read_timeout,
                            pre_read=pre_read)
        return resp

    def __repr__(self):
        return "%s:%d" % (self.ip, self.port)


@dataclass
class POC:
    key: str
    name: str
    category: str        # 分类: 数据库 / 缓存 / 中间件 / 容器编排 / 大数据 / 开发框架 / 监控运维 / AI组件 / 网络协议
    severity: str        # Critical / High / Medium / Low / Info
    ports: tuple
    kind: str = "path"   # path(HTTP路径级) / proto(协议级) / cred(默认口令)
    proto: str = "tcp"   # tcp / udp
    cve: str = ""
    desc: str = ""
    fix: str = ""
    banner_re: str = ""  # banner 命中此正则时, 即使端口不匹配也触发 proto POC
    always: bool = False # path POC 是否在 --fast 模式下也对任意 HTTP 端口执行
    default_only: bool = False # path POC 是否仅在默认端口执行(避免对非目标产品的全端口误报)
    fn: object = field(default=None, repr=False, compare=False)


POCS: List[POC] = []


def poc(key, name, category, severity, ports=(), kind="path", proto="tcp",
        cve="", desc="", fix="", banner_re="", always=False, default_only=False):
    def deco(fn):
        POCS.append(POC(key=key, name=name, category=category, severity=severity,
                        ports=tuple(ports), kind=kind, proto=proto, cve=cve,
                        desc=desc, fix=fix, banner_re=banner_re, always=always,
                        default_only=default_only,
                        fn=fn))
        return fn
    return deco


@dataclass
class Finding:
    target: Target
    poc: POC
    confidence: str      # Confirmed / Likely
    evidence: str
    url: str = ""

    @property
    def sev_rank(self):
        return (SEV_ORDER.get(self.poc.severity, 9),
                0 if self.confidence == "Confirmed" else 1)


# ==============================================================================
# 3. 协议级 POC (非 HTTP, 二进制/文本协议严格匹配)
# ==============================================================================

# ---------------------------- Redis ------------------------------------------
@poc("redis-unauth", "Redis 未授权访问", "缓存", "Critical", [6379],
     kind="proto", banner_re=r"^-ERR|^\*\d|\$\d",
     desc="Redis 无密码或弱监听暴露, 可任意读写数据、写 crontab/SSH 公钥, "
          "4.x/5.x 可主从复制 RCE。等保/PCI 均判定为高危。",
     fix="redis.conf: requirepass 强口令 + bind 127.0.0.1/内网地址 + "
         "rename-command FLUSHALL/CONFIG/SHUTDOWN + 网络 ACL 收口。")
def poc_redis(t: Target) -> Optional[Finding]:
    try:
        s = tcp_connect(t.ip, t.port, t.timeout)
        s.settimeout(t.timeout)
        s.sendall(b"PING\r\n")
        r1 = s.recv(128)
        s.sendall(b"INFO server\r\n")
        s.settimeout(2.0)
        r2 = b""
        try:
            r2 = s.recv(4096)
        except Exception:
            pass
        s.close()
    except Exception:
        return None
    if r1.startswith(b"+PONG"):
        ver = ""
        m = re.search(rb"redis_version:([0-9.]+)", r2)
        if m:
            ver = " version=%s" % m.group(1).decode()
        return Finding(t, _find_poc("redis-unauth"), "Confirmed",
                       "PING -> +PONG 无需认证%s; INFO 可读服务信息" % ver)
    if r1.startswith(b"-NOAUTH") or r1.startswith(b"-ERR"):
        return None        # 有认证, 安全
    return None


# ---------------------------- MongoDB ----------------------------------------
def _bson_doc(pairs):
    body = b""
    for k, v in pairs:
        body += b"\x10" + k.encode() + b"\x00" + struct.pack("<i", v)
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _mongo_opmsg(doc):
    body = struct.pack("<I", 0) + b"\x00" + doc
    return struct.pack("<iiii", 16 + len(body), 1, 0, 2013) + body


def _mongo_opquery(doc):
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + \
        struct.pack("<ii", 0, -1) + doc
    return struct.pack("<iiii", 16 + len(body), 2, 0, 2004) + body


@poc("mongodb-unauth", "MongoDB 未授权访问", "数据库", "Critical", [27017, 27018, 27019],
     kind="proto",
     desc="MongoDB 未启用 --auth, 可任意读写库表, 敏感数据(PII)直接泄露。",
     fix="mongod 启动加 --auth 并创建管理员账户; bind 内网 IP; 安全组仅放行应用服务器; "
         "开启 TLS。")
def poc_mongodb(t: Target) -> Optional[Finding]:
    doc = _bson_doc([("listDatabases", 1)])
    probes = [_mongo_opmsg(doc), _mongo_opquery(doc)]
    for data in probes:
        resp = t.send(data, read_timeout=3.0)
        if not resp:
            continue
        low = resp.lower()
        if b"databases" in low and b"totalSize".lower() in low:
            return Finding(t, _find_poc("mongodb-unauth"), "Confirmed",
                           "listDatabases 无需认证返回数据库列表")
        if b"not authorized" in low or b"requires authentication" in low or \
                b"unauthorized" in low or b"auth failed" in low:
            return None
    return None


# ---------------------------- Memcached --------------------------------------
@poc("memcached-unauth", "Memcached 未授权访问", "缓存", "High", [11211],
     kind="proto",
     desc="Memcached 无 SASL 认证, 可读写缓存数据; UDP 版可被用作 DRDoS 放大源。",
     fix="启用 SASL(-S) 认证; bind 内网; 关闭 UDP(-U 0); 云上用安全组收口 11211。")
def poc_memcached(t: Target) -> Optional[Finding]:
    resp = t.send(b"stats\r\n", read_timeout=3.0)
    if resp.startswith(b"STAT "):
        ver = ""
        m = re.search(rb"STAT version ([0-9.]+)", resp)
        if m:
            ver = " version=%s" % m.group(1).decode()
        return Finding(t, _find_poc("memcached-unauth"), "Confirmed",
                       "stats 命令无需认证返回统计信息%s" % ver)
    return None


# ---------------------------- Rsync -------------------------------------------
@poc("rsync-unauth", "Rsync 未授权访问(模块信息泄露/可读写)", "中间件", "High", [873],
     kind="proto", banner_re=r"@RSYNCD:",
     desc="Rsync daemon 模块无 secrets 认证, 可匿名列出/同步模块目录, "
          "可读源码与配置、写 webshell/计划任务。",
     fix="/etc/rsyncd.conf 每个模块配置 auth users + secrets file, 权限 600; "
         "hosts allow 白名单; 非必要改为 ssh 隧道同步。")
def poc_rsync(t: Target) -> Optional[Finding]:
    try:
        s = tcp_connect(t.ip, t.port, t.timeout)
        s.settimeout(t.timeout)
        banner = s.recv(128)
        if not banner.startswith(b"@RSYNCD:"):
            s.close()
            return None
        s.sendall(b"@RSYNCD: 30.0\n")
        s.settimeout(3.0)
        data = b""
        try:
            while len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        s.close()
    except Exception:
        return None
    modules = [ln.strip() for ln in data.decode("utf-8", "replace").splitlines()
               if ln.strip() and not ln.startswith("@RSYNCD")]
    if modules:
        return Finding(t, _find_poc("rsync-unauth"), "Confirmed",
                       "匿名列出模块: " + ", ".join(m.split("\t")[0] for m in modules[:5]))
    return None


# ---------------------------- ZooKeeper ---------------------------------------
@poc("zookeeper-unauth", "ZooKeeper 未授权访问", "中间件", "High", [2181, 2182],
     kind="proto",
     desc="ZooKeeper 无 ACL, 匿名可执行 envi/srvr 四字命令泄露环境变量, "
          "并可通过 kill 干掉会话/节点, 影响 Kafka/HBase/Dubbo 等依赖服务。",
     fix="zoo.cfg 配置 aclProvider 或 admin.serverPort 白名单; 4lw 白名单收紧; "
         "网络 ACL 仅放行集群与应用网段; 敏感 znode 设置 digest ACL。")
def poc_zookeeper(t: Target) -> Optional[Finding]:
    resp = t.send(b"srvr\n", read_timeout=2.5)
    if b"Zookeeper version" in resp or b"zk_version" in resp:
        ver = ""
        m = re.search(rb"Zookeeper version: ([0-9.]+)", resp)
        if m:
            ver = " version=%s" % m.group(1).decode()
        return Finding(t, _find_poc("zookeeper-unauth"), "Confirmed",
                       "四字命令 srvr 无需认证可用%s" % ver)
    resp2 = t.send(b"mntr\n", read_timeout=2.5)
    if b"zk_server_state" in resp2:
        return Finding(t, _find_poc("zookeeper-unauth"), "Confirmed",
                       "四字命令 mntr 无需认证可用")
    return None


# ---------------------------- FTP 匿名登录 ------------------------------------
@poc("ftp-anon", "FTP 匿名登录", "网络协议", "Medium", [21],
     kind="proto", banner_re=r"^220 ",
     desc="FTP 允许匿名(anonymous)登录, 若目录可写则可上传 webshell/钓鱼文件。",
     fix="vsftpd: anonymous_enable=NO; 读写目录分离; 改用 SFTP/FTPS。")
def poc_ftp_anon(t: Target) -> Optional[Finding]:
    try:
        s = tcp_connect(t.ip, t.port, t.timeout)
        s.settimeout(t.timeout)
        banner = s.recv(256)
        if not banner.startswith(b"220"):
            s.close()
            return None
        s.sendall(b"USER anonymous\r\n")
        r1 = s.recv(256)
        s.sendall(b"PASS anonymous@\r\n")
        r2 = s.recv(256)
        s.sendall(b"QUIT\r\n")
        s.close()
    except Exception:
        return None
    if r2.startswith(b"230"):
        return Finding(t, _find_poc("ftp-anon"), "Confirmed",
                       "USER anonymous/PASS anonymous -> 230 登录成功 (%s)" %
                       b2s(banner, 60))
    return None


# ---------------------------- VNC 无认证 ---------------------------------------
@poc("vnc-noauth", "VNC 无认证访问", "网络协议", "High", [5900, 5901, 5902],
     kind="proto", banner_re=r"^RFB ",
     desc="VNC 服务端安全类型含 None, 无密码即可控制桌面。",
     fix="设置 VNC 密码(vncpasswd); 启用 TLS/加密类型; bind 白名单地址。")
def poc_vnc(t: Target) -> Optional[Finding]:
    try:
        s = tcp_connect(t.ip, t.port, t.timeout)
        s.settimeout(t.timeout)
        banner = s.recv(64)
        if not banner.startswith(b"RFB "):
            s.close()
            return None
        s.sendall(banner.strip() + b"\n")
        s.settimeout(3.0)
        data = s.recv(128)
        s.close()
    except Exception:
        return None
    if not data:
        return None
    if len(data) >= 1 and data[0] == 1 and len(data) > 1:
        types = list(data[1:1 + data[0]])
        if 1 in types:            # type 1 = None
            return Finding(t, _find_poc("vnc-noauth"), "Confirmed",
                           "RFB 安全类型协商含 None(无认证)")
    if len(data) == 4:
        sec = struct.unpack(">I", data)[0]
        if sec == 1:
            return Finding(t, _find_poc("vnc-noauth"), "Confirmed",
                           "RFB 3.3 安全类型=1(None)")
    return None


# ---------------------------- MySQL 空口令 root --------------------------------
@poc("mysql-empty-root", "MySQL root 空口令", "数据库", "Critical", [3306],
     kind="proto",
     desc="root 账户空密码, 任意连接即获 DBA 权限, 可 UDF 提权/写 webshell。",
     fix="ALTER USER 'root'@'%' IDENTIFIED BY '强口令'; 删除匿名账户; "
         "bind 内网; 不使用 root 远程连接。")
def poc_mysql_empty(t: Target) -> Optional[Finding]:
    try:
        s = tcp_connect(t.ip, t.port, t.timeout)
        s.settimeout(t.timeout)
        hdr = b""
        while len(hdr) < 4:
            chunk = s.recv(4 - len(hdr))
            if not chunk:
                raise IOError
            hdr += chunk
        plen = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
        payload = b""
        while len(payload) < plen:
            chunk = s.recv(plen - len(payload))
            if not chunk:
                raise IOError
            payload += chunk
        if payload[0] != 0x0a:
            s.close()
            return None
        end = payload.index(b"\x00", 1)
        version = payload[1:end].decode("utf-8", "replace")
        # 构造 HandshakeResponse41: root + 空密码(native)
        caps = 0x0200 | 0x8000 | 0x00080000 | 0x00000001 | 0x00200000
        p = struct.pack("<IIB23x", caps, 1 << 24, 33)
        p += b"root\x00\x00"                 # username + 空 auth response
        p += b"mysql_native_password\x00"
        out = struct.pack("<I", len(p))[0:3] + b"\x01" + p
        s.sendall(out)
        s.settimeout(3.0)
        rh = s.recv(5)
        if len(rh) >= 5:
            rlen = rh[0] | (rh[1] << 8) | (rh[2] << 16)
            rp = s.recv(max(rlen, 1))
            s.close()
            if rp and rp[0] == 0x00:
                return Finding(t, _find_poc("mysql-empty-root"), "Confirmed",
                               "root 空口令登录成功 (server %s)" % version)
    except Exception:
        return None
    return None


# ---------------------------- PostgreSQL trust 认证 ----------------------------
@poc("pgsql-trust", "PostgreSQL 信任认证(免密登录)", "数据库", "Critical", [5432],
     kind="proto",
     desc="pg_hba.conf 配置 trust, 免密直连数据库, superuser 权限可读写文件。",
     fix="pg_hba.conf 将 trust 改为 scram-sha-256/md5; bind 内网; 强口令。")
def poc_pgsql(t: Target) -> Optional[Finding]:
    params = b"user\x00postgres\x00database\x00postgres\x00\x00"
    msg = struct.pack(">i", 8 + len(params)) + b"\x00\x03\x00\x00" + params
    resp = t.send(msg, read_timeout=3.0)
    if resp and resp[:1] == b"R":
        auth_type = struct.unpack(">i", resp[5:9])[0] if len(resp) >= 9 else -1
        if auth_type == 0:
            return Finding(t, _find_poc("pgsql-trust"), "Confirmed",
                           "StartupMessage(user=postgres) -> AuthenticationOk, 免密可连")
        return None       # md5/scram 等需要认证
    return None


# ---------------------------- Dubbo Telnet -------------------------------------
@poc("dubbo-telnet", "Dubbo Telnet 未授权", "中间件", "High", [20880, 20881],
     kind="proto",
     desc="Dubbo QoS/telnet 端口无认证, 可 ls 列出服务与 invoke 调用任意方法。",
     fix="dubbo.protocol.qos.enable=false 或 qos.accept.foreign.ip=false; "
         "网络 ACL 收口; 升级到带鉴权的 QoS 版本。")
def poc_dubbo(t: Target) -> Optional[Finding]:
    resp = t.send(b"ls\r\n", read_timeout=3.0)
    if not resp:
        return None
    if re.search(rb"[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+){2,}", resp) and \
            b"command not found" not in resp.lower():
        return Finding(t, _find_poc("dubbo-telnet"), "Confirmed",
                       "telnet ls 无认证返回服务列表: " + b2s(resp, 120))
    return None


# ---------------------------- RMI / JRMP ---------------------------------------
@poc("rmi-jrmp", "RMI/JRMP 端口暴露(无传输层认证)", "中间件", "Medium", [1099, 1098],
     kind="proto",
     desc="Java RMI 注册端口可达, JRMP 无认证, 结合 JNDI 利用链/ysoserial 可 RCE。",
     fix="限制 bind 地址为内网; 使用 SSL + 客户端证书; 升级 JDK 修复反序列化 Gadget。")
def poc_rmi(t: Target) -> Optional[Finding]:
    resp = t.send(b"JRMI\x00\x02K", read_timeout=3.0)
    if resp[:1] == b"\x4e":    # JRMP ACK
        return Finding(t, _find_poc("rmi-jrmp"), "Likely",
                       "JRMP 握手 ACK(0x4e), RMI 服务可达且无传输层认证")
    return None


# ---------------------------- SNMP 默认团体名 (UDP) -----------------------------
def _ber_len(n):
    if n < 128:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _snmp_get(community, oid=b"\x2b\x06\x01\x02\x01\x01\x01\x00"):
    varbind = _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b""))
    pdu = _tlv(0xa0, _tlv(0x02, b"\x01\x00") + _tlv(0x02, b"\x01\x00") +
               _tlv(0x02, b"\x01\x00") + _tlv(0x30, varbind))
    return _tlv(0x30, _tlv(0x02, b"\x00") +
                _tlv(0x04, community.encode()) + pdu)


@poc("snmp-default", "SNMP 默认团体名 public", "网络协议", "High", [161],
     kind="proto", proto="udp",
     desc="SNMP 使用默认团体名 public, 可读取设备配置/接口/ARP 等信息。",
     fix="修改为 16 位以上随机团体名; 改用 SNMPv3; ACL 限制管理站 IP。")
def poc_snmp(ip, port, timeout):
    t = Target(ip, port, timeout)
    pkt = _snmp_get("public")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, port))
        data, _ = s.recvfrom(4096)
        s.close()
    except Exception:
        return None
    if data and b"public" in data and len(data) > len(pkt):
        return Finding(t, _find_poc("snmp-default"), "Confirmed",
                       "SNMPv1 GET community=public 获得响应")
    return None


# ==============================================================================
# 4. HTTP 路径级 POC (对每个识别为 HTTP/HTTPS 的端口执行)
#    每条 POC 均要求: 状态码 200 + 内容强特征
# ==============================================================================

# ---------------------------- Spring Boot Actuator ----------------------------
@poc("springboot-actuator", "Spring Boot Actuator 未授权访问", "开发框架", "Critical",
     [8080, 8081, 8082, 9090, 9001, 9002, 8090, 8443, 80, 443], always=True,
     desc="Actuator 端点匿名可读; env/heapdump 泄露数据库密码、密钥、内网拓扑, "
          "heapdump 可直接提取 Token; jolokia/gateway 路由可 RCE。",
     fix="management.endpoint 暴露仅 health; management.security.enabled=true; "
         "引入 spring-security 对 actuator 做 Basic/OAuth 认证; 网络层仅内网可达。")
def poc_actuator(t: Target) -> Optional[Finding]:
    for base in ("/actuator", "/management"):
        r = t.http_json_200(base)
        if r and isinstance(r.json(), dict) and "_links" in r.json():
            links = list(r.json()["_links"].keys())
            danger = [x for x in links if x in
                      ("env", "heapdump", "threaddump", "loggers", "mappings",
                       "configprops", "gateway", "jolokia", "beans", "trace",
                       "httptrace", "scheduledtasks")]
            if danger:
                return Finding(t, _find_poc("springboot-actuator"), "Confirmed",
                               "%s 匿名可访问且暴露敏感端点: %s" % (base, ",".join(danger)),
                               url=t.http_url(base))
    # 旧版 Spring Boot 1.x 无 /actuator 前缀
    r = t.http_json_200("/env")
    if r and isinstance(r.json(), dict) and "profiles" in r.json():
        return Finding(t, _find_poc("springboot-actuator"), "Confirmed",
                       "/env(SB 1.x) 匿名返回环境变量与配置属性", url=t.http_url("/env"))
    return None


@poc("springboot-heapdump", "Spring Boot heapdump 内存转储泄露", "开发框架", "Critical",
     [8080, 8081, 8082, 9090, 8090, 8443], always=True,
     desc="可下载 JVM 堆转储, 使用 heapdump_tool/JProfiler 可提取数据库凭据、"
          "Session、JWT 密钥等内存敏感数据。", 
     fix="关闭 heapdump 端点暴露; actuator 增加认证与内网限制。")
def poc_heapdump(t: Target) -> Optional[Finding]:
    for path in ("/actuator/heapdump", "/heapdump", "/actuator/dump", "/dump"):
        try:
            s = tcp_connect(t.ip, t.port, t.timeout)
            if t.proto == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s)
            req = "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: ua\r\n" \
                  "Connection: close\r\n\r\n" % (path, t.ip, t.port)
            s.sendall(req.encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = s.recv(4096)
                if not chunk:
                    break
                head += chunk
                if len(head) > 65536:
                    break
            body_start = head.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in head else b""
            s.close()
            first = head.split(b"\r\n")[0]
            if b" 200 " in first and (b"JAVA PROFILE" in body_start[:32] or
                                      body_start[:4] == b"\x00\x00\x00\x04"):
                return Finding(t, _find_poc("springboot-heapdump"), "Confirmed",
                               "%s 匿名返回 HPROF 堆转储" % path, url=t.http_url(path))
        except Exception:
            continue
    return None


@poc("spring-cloud-gateway-routes", "Spring Cloud Gateway 路由信息泄露(CVE-2022-22947 风险面)",
     "开发框架", "Critical", [8080, 8081, 9000, 8443], always=True,
     cve="CVE-2022-22947",
     desc="gateway routes 端点匿名可读; 若 actuator POST 可达即被 CVE-2022-22947 "
          "SpEL 注入 RCE(本工具只做只读验证)。",
     fix="禁用 gateway actuator 端点或加认证; 升级 Spring Cloud Gateway >= 3.1.1/3.0.7。")
def poc_scg(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/actuator/gateway/routes")
    if r and isinstance(r.json(), list) and r.json():
        return Finding(t, _find_poc("spring-cloud-gateway-routes"), "Confirmed",
                      "匿名读取 %d 条网关路由(含 uri/filters)" % len(r.json()),
                      url=t.http_url("/actuator/gateway/routes"))
    return None


# ---------------------------- Nacos --------------------------------------------
NACOS_HDRS = {"User-Agent": "Nacos-Server",
              "serverIdentity": "security",
              "Accept": "application/json"}


@poc("nacos-unauth", "Nacos 未授权访问(UA/serverIdentity 绕过)", "中间件", "Critical",
     [8848], always=True, cve="CVE-2021-29441",
     desc="通过 User-Agent: Nacos-Server 或 serverIdentity 头绕过鉴权, "
          "可读取用户列表/配置中的 DB 密码, 新增用户接管控制台。",
     fix="nacos.core.auth.enabled=true; 更换默认 serverIdentity 值; "
         "自定义 nacos.core.auth.server.identity.key/value; 升级 >= 1.4.1。")
def poc_nacos(t: Target) -> Optional[Finding]:
    r = t.http("/nacos/v1/auth/users?pageNo=1&pageSize=2", headers=NACOS_HDRS)
    if r is not None and r.status == 200 and r.json() is not None:
        j = r.json()
        if isinstance(j, dict) and ("totalCount" in j or "pageItems" in j):
            return Finding(t, _find_poc("nacos-unauth"), "Confirmed",
                           "UA 绕过鉴权读取用户列表: " + b2s(r.body, 120),
                           url=t.http_url("/nacos/v1/auth/users"))
    r = t.http_json_200("/nacos/v1/console/server/state", headers=NACOS_HDRS)
    if r and isinstance(r.json(), dict) and (
            "standalone_mode" in r.json() or "nacos" in str(r.json()).lower()):
        return Finding(t, _find_poc("nacos-unauth"), "Likely",
                       "server/state 匿名可读: " + b2s(r.body, 100),
                       url=t.http_url("/nacos/v1/console/server/state"))
    return None


@poc("nacos-default-cred", "Nacos 默认口令 nacos/nacos", "中间件", "High",
     [8848], kind="cred", always=True,
     desc="控制台使用默认口令, 登录后可读写全部配置(含数据库凭据)。",
     fix="修改默认口令; auth.enabled=true; 关闭匿名控制台。")
def poc_nacos_cred(t: Target) -> Optional[Finding]:
    body = "username=nacos&password=nacos"
    r = t.http("/nacos/v1/auth/login", method="POST",
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               body=body)
    if r is not None and r.status == 200 and r.json() and \
            ("accessToken" in r.json() or "data" in r.json()):
        return Finding(t, _find_poc("nacos-default-cred"), "Confirmed",
                       "nacos/nacos 默认口令登录成功获取 accessToken",
                       url=t.http_url("/nacos/v1/auth/login"))
    return None


# ---------------------------- Druid ---------------------------------------------
@poc("druid-unauth", "Alibaba Druid 监控未授权访问", "开发框架", "Medium",
     [8080, 8081, 8090, 80, 443, 7001], always=True,
     desc="Druid Monitor 无登录直接访问, 泄露 SQL/URI/Session/数据源密码等监控数据。",
     fix="WebStatFilter/StatViewServlet 配置 loginUsername/loginPassword; "
         "或 allow 127.0.0.1; 不对外暴露监控页。")
def poc_druid(t: Target) -> Optional[Finding]:
    for path in ("/druid/index.html", "/druid/sql.html", "/druid/datasource.html"):
        r = t.http(path)
        if r is not None and r.status == 200 and r.has("druid") and \
                r.has("stat") and not r.has("login"):
            return Finding(t, _find_poc("druid-unauth"), "Confirmed",
                          "%s 无需登录返回监控页" % path, url=t.http_url(path))
    return None


# ---------------------------- Swagger --------------------------------------------
@poc("swagger-unauth", "Swagger/OpenAPI 接口文档泄露", "开发框架", "Medium",
     [80, 443, 8080, 8081, 8082, 8090, 9000, 9090, 7001], always=True,
     desc="接口文档匿名可读, 泄露全部 API 路径与参数, 大幅降低攻击成本。",
     fix="生产环境关闭 swagger/knife4j; 或加 Basic 认证与内网限制。")
def poc_swagger(t: Target) -> Optional[Finding]:
    for path in ("/v2/api-docs", "/v3/api-docs", "/swagger-resources",
                 "/api-docs", "/api/swagger.json"):
        r = t.http_json_200(path)
        if not r:
            continue
        j = r.json()
        if isinstance(j, dict) and (j.get("swagger") == "2.0" or
                                    str(j.get("openapi", "")).startswith("3.")):
            return Finding(t, _find_poc("swagger-unauth"), "Confirmed",
                           "%s 匿名返回 API 文档" % path, url=t.http_url(path))
        if isinstance(j, list) and j and isinstance(j[0], dict) and \
                ("location" in j[0] or "name" in j[0]):
            return Finding(t, _find_poc("swagger-unauth"), "Confirmed",
                          "%s 匿名返回 swagger 资源列表" % path, url=t.http_url(path))
    for path in ("/swagger-ui.html", "/doc.html", "/swagger-ui/index.html"):
        r = t.http(path)
        if r is not None and r.status == 200 and \
                (r.has("swagger") or r.has("knife4j")) and not r.has("login"):
            return Finding(t, _find_poc("swagger-unauth"), "Likely",
                           "%s 匿名返回接口文档页面" % path, url=t.http_url(path))
    return None


# ---------------------------- Docker / 容器 ---------------------------------------
@poc("docker-api-unauth", "Docker Remote API 未授权访问", "容器编排", "Critical",
     [2375, 2376], always=True,
     desc="2375 端口匿名可管理容器: 创建特权容器挂载宿主机根目录即逃逸 getshell。",
     fix="关闭 -H tcp://0.0.0.0:2375 或改用 unix socket; 启用 TLS 双向认证; "
         "安全组/ACL 收口。")
def poc_docker(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/version")
    if r:
        j = r.json()
        if isinstance(j, dict) and "ApiVersion" in j and "Version" in j:
            r2 = t.http_json_200("/containers/json?all=1")
            extra = ""
            if r2 and isinstance(r2.json(), list):
                extra = "; 匿名列出 %d 个容器" % len(r2.json())
            return Finding(t, _find_poc("docker-api-unauth"), "Confirmed",
                           "/version 匿名返回 Docker 信息" + extra,
                           url=t.http_url("/version"))
    return None


@poc("docker-registry-unauth", "Docker Registry 未授权(镜像可拉取)", "容器编排", "High",
     [5000, 5001],
     desc="私有镜像仓库匿名可列出/拉取镜像, 镜像内常含源码与凭据。",
     fix="Registry 配置 htpasswd 认证或 TLS+basic auth; 仅内网可达。")
def poc_docker_registry(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/v2/_catalog")
    if r and isinstance(r.json(), dict) and "repositories" in r.json():
        repos = r.json()["repositories"]
        return Finding(t, _find_poc("docker-registry-unauth"), "Confirmed",
                       "匿名列出镜像仓库: %s" % ",".join(repos[:5]),
                       url=t.http_url("/v2/_catalog"))
    return None


@poc("k8s-api-anon", "Kubernetes API Server 匿名访问", "容器编排", "Critical",
     [6443, 8443, 8080, 10255, 10250], always=True,
     desc="API Server 匿名鉴权(--anonymous-auth=true 且 RBAC 放开), "
          "可 list secrets/pods, 进一步创建恶意 Pod 接管集群。",
     fix="--anonymous-auth=false; RBAC 收紧 system:anonymous; apiserver 仅内网可达。")
def poc_k8s(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/version")
    if r and isinstance(r.json(), dict) and "gitVersion" in r.json():
        r2 = t.http("/api/v1/namespaces")
        extra = ""
        if r2 is not None and r2.status == 200:
            extra = "; /api/v1/namespaces 匿名可读"
        return Finding(t, _find_poc("k8s-api-anon"), "Confirmed",
                       "/version 匿名返回 %s%s" %
                       (r.json().get("gitVersion", ""), extra),
                       url=t.http_url("/version"))
    return None


@poc("kubelet-read-only", "Kubelet 10250/10255 未授权", "容器编排", "Critical",
     [10250, 10255, 4194],
     desc="kubelet /pods、/runningpods 匿名可读, 10250 exec 接口可执行容器命令。",
     fix="--anonymous-auth=false + webhook 授权模式; 10255 只读端口关闭; "
         "安全组仅放行 master 网段。")
def poc_kubelet(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/pods")
    if r and isinstance(r.json(), dict) and r.json().get("kind") == "PodList":
        n = len(r.json().get("items", []))
        return Finding(t, _find_poc("kubelet-read-only"), "Confirmed",
                       "/pods 匿名返回 PodList(%d pods)" % n,
                       url=t.http_url("/pods"))
    return None


@poc("etcd-unauth", "etcd 未授权访问", "容器编排", "Critical", [2379, 2380],
     desc="etcd v3 API 无认证, 可读写集群全部 KV, 含 K8s secrets、服务配置。",
     fix="开启 --client-cert-auth TLS 双向认证; 限制 client-urls 为内网/localhost。")
def poc_etcd(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/version")
    if r and isinstance(r.json(), dict) and "etcdserver" in r.json():
        r2 = t.http_json_200("/v2/keys/?recursive=true")
        r3 = t.http_json_200("/health")
        extra = ""
        if r2:
            extra = "; /v2/keys 递归读取成功"
        elif r3 and isinstance(r3.json(), dict) and "health" in r3.json():
            extra = "; /health 可读"
        return Finding(t, _find_poc("etcd-unauth"), "Confirmed",
                       "/version 匿名返回 etcdserver=%s%s" %
                       (r.json()["etcdserver"], extra), url=t.http_url("/version"))
    return None


@poc("consul-unauth", "Consul 未授权访问", "容器编排", "High", [8500],
     desc="Consul agent API 无 ACL, 可读取 KV(常存配置/密钥)并注册恶意服务。",
     fix="启用 ACL default policy=deny; config/agent 绑定内网。")
def poc_consul(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/v1/agent/self")
    if r and isinstance(r.json(), dict) and "Config" in r.json():
        r2 = t.http_json_200("/v1/kv/?recurse=true")
        extra = "; KV 递归读取成功" if r2 else ""
        return Finding(t, _find_poc("consul-unauth"), "Confirmed",
                       "/v1/agent/self 匿名可读" + extra,
                       url=t.http_url("/v1/agent/self"))
    return None


@poc("nomad-unauth", "HashiCorp Nomad 未授权", "容器编排", "High", [4646],
     desc="Nomad agent API 匿名可读, 结合 exec 接口可运行任务。",
     fix="启用 ACL; bind 内网地址。")
def poc_nomad(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/v1/agent/self")
    if r and isinstance(r.json(), dict) and "config" in r.json():
        return Finding(t, _find_poc("nomad-unauth"), "Confirmed",
                       "/v1/agent/self 匿名可读", url=t.http_url("/v1/agent/self"))
    return None


@poc("vault-unauth", "HashiCorp Vault 未授权泄露", "容器编排", "Medium", [8200],
     desc="sys 接口匿名可读, 泄露挂载点/密封状态等信息。",
     fix="生产启用 TLS + token 认证; 8200 仅内网可达。")
def poc_vault(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/v1/sys/health")
    if r and isinstance(r.json(), dict) and "initialized" in r.json():
        r2 = t.http_json_200("/v1/sys/mounts")
        extra = "; /v1/sys/mounts 匿名可读" if r2 else ""
        return Finding(t, _find_poc("vault-unauth"), "Confirmed",
                       "/v1/sys/health 匿名可读" + extra,
                       url=t.http_url("/v1/sys/health"))
    return None


@poc("kubernetes-dashboard", "Kubernetes Dashboard 暴露", "容器编排", "High",
     [30000, 8443, 9090, 30009],
     desc="Dashboard 登录页对外暴露(skip/anon 模式则直接接管集群)。",
     fix="Dashboard 增加 token 登录; 关闭 --enable-skip-login; apiserver 收口。")
def poc_k8s_dashboard(t: Target) -> Optional[Finding]:
    r = t.http("/")
    if r is not None and r.status in (200, 401) and \
            r.has("kubernetes dashboard"):
        return Finding(t, _find_poc("kubernetes-dashboard"), "Likely",
                       "页面含 Kubernetes Dashboard 特征",
                       url=t.http_url("/"))
    return None


# ---------------------------- 大数据 -----------------------------------------------
@poc("hadoop-yarn-unauth", "Hadoop YARN REST API 未授权", "大数据", "Critical",
     [8088, 8032, 8030],
     desc="ResourceManager REST 匿名可提交任务, 可直接 RCE 获取服务器权限。",
     fix="yarn-site.xml 开启 Kerberos; 安全组限制 8088 为管理网段。")
def poc_yarn(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/ws/v1/cluster/info")
    if r and isinstance(r.json(), dict) and (
            "resourceManagerVersion" in r.json() or
            "hadoopVersion" in r.json()):
        return Finding(t, _find_poc("hadoop-yarn-unauth"), "Confirmed",
                       "cluster/info 匿名可读: RM=%s" %
                       r.json().get("resourceManagerVersion", ""),
                       url=t.http_url("/ws/v1/cluster/info"))
    return None


@poc("hdfs-namenode-unauth", "HDFS NameNode Web 未授权", "大数据", "High",
     [50070, 50075, 9870, 9864],
     desc="NameNode/Datanode Web UI 匿名可浏览目录, webhdfs 可读写文件。",
     fix="开启 Kerberos + HTTP SPNEGO; Web 端口仅内网可达。")
def poc_hdfs(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo")
    if r and isinstance(r.json(), dict) and "beans" in r.json():
        return Finding(t, _find_poc("hdfs-namenode-unauth"), "Confirmed",
                       "NameNode jmx 匿名可读", url=t.http_url("/jmx"))
    r2 = t.http_json_200("/webhdfs/v1/?op=LISTSTATUS")
    if r2 and isinstance(r2.json(), dict) and "FileStatuses" in r2.json():
        return Finding(t, _find_poc("hdfs-namenode-unauth"), "Confirmed",
                       "webhdfs LISTSTATUS 匿名可读",
                       url=t.http_url("/webhdfs/v1/?op=LISTSTATUS"))
    return None


@poc("spark-unauth", "Apache Spark Master/UI 未授权", "大数据", "High",
     [8080, 7077, 6066, 4040, 8081],
     desc="Spark Master REST(6066) 匿名可提交 jar 任务 RCE; Web UI 泄露作业与环境信息。",
     fix="spark.acls.enable=true; REST 提交端口仅管理网段可达。")
def poc_spark(t: Target) -> Optional[Finding]:
    r = t.http("/")
    if r is not None and r.status == 200 and \
            (r.has("spark master at") or r.has("sparkui")):
        return Finding(t, _find_poc("spark-unauth"), "Confirmed",
                       "Spark Master/UI 页面匿名可访问", url=t.http_url("/"))
    r2 = t.http_json_200("/api/v1/applications")
    if r2 and isinstance(r2.json(), list):
        return Finding(t, _find_poc("spark-unauth"), "Confirmed",
                       "/api/v1/applications 匿名可读",
                       url=t.http_url("/api/v1/applications"))
    return None


@poc("flink-unauth", "Apache Flink REST 未授权", "大数据", "Critical",
     [8081, 8082, 9092],
     desc="Flink REST 匿名可上传/运行 jar 任务, 直接 RCE。",
     fix="flink-conf 配置 security.rest.auth; 或 REST 端口仅内网可达。")
def poc_flink(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/jars")
    if r and isinstance(r.json(), dict) and "address" in r.json():
        return Finding(t, _find_poc("flink-unauth"), "Confirmed",
                       "/jars 匿名可列出与上传作业 jar", url=t.http_url("/jars"))
    r2 = t.http_json_200("/jobs/overview")
    if r2 and isinstance(r2.json(), dict) and "jobs" in r2.json():
        return Finding(t, _find_poc("flink-unauth"), "Confirmed",
                       "/jobs/overview 匿名可读", url=t.http_url("/jobs/overview"))
    return None


@poc("hbase-unauth", "HBase Master Web 未授权", "大数据", "Medium", [16010, 16030],
     desc="HBase Master UI 匿名可读, 泄露表结构与 region 信息。",
     fix="hbase.security.authentication=kerberos; Web 端口收口内网。")
def poc_hbase(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/jmx?qry=Hadoop:service=HBase,name=Master,service=HBase")
    if r and isinstance(r.json(), dict) and "beans" in r.json():
        return Finding(t, _find_poc("hbase-unauth"), "Confirmed",
                       "HBase Master jmx 匿名可读", url=t.http_url("/jmx"))
    return None


@poc("clickhouse-unauth", "ClickHouse HTTP 未授权", "数据库", "Critical", [8123, 8443],
     desc="HTTP 接口无密码即可执行 SQL, 可读取系统表与 UDF RCE。",
     fix="users.xml 设置 password; listen 只绑内网; default 用户禁用远程。")
def poc_clickhouse(t: Target) -> Optional[Finding]:
    r = t.http("/?query=SELECT%20version()")
    if r is not None and r.status == 200 and re.match(r"^\d+\.\d+", r.text(64).strip()):
        return Finding(t, _find_poc("clickhouse-unauth"), "Confirmed",
                       "匿名执行 SELECT version() => %s" % r.text(32).strip(),
                       url=t.http_url("/?query=SELECT%20version()"))
    return None


@poc("doris-http-unauth", "Doris/StarRocks HTTP API 未授权", "数据库", "High",
     [8030, 8040],
     desc="FE/BE HTTP 端口匿名可读, 泄露集群状态与数据。",
     fix="配置 FE http 认证; 端口仅内网可达。")
def poc_doris(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/show_config")
    if r and isinstance(r.json(), list):
        return Finding(t, _find_poc("doris-http-unauth"), "Confirmed",
                       "/api/show_config 匿名返回配置", url=t.http_url("/api/show_config"))
    return None


# ---------------------------- 消息队列 ----------------------------------------------
@poc("activemq-unauth", "ActiveMQ Web Console 未授权", "中间件", "High", [8161],
     desc="Web Console 无认证(或默认口令 admin/admin), 可 PUT 文件配合 Fileserver RCE。",
     fix="jetty.xml securityConstraint authenticate=true; 修改默认口令; 收口内网。")
def poc_activemq(t: Target) -> Optional[Finding]:
    r = t.http("/admin/")
    if r is not None and r.status == 200 and r.has("activemq"):
        return Finding(t, _find_poc("activemq-unauth"), "Confirmed",
                       "/admin/ 匿名返回 ActiveMQ 控制台", url=t.http_url("/admin/"))
    return None


@poc("rabbitmq-default-cred", "RabbitMQ guest/guest 默认口令", "中间件", "High",
     [15672], kind="cred",
     desc="guest 账户默认仅允许本机登录, 暴露外网且未删除即被远程登录管理队列与消息。",
     fix="删除 guest 或限定 loopback_users; 使用自定义强口令账户。")
def poc_rabbitmq(t: Target) -> Optional[Finding]:
    r = t.http("/api/overview", auth=("guest", "guest"))
    if r is not None and r.status == 200 and r.json() and \
            "rabbitmq_version" in r.json():
        return Finding(t, _find_poc("rabbitmq-default-cred"), "Confirmed",
                      "guest/guest 登录 /api/overview 成功 (RabbitMQ %s)" %
                      r.json()["rabbitmq_version"], url=t.http_url("/api/overview"))
    return None


@poc("rocketmq-dashboard", "RocketMQ Dashboard/Console 未授权", "中间件", "High",
     [8080, 8180, 9876],
     desc="rocketmq-console 无认证, 可查看与更新消息/主题/消费者配置。",
     fix="console 增加 ACL 与登录; 端口收口内网。")
def poc_rocketmq(t: Target) -> Optional[Finding]:
    r = t.http("/topic/query.topic.list?pageNo=1&pageSize=10")
    if r is None:
        r = t.http("/topic/query.topic.list?topicKey=&pageNo=1&pageSize=10")
    if r is not None and r.status == 200 and r.json() and \
            isinstance(r.json(), dict) and "data" in r.json():
        return Finding(t, _find_poc("rocketmq-dashboard"), "Confirmed",
                       "topic 列表接口匿名可读", url=t.http_url("/"))
    r2 = t.http("/")
    if r2 is not None and r2.status == 200 and r2.has("rocketmq"):
        return Finding(t, _find_poc("rocketmq-dashboard"), "Likely",
                       "页面含 RocketMQ Dashboard 特征", url=t.http_url("/"))
    return None


@poc("kafka-manager-unauth", "Kafka Manager/CMAK 未授权", "中间件", "Medium",
     [9000, 9001, 2182],
     desc="集群管理界面无认证, 泄露 topic/broker/消费者组信息。",
     fix="增加认证反向代理; 端口收口内网。")
def poc_kafka_mgr(t: Target) -> Optional[Finding]:
    r = t.http("/api/clusterSummary")
    if r is None:
        r = t.http("/clusters")
    if r is not None and r.status == 200 and (r.has("kafka") or r.has("broker")):
        return Finding(t, _find_poc("kafka-manager-unauth"), "Likely",
                       "页面含 Kafka 集群管理特征", url=t.http_url("/"))
    return None


# ---------------------------- Java 中间件 --------------------------------------------
@poc("jenkins-unauth", "Jenkins 未授权访问(任意读取/脚本台)", "中间件", "Critical",
     [8080, 8081, 8888, 9090], always=True,
     desc="匿名可读 /api/json、/script 脚本控制台则可执行 Groovy 命令 RCE。",
     fix="启用登录与矩阵授权; 禁止匿名可读; /script 收紧; 不暴露公网。")
def poc_jenkins(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/json")
    if r and isinstance(r.json(), dict) and "jobs" in r.json():
        r2 = t.http("/script")
        extra = "; /script 脚本台匿名可达!" if (r2 is not None and r2.status == 200
                                              and r2.has("groovy")) else ""
        return Finding(t, _find_poc("jenkins-unauth"), "Confirmed",
                       "/api/json 匿名返回作业信息%s" % extra,
                       url=t.http_url("/api/json"))
    return None


@poc("jboss-jmx-console", "JBoss jmx-console 未授权", "中间件", "Critical",
     [8080, 8180, 9990],
     desc="jmx-console/web-console 无认证, 可部署 WAR 直接 RCE。",
     fix="jmx-console 配置 BASIC 认证; 升级 JBoss/WildFly; 收口内网。")
def poc_jboss(t: Target) -> Optional[Finding]:
    for path in ("/jmx-console/", "/web-console/"):
        r = t.http(path)
        if r is not None and r.status == 200 and \
                (r.has("jmx") and r.has("mbean")):
            return Finding(t, _find_poc("jboss-jmx-console"), "Confirmed",
                           "%s 匿名返回 JMX 控制台" % path, url=t.http_url(path))
    return None


@poc("weblogic-console-expose", "WebLogic 控制台暴露", "中间件", "Medium", [7001, 7002],
     desc="WebLogic Console/UDDI 对外暴露, 配合弱口令与已知 CVE(T3/IIOP 反序列化)利用。",
     fix="控制台限内网访问; 及时打 CPU 补丁; 禁用 T3/IIOP 或限制来源。",
     default_only=True)
def poc_weblogic(t: Target) -> Optional[Finding]:
    r = t.http("/console/login/LoginForm.jsp")
    if r is None or r.status != 200:
        return None
    body = (r.body or b"").decode("latin-1", "replace").lower()
    srv = (r.header("server") + " " + r.header("x-powered-by")).lower()
    # 强指纹: 必须匹配 WebLogic 专属特征, 避免其他 Java 应用/WAF 错误页误报
    #   - 登录页 body 同时含 weblogic + login/console 关键词
    #   - 或 Server / X-Powered-By 响应头含 WebLogic
    title_ok = ("weblogic" in body) and ("login" in body or "console" in body)
    header_ok = "weblogic" in srv
    if not (title_ok or header_ok):
        return None
    r2 = t.http("/uddiexplorer/")
    extra = "; UDDIExplorer 可达(历史 SSRF CVE-2014-4210)" if (r2 is not None and r2.status == 200) else ""
    return Finding(t, _find_poc("weblogic-console-expose"), "Likely",
                   "WebLogic 管理控制台对外暴露%s" % extra, url=t.http_url("/"))


@poc("tomcat-manager", "Tomcat Manager 未授权/暴露", "中间件", "High",
     [8080, 8081, 8181, 8443, 9009],
     desc="manager/html 匿名可访问可部署 WAR RCE; 返回 401 说明存在管理端(需弱口令配合)。",
     fix="删除 manager 应用或 conf/tomcat-users.xml 配置强口令; 收口内网。")
def poc_tomcat_manager(t: Target) -> Optional[Finding]:
    r = t.http("/manager/html")
    if r is None:
        return None
    if r.status == 200 and r.has("tomcat") and r.has("server status"):
        return Finding(t, _find_poc("tomcat-manager"), "Confirmed",
                       "manager/html 匿名可访问", url=t.http_url("/manager/html"))
    if r.status == 401:
        return Finding(t, _find_poc("tomcat-manager"), "Likely",
                       "manager/html 存在(401 需认证), 建议核查默认/弱口令",
                       url=t.http_url("/manager/html"))
    return None


@poc("eureka-unauth", "Spring Eureka 注册中心未授权", "中间件", "Medium",
     [8761, 8762],
     desc="注册中心匿名可读全部微服务实例(内网拓扑泄露), 高危操作接口可下线服务。",
     fix="eureka.security.basic.enabled=true; 配置账号密码; 收口内网。")
def poc_eureka(t: Target) -> Optional[Finding]:
    r = t.http("/eureka/apps")
    if r is not None and r.status == 200 and (r.has("<applications>") or
                                              r.has("eureka")):
        return Finding(t, _find_poc("eureka-unauth"), "Confirmed",
                       "/eureka/apps 匿名返回服务注册列表",
                       url=t.http_url("/eureka/apps"))
    return None


@poc("xxljob-executor-unauth", "XXL-JOB Executor REST 未授权", "中间件", "Critical",
     [9999, 9998],
     desc="executor REST /run 匿名可调度任务(内置 Groovy/shell 任务即 RCE); "
          "本工具仅做只读探测。",
     fix="executor 配置 xxl.job.accessToken 并与 admin 一致; 端口收口内网。")
def poc_xxljob_exec(t: Target) -> Optional[Finding]:
    r = t.http("/run")
    if r is not None and r.status == 405:
        return Finding(t, _find_poc("xxljob-executor-unauth"), "Likely",
                       "GET /run 返回 405, REST 执行接口存在(POST 未做写入验证)",
                       url=t.http_url("/run"))
    return None


@poc("xxljob-admin-default", "XXL-JOB Admin 默认口令 admin/123456", "中间件", "High",
     [8080, 8081], kind="cred",
     desc="调度中心默认口令, 登录后可创建执行 shell 的定时任务实现 RCE。",
     fix="修改默认口令; accessToken 非空; 收口内网。")
def poc_xxljob_admin(t: Target) -> Optional[Finding]:
    for base in ("/xxl-job-admin", ""):
        r = t.http(base + "/login", method="POST",
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   body="userName=admin&password=123456")
        if r is not None and r.status == 200 and r.json() and \
                r.json().get("code") == 200:
            return Finding(t, _find_poc("xxljob-admin-default"), "Confirmed",
                           "admin/123456 默认口令登录成功",
                           url=t.http_url(base + "/login"))
    return None


@poc("sentinel-dashboard-unauth", "Sentinel Dashboard 未授权", "中间件", "High",
     [8080, 8718, 8858],
     desc="Sentinel 控制台默认无登录, 可查看/修改任意服务限流规则并下线流量。",
     fix="接入 LDAP/自建登录鉴权; 收口内网。")
def poc_sentinel(t: Target) -> Optional[Finding]:
    r = t.http("/app/namespaces.json")
    if r is not None and r.status == 200 and isinstance(r.json(), list):
        r2 = t.http("/auth/currentuser.json")
        if r2 is not None and r2.status == 200 and (
                r2.json() in (None, {}, "") or
                (isinstance(r2.json(), dict) and not r2.json().get("username"))):
            return Finding(t, _find_poc("sentinel-dashboard-unauth"),
                           "Confirmed",
                           "currentuser.json 匿名返回空用户(未启用登录)",
                           url=t.http_url("/app/namespaces.json"))
    return None


@poc("dubbo-admin-unauth", "Dubbo Admin 未授权", "中间件", "High", [8080],
     desc="Dubbo Admin 无登录(或默认 root/root), 可查看并调用任意 Dubbo 服务。",
     fix="配置 admin 检查 root 账号; 收口内网。")
def poc_dubbo_admin(t: Target) -> Optional[Finding]:
    r = t.http("/")
    if r is not None and r.status == 200 and r.has("dubbo"):
        return Finding(t, _find_poc("dubbo-admin-unauth"), "Likely",
                       "页面含 Dubbo Admin 特征", url=t.http_url("/"))
    r2 = t.http_json_200("/api/dev/status")
    if r2 and isinstance(r2.json(), dict) and "success" in r2.json():
        return Finding(t, _find_poc("dubbo-admin-unauth"), "Likely",
                       "Dubbo Admin API 匿名可读", url=t.http_url("/api/dev/status"))
    return None


# ---------------------------- 监控运维 -------------------------------------------------
@poc("prometheus-unauth", "Prometheus 未授权访问", "监控运维", "Medium",
     [9090, 9091], always=True,
     desc="匿名可读取全局抓取配置(含目标系统的 exporter 与凭证信息)与指标。",
     fix="--web.config.file 启用 basic_auth; 或反代加认证; 收口内网。")
def poc_prometheus(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/v1/status/config")
    if r and isinstance(r.json(), dict) and r.json().get("status") == "success":
        data = r.json().get("data", {})
        if isinstance(data, dict) and data.get("yaml"):
            return Finding(t, _find_poc("prometheus-unauth"), "Confirmed",
                           "/api/v1/status/config 匿名返回完整抓取配置",
                           url=t.http_url("/api/v1/status/config"))
    return None


@poc("grafana-default-cred", "Grafana 默认口令 admin/admin", "监控运维", "High",
     [3000], kind="cred",
     desc="默认管理员口令, 可查看全部数据源凭据与仪表盘。",
     fix="首次登录强制修改默认口令; admin 密码复杂化。")
def poc_grafana(t: Target) -> Optional[Finding]:
    r = t.http("/api/org", auth=("admin", "admin"))
    if r is not None and r.status == 200 and isinstance(r.json(), dict) and \
            "id" in r.json():
        return Finding(t, _find_poc("grafana-default-cred"), "Confirmed",
                       "admin/admin 登录 /api/org 成功", url=t.http_url("/api/org"))
    return None


@poc("kibana-unauth", "Kibana 未授权访问", "监控运维", "High", [5601, 5602],
     desc="Kibana 匿名可访问, 可检索全部 ES 日志(常含订单/账号/Token)。",
     fix="xpack.security.enabled + 匿名角色禁用; 收口内网。")
def poc_kibana(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/status")
    if r and isinstance(r.json(), dict) and "version" in r.json():
        return Finding(t, _find_poc("kibana-unauth"), "Confirmed",
                       "/api/status 匿名返回版本信息",
                       url=t.http_url("/api/status"))
    return None


@poc("elasticsearch-unauth", "Elasticsearch 未授权访问", "数据库", "Critical",
     [9200, 9201, 9300], always=True,
     desc="匿名可读写全部索引数据与脚本, 利用 script RCE。",
     fix="elasticsearch.yml: xpack.security.enabled=true; 配置 TLS 与认证; 收口内网。")
def poc_es(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/")
    if r and isinstance(r.json(), dict) and "cluster_name" in r.json():
        r2 = t.http_json_200("/_cat/indices")
        extra = "; _cat/indices 匿名可读" if r2 else ""
        return Finding(t, _find_poc("elasticsearch-unauth"), "Confirmed",
                       "匿名读取集群信息 cluster_name=%s%s" %
                       (r.json().get("cluster_name"), extra),
                       url=t.http_url("/"))
    return None


@poc("couchdb-unauth", "CouchDB 未授权访问", "数据库", "High", [5984, 6984],
     desc="匿名可列出/读写全部数据库, 历史版本存在配置 RCE(CVE-2017-12636)。",
     fix="local.ini [admins] 配置管理员; require_valid_user=true; 绑定内网。")
def poc_couchdb(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/_all_dbs")
    if r and isinstance(r.json(), list):
        return Finding(t, _find_poc("couchdb-unauth"), "Confirmed",
                       "/_all_dbs 匿名返回 %d 个数据库" % len(r.json()),
                       url=t.http_url("/_all_dbs"))
    return None


@poc("influxdb-unauth", "InfluxDB 未授权访问", "数据库", "High", [8086],
     desc="匿名可 SHOW DATABASES 并查询时序数据。",
     fix="配置 http auth; bind 内网。")
def poc_influxdb(t: Target) -> Optional[Finding]:
    r = t.http("/query?q=SHOW%20DATABASES")
    if r is not None and r.status == 200 and r.json() and \
            isinstance(r.json(), dict) and ("results" in r.json() or
                                             "series" in r.json()):
        return Finding(t, _find_poc("influxdb-unauth"), "Confirmed",
                       "匿名执行 SHOW DATABASES 成功",
                       url=t.http_url("/query?q=SHOW%20DATABASES"))
    return None


@poc("tdengine-default-cred", "TDengine 默认口令 root/taosdata", "数据库", "High",
     [6041], kind="cred",
     desc="REST 接口使用默认口令, 可读写全部时序数据。",
     fix="ALTER USER root PASS '强口令'; REST 仅内网。")
def poc_tdengine(t: Target) -> Optional[Finding]:
    r = t.http("/rest/login/root/taosdata", method="POST")
    if r is not None and r.status == 200 and r.json() and \
            r.json().get("code") == 0:
        return Finding(t, _find_poc("tdengine-default-cred"), "Confirmed",
                       "root/taosdata 默认口令登录成功",
                       url=t.http_url("/rest/login/root/taosdata"))
    return None


@poc("neo4j-unauth", "Neo4j HTTP 未授权", "数据库", "High", [7474, 7473],
     desc="HTTP API 匿名可执行 Cypher 查询读取图数据。",
     fix="dbms.security.auth_enabled=true; 收口内网。")
def poc_neo4j(t: Target) -> Optional[Finding]:
    r = t.http("/db/data/")
    if r is not None and r.status == 200 and r.has("neo4j"):
        return Finding(t, _find_poc("neo4j-unauth"), "Likely",
                       "页面含 Neo4j 特征(建议进一步验证认证配置)",
                       url=t.http_url("/db/data/"))
    return None


@poc("node-exporter", "Node Exporter 指标泄露", "监控运维", "Low", [9100, 9101],
     desc="/metrics 匿名可读, 泄露主机资源与进程信息(内网侦察价值)。",
     fix="exporter 仅绑定内网采集地址。")
def poc_node_exporter(t: Target) -> Optional[Finding]:
    r = t.http("/metrics")
    if r is not None and r.status == 200 and r.has("node_", "go_gc"):
        return Finding(t, _find_poc("node-exporter"), "Confirmed",
                       "/metrics 匿名返回 node exporter 指标",
                       url=t.http_url("/metrics"))
    return None


@poc("logstash-unauth", "Logstash API 未授权", "监控运维", "Medium", [9600],
     desc="node stats API 匿名可读, 泄露管道与主机信息。",
     fix="api.http.host 仅绑定内网。")
def poc_logstash(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/")
    if r and isinstance(r.json(), dict) and ("version" in r.json() or
                                              "host" in r.json()):
        return Finding(t, _find_poc("logstash-unauth"), "Confirmed",
                       "Logstash API 匿名可读: " + b2s(r.body, 80),
                       url=t.http_url("/"))
    return None


@poc("solr-unauth", "Apache Solr 未授权访问", "中间件", "High",
     [8983, 8984], always=True,
     desc="匿名可读核心/配置, 结合 Velocity 模板 RCE 或 Config API 修改配置。",
     fix="启用 BasicAuth(security.json); 收口内网。")
def poc_solr(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/solr/admin/collections?action=LIST")
    if r and isinstance(r.json(), dict) and "collections" in r.json():
        return Finding(t, _find_poc("solr-unauth"), "Confirmed",
                       "collections LIST 匿名可读",
                       url=t.http_url("/solr/admin/collections?action=LIST"))
    r2 = t.http_json_200("/solr/admin/info/system")
    if r2 and isinstance(r2.json(), dict) and "lucene" in r2.json():
        return Finding(t, _find_poc("solr-unauth"), "Confirmed",
                       "info/system 匿名可读", url=t.http_url("/solr/admin/info/system"))
    return None


@poc("zabbix-default-cred", "Zabbix 默认口令 Admin/zabbix", "监控运维", "High",
     [80, 8080, 10051], kind="cred",
     desc="Zabbix 前端默认口令, 可下发监控 agent 命令(RCE 面)。",
     fix="修改默认口令; 前端收口内网。")
def poc_zabbix(t: Target) -> Optional[Finding]:
    r = t.http("/")
    if r is None or not (r.has("zabbix")):
        return None
    for user, pwd in (("Admin", "zabbix"), ("guest", "")):
        rr = t.http("/index.php", method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="name=%s&password=%s&autologin=1&enter=Sign%%20in" % (user, pwd))
        if rr is not None and rr.status == 200 and not rr.has("sign in") and \
                rr.has("dashboard"):
            return Finding(t, _find_poc("zabbix-default-cred"), "Confirmed",
                           "%s/%s 登录成功" % (user, pwd), url=t.http_url("/"))
    return None


@poc("sonarqube-unauth", "SonarQube 未授权/默认口令", "监控运维", "Medium",
     [9000, 9001], always=True,
     desc="匿名可读项目与代码质量数据; 默认口令 admin/admin 可进入并拉取源码。",
     fix="sonar.forceAuthentication=true; 修改默认口令。")
def poc_sonarqube(t: Target) -> Optional[Finding]:
    r = t.http("/api/system/ping")
    if r is not None and r.status == 200 and r.text(8) == "pong":
        rr = t.http("/api/system/health", auth=("admin", "admin"))
        if rr is not None and rr.status == 200:
            return Finding(t, _find_poc("sonarqube-unauth"), "Confirmed",
                           "默认口令 admin/admin 有效", url=t.http_url("/api/system/ping"))
        return Finding(t, _find_poc("sonarqube-unauth"), "Likely",
                      "API 匿名可访问(建议核查强制认证配置)",
                      url=t.http_url("/api/system/ping"))
    return None


@poc("nexus-unauth", "Nexus Repository 未授权/默认口令", "监控运维", "High",
     [8081], kind="cred",
     desc="匿名/默认口令(admin/admin123)可上传恶意构件, 供应链投毒面。",
     fix="启用匿名访问=false; 修改默认口令; 收口内网。")
def poc_nexus(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/service/rest/v1/repositories")
    if r and isinstance(r.json(), list):
        rr = t.http_json_200("/service/rest/v1/security/users",
                             auth=("admin", "admin123"))
        if rr and isinstance(rr.json(), list):
            return Finding(t, _find_poc("nexus-unauth"), "Confirmed",
                           "默认口令 admin/admin123 有效", url=t.http_url("/"))
        return Finding(t, _find_poc("nexus-unauth"), "Confirmed",
                       "REST API 匿名可读 repositories",
                       url=t.http_url("/service/rest/v1/repositories"))
    return None


@poc("harbor-unauth", "Harbor 镜像仓库未授权", "容器编排", "High",
     [80, 443, 8443],
     desc="匿名可列出项目/仓库并拉取镜像(含源码与凭据)。",
     fix="Harbor 配置认证; 项目设为私有; 收口内网。")
def poc_harbor(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/v2.0/projects")
    if r and isinstance(r.json(), list):
        return Finding(t, _find_poc("harbor-unauth"), "Confirmed",
                       "/api/v2.0/projects 匿名返回 %d 个项目" % len(r.json()),
                       url=t.http_url("/api/v2.0/projects"))
    return None


@poc("argo-workflows-unauth", "Argo Workflows 未授权", "容器编排", "High",
     [2746, 8080],
     desc="匿名可读取/提交 Workflow, 可执行任意容器命令。",
     fix="开启 SSO/认证; 收口内网。")
def poc_argo(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/v1/workflows")
    if r and isinstance(r.json(), dict) and "items" in r.json():
        return Finding(t, _find_poc("argo-workflows-unauth"), "Confirmed",
                       "/api/v1/workflows 匿名可读", url=t.http_url("/api/v1/workflows"))
    return None


@poc("argocd-unauth", "ArgoCD 未授权", "容器编排", "High", [8080, 8443],
     desc="session API 匿名可访问, 泄露集群与应用编排信息。",
     fix="开启登录; --insecure 关闭; 收口内网。")
def poc_argocd(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/v1/session/userinfo")
    if r and isinstance(r.json(), dict) and (
            "loggedIn" in r.json() or "username" in r.json()):
        return Finding(t, _find_poc("argocd-unauth"), "Likely",
                       "/api/v1/session/userinfo 匿名返回信息: " + b2s(r.body, 80),
                       url=t.http_url("/api/v1/session/userinfo"))
    return None


@poc("kong-admin-unauth", "Kong Admin API 未授权", "中间件", "High", [8001, 8444],
     desc="Admin API 匿名可读写路由/消费者/插件, 相当于网关接管。",
     fix="admin_listen 仅 127.0.0.1; 配置 mTLS 或 RBAC(企业版)。")
def poc_kong(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/")
    if r and isinstance(r.json(), dict) and "configuration" in r.json():
        return Finding(t, _find_poc("kong-admin-unauth"), "Confirmed",
                       "Kong Admin API 匿名可读", url=t.http_url("/"))
    return None


@poc("traefik-unauth", "Traefik Dashboard 未授权", "中间件", "Medium",
     [8079, 8080, 8443],
     desc="Dashboard/API 匿名可读全部路由与后端服务信息。",
     fix="api.dashboard=false 或加认证; 收口内网。")
def poc_traefik(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/rawdata")
    if r and isinstance(r.json(), dict) and ("routers" in r.json() or
                                             "services" in r.json()):
        return Finding(t, _find_poc("traefik-unauth"), "Confirmed",
                       "/api/rawdata 匿名可读", url=t.http_url("/api/rawdata"))
    return None


@poc("airflow-unauth", "Apache Airflow 未授权", "监控运维", "Critical",
     [8080, 8081],
     desc="Web UI 匿名可访问可触发 DAG(BashOperator 即命令执行)。",
     fix="webserver 配置 authenticated=True + Flask-AppBuilder RBAC; 收口内网。")
def poc_airflow(t: Target) -> Optional[Finding]:
    r = t.http("/health")
    if r is not None and r.status == 200 and (r.has("healthy") or
                                              r.has("metadatabase")):
        r2 = t.http("/api/v1/dags")
        if r2 is not None and r2.status == 200 and r2.json():
            return Finding(t, _find_poc("airflow-unauth"), "Confirmed",
                           "/api/v1/dags 匿名可读", url=t.http_url("/api/v1/dags"))
        return Finding(t, _find_poc("airflow-unauth"), "Likely",
                       "/health 匿名返回 healthy", url=t.http_url("/health"))
    return None


@poc("superset-unauth", "Apache Superset 未授权", "监控运维", "Medium",
     [8088, 8080],
     desc="匿名可访问看板/数据库连接信息(Secret Key 默认时还可伪造 session)。",
     fix="配置 AUTH; 更换 SECRET_KEY; 收口内网。")
def poc_superset(t: Target) -> Optional[Finding]:
    r = t.http("/health")
    if r is not None and r.status == 200:
        r2 = t.http("/api/v1/database/_info?q=(order_column:database_name)")
        if r2 is not None and r2.status == 200 and r2.json() and \
                "result" in r2.json():
            return Finding(t, _find_poc("superset-unauth"), "Confirmed",
                           "/api/v1/database 匿名可读",
                           url=t.http_url("/api/v1/database/_info"))
    return None


@poc("metabase-unauth", "Metabase 未授权", "监控运维", "Medium", [3000, 3001],
     desc="匿名可访问分析看板与数据源信息; setup token 未撤销可接管(CVE-2023-38646)。",
     fix="撤销 setup token(升级 >= 0.46.6.1); 启用登录; 收口内网。",
     cve="CVE-2023-38646")
def poc_metabase(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/session/properties")
    if r and isinstance(r.json(), dict) and ("setup-token" in r.json() or
                                             "version" in r.json()):
        token = r.json().get("setup-token")
        sev_extra = "; setup-token=%s(可接管)" % token if token not in (None, "") else ""
        return Finding(t, _find_poc("metabase-unauth"), "Confirmed",
                       "session/properties 匿名可读" + sev_extra,
                       url=t.http_url("/api/session/properties"))
    return None


@poc("jupyter-unauth", "Jupyter Notebook 未授权", "监控运维", "Critical",
     [8888, 8889, 9999], always=True,
     desc="无 token 访问即可新建 terminal 执行任意命令 RCE。",
     fix="启动配置 token 或密码; NotebookApp.allow_remote_access 收口。")
def poc_jupyter(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/contents?content=0")
    if r and isinstance(r.json(), dict) and "content" in r.json():
        return Finding(t, _find_poc("jupyter-unauth"), "Confirmed",
                       "/api/contents 匿名可读(未启用 token)",
                       url=t.http_url("/api/contents?content=0"))
    r2 = t.http("/login?next=")
    if r2 is not None and r2.status == 200 and r2.has("jupyter"):
        r3 = t.http("/tree")
        if r3 is not None and r3.status == 200 and r3.has("jupyter") and \
                not r3.has("password"):
            return Finding(t, _find_poc("jupyter-unauth"), "Likely",
                           "Jupyter 页面可达且未见登录跳转",
                           url=t.http_url("/tree"))
    return None


@poc("supervisord-unauth", "Supervisord Web 未授权", "监控运维", "High",
     [9001, 9002],
     desc="Web 控制台无认证, 可控制进程启停(老版本 XML-RPC 可 RCE)。",
     fix="配置 username/password; inet_http_server 绑定内网。")
def poc_supervisord(t: Target) -> Optional[Finding]:
    r = t.http("/")
    if r is not None and r.status == 200 and r.has("supervisor", "status"):
        return Finding(t, _find_poc("supervisord-unauth"), "Confirmed",
                       "Supervisord 控制台匿名可访问", url=t.http_url("/"))
    return None


@poc("cadvisor-unauth", "cAdvisor 容器指标未授权", "容器编排", "Low",
     [4194, 8080],
     desc="匿名可读全部容器/主机资源信息(容器逃逸侦察价值)。",
     fix="--listen_ip 仅内网。")
def poc_cadvisor(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/v1.3/subcontainers")
    if r and isinstance(r.json(), list) and r.json():
        return Finding(t, _find_poc("cadvisor-unauth"), "Confirmed",
                       "/api/v1.3/subcontainers 匿名返回 %d 个容器" % len(r.json()),
                       url=t.http_url("/api/v1.3/subcontainers"))
    return None


# ---------------------------- AI 组件 (2024-2026 高发) ---------------------------------
@poc("ollama-unauth", "Ollama 未授权访问(CNVD-2025-04094)", "AI组件", "Critical",
     [11434], always=True,
     desc="LLM 推理服务无认证, 可窃取本地模型、篡改系统配置、滥用推理资源。",
     fix="OLLAMA_HOST=127.0.0.1:11434; 或前置网关加认证; 收口内网。")
def poc_ollama(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/tags")
    if r and isinstance(r.json(), dict) and "models" in r.json():
        n = len(r.json()["models"])
        return Finding(t, _find_poc("ollama-unauth"), "Confirmed",
                       "/api/tags 匿名返回 %d 个模型" % n,
                       url=t.http_url("/api/tags"))
    return None


@poc("ray-dashboard-unauth", "Ray Dashboard 未授权(ShadowRay)", "AI组件", "Critical",
     [8265, 10001],
     desc="Ray 控制台/Job API 无认证, 可提交任意任务 RCE; 已被大规模用于挖矿。",
     fix="Ray >= 1.13 并配置登录; dashboard/job 端口绝不暴露公网。",
     cve="CVE-2023-48022")
def poc_ray(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/version")
    if r is None or r.status != 200:
        r = t.http("/")
        if r is not None and r.status == 200 and r.has("ray dashboard"):
            return Finding(t, _find_poc("ray-dashboard-unauth"), "Confirmed",
                           "Ray Dashboard 页面匿名可访问", url=t.http_url("/"))
        return None
    if r and isinstance(r.json(), dict) and "version" in r.json():
        return Finding(t, _find_poc("ray-dashboard-unauth"), "Confirmed",
                       "/api/version 匿名可读: " + b2s(r.body, 60),
                       url=t.http_url("/api/version"))
    return None


@poc("mlflow-unauth", "MLflow 未授权", "AI组件", "Critical", [5000, 5001],
     desc="可匿名读写实验/模型注册表; 利用 file:// artifact 上传写任意文件 RCE。",
     fix="启用认证(>= 2.3); artifact root 禁 file://; 收口内网。")
def poc_mlflow(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/2.0/mlflow/experiments/list")
    if r and isinstance(r.json(), dict) and "experiments" in r.json():
        return Finding(t, _find_poc("mlflow-unauth"), "Confirmed",
                       "experiments/list 匿名可读",
                       url=t.http_url("/api/2.0/mlflow/experiments/list"))
    return None


@poc("vllm-unauth", "vLLM / OpenAI 兼容 API 未授权", "AI组件", "High",
     [8000, 8001, 1234],
     desc="模型 API 无 API Key, 可白嫖推理并读取系统 prompt 与配置。",
     fix="--api-key 设置密钥; 收口内网。")
def poc_vllm(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/v1/models")
    if r and isinstance(r.json(), dict) and r.json().get("object") == "list" \
            and r.json().get("data"):
        return Finding(t, _find_poc("vllm-unauth"), "Confirmed",
                       "/v1/models 匿名返回模型列表",
                       url=t.http_url("/v1/models"))
    return None


@poc("comfyui-unauth", "ComfyUI 未授权", "AI组件", "High", [8188, 8189],
     desc="工作流 UI 无认证, 可读取/覆盖工作流与自定义节点, 并可上传文件。",
     fix="--listen 127.0.0.1; 前置认证网关。")
def poc_comfyui(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/system_stats")
    if r and isinstance(r.json(), dict) and "system" in r.json():
        return Finding(t, _find_poc("comfyui-unauth"), "Confirmed",
                       "/system_stats 匿名可读(含 Python/设备信息)",
                       url=t.http_url("/system_stats"))
    return None


@poc("tensorboard-unauth", "TensorBoard 未授权", "AI组件", "Low", [6006],
     desc="训练监控匿名可读, 泄露训练任务与参数信息。",
     fix="--bind_all 改为内网监听。")
def poc_tensorboard(t: Target) -> Optional[Finding]:
    r = t.http("/")
    if r is not None and r.status == 200 and r.has("tensorboard"):
        return Finding(t, _find_poc("tensorboard-unauth"), "Confirmed",
                       "TensorBoard 页面匿名可访问", url=t.http_url("/"))
    return None


@poc("milvus-unauth", "Milvus 管理端口未授权(CVE-2026-26190 / CVE-2025-64513)",
     "AI组件", "Critical", [9091, 19530],
     desc="9091 管理端口 REST API 无认证(可建删集合/用户); /expr 调试端点默认 "
          "token 'by-dev' 可执行任意表达式 RCE。",
     fix="升级 >= 2.5.27 / 2.6.10; exprEnabled=false; 9091/19530/53100 收口内网。",
     cve="CVE-2026-26190, CVE-2025-64513")
def poc_milvus(t: Target) -> Optional[Finding]:
    for path in ("/api/v1/vector/collections",
                 "/api/v1/collection",
                 "/v2/vectordb/collections/list"):
        r = t.http_json_200(path)
        j = r.json() if r else None
        hit = (isinstance(j, dict) and ("collections" in j or "count" in j)) or \
              (isinstance(j, list) and j and isinstance(j[0], dict) and
               ("collection_name" in j[0] or "status" in j[0]))
        if hit:
            return Finding(t, _find_poc("milvus-unauth"), "Confirmed",
                           "%s 匿名返回数据(管理 API 未授权)" % path,
                           url=t.http_url(path))
    r2 = t.http("/metrics")
    if r2 is not None and r2.status == 200 and r2.has("milvus"):
        return Finding(t, _find_poc("milvus-unauth"), "Likely",
                       "Milvus metrics 端点匿名可读(9091 暴露)",
                       url=t.http_url("/metrics"))
    return None


@poc("qdrant-unauth", "Qdrant 向量库未授权", "AI组件", "High", [6333, 6334],
     desc="REST API 无 API Key, 可读写全部 collection 与向量数据。",
     fix="--api-key 设置密钥; 收口内网。")
def poc_qdrant(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/")
    if r and isinstance(r.json(), dict) and "qdrant" in str(r.json().get("title", "")).lower():
        return Finding(t, _find_poc("qdrant-unauth"), "Confirmed",
                       "根路径匿名返回 Qdrant 服务信息",
                       url=t.http_url("/"))
    r2 = t.http_json_200("/collections")
    if r2 and isinstance(r2.json(), dict) and "result" in r2.json():
        return Finding(t, _find_poc("qdrant-unauth"), "Confirmed",
                       "/collections 匿名可读", url=t.http_url("/collections"))
    return None


@poc("weaviate-unauth", "Weaviate 向量库未授权", "AI组件", "High", [8080, 8081],
     desc="REST/GraphQL 匿名可读, 全库数据泄露。",
     fix="配置 authentication apikey; 收口内网。")
def poc_weaviate(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/v1/meta")
    if r and isinstance(r.json(), dict) and "version" in r.json():
        return Finding(t, _find_poc("weaviate-unauth"), "Confirmed",
                       "/v1/meta 匿名可读", url=t.http_url("/v1/meta"))
    return None


@poc("chromadb-unauth", "ChromaDB 未授权", "AI组件", "High", [8000, 8001],
     desc="向量数据库 API 无认证, 可读写全部 collection。",
     fix="配置 Basic Auth(>= 0.5); 收口内网。")
def poc_chroma(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/api/v1/heartbeat")
    if r and isinstance(r.json(), dict) and ("nanosecond heartbeat" in r.json()
                                             or "heartbeat" in r.json()):
        return Finding(t, _find_poc("chromadb-unauth"), "Confirmed",
                       "/api/v1/heartbeat 匿名可读",
                       url=t.http_url("/api/v1/heartbeat"))
    return None


@poc("minio-unauth", "MinIO 对象存储未授权", "AI组件", "High", [9000, 9001],
     desc="S3 API 匿名可列出/读写桶内对象(常含数据集、模型、备份)。",
     fix="MINIO_ROOT_USER/PASSWORD 强口令; 桶策略禁止匿名; 收口内网。")
def poc_minio(t: Target) -> Optional[Finding]:
    r = t.http("/")
    if r is not None and r.status == 200 and r.has("listallmybucketsresult"):
        return Finding(t, _find_poc("minio-unauth"), "Confirmed",
                       "匿名列出全部存储桶(ListAllMyBucketsResult)",
                       url=t.http_url("/"))
    r2 = t.http("/minio/health/live")
    if r2 is not None and r2.status == 200:
        r3 = t.http("/?list-type=2")
        if r3 is not None and r3.status == 200 and r3.has("listbucketresult"):
            return Finding(t, _find_poc("minio-unauth"), "Confirmed",
                          "匿名列出桶对象", url=t.http_url("/"))
    return None


@poc("langserve-unauth", "LangServe / LangChain playground 泄露", "AI组件", "High",
     [8000, 7860, 8080],
     desc="/playground 与 OpenAPI 端点匿名可读, 泄露 Agent 链路、工具与系统 prompt。",
     fix="路由加认证; 关闭 playground; 收口内网。")
def poc_langserve(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/openapi.json")
    if not (r and isinstance(r.json(), dict)):
        return None
    paths = r.json().get("paths")
    if not isinstance(paths, dict):
        return None
    # 强指纹(避免普通 FastAPI 业务接口误报):
    #   - /playground 端点匿名可达(GET, LangServe 专属 playground)
    #   - 或 POST /{name}/invoke|run|batch|stream 且 requestBody 顶层含 input 字段
    #     (RemoteRunnable 接口签名固定 {input, config?, kwargs?}, 普通业务 API 极罕见)
    for p, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        pl = p.rstrip("/").lower()
        if pl == "/playground" or pl.endswith("/playground"):
            return Finding(t, _find_poc("langserve-unauth"), "Confirmed",
                           "openapi.json 暴露 LangServe playground 端点(%s)" % p,
                           url=t.http_url("/openapi.json"))
        if not any(pl == e or pl.endswith(e)
                   for e in ("/invoke", "/run", "/batch", "/stream")):
            continue
        post = ops.get("post")
        if not isinstance(post, dict):
            continue
        props = (post.get("requestBody", {}).get("content", {})
                 .get("application/json", {}).get("schema", {}).get("properties", {}))
        if isinstance(props, dict) and "input" in props:
            return Finding(t, _find_poc("langserve-unauth"), "Confirmed",
                           "openapi.json 暴露 LangServe runnable 接口(%s), body 含 input 字段" % p,
                           url=t.http_url("/openapi.json"))
    return None


@poc("flowise-unauth", "Flowise/Langflow 可视化编排未授权", "AI组件", "High",
     [3000, 3001, 7860],
     desc="无登录访问, 可读取/篡改全部 LLM 工作流(含 API Key 与凭据)。",
     fix="启用登录与鉴权; 收口内网。")
def poc_flowise(t: Target) -> Optional[Finding]:
    for path in ("/api/v1/chatflows", "/api/v1/flows"):
        r = t.http_json_200(path)
        if r and isinstance(r.json(), list):
            return Finding(t, _find_poc("flowise-unauth"), "Confirmed",
                           "%s 匿名返回 %d 个工作流" % (path, len(r.json())),
                           url=t.http_url(path))
    return None


@poc("dify-unauth", "Dify 控制台 API 未授权", "AI组件", "Medium", [5001, 3000],
     desc="console API 匿名可读取系统配置(版本/setup 状态)。",
     fix="完成初始化并启用登录; 收口内网。")
def poc_dify(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/console/api/setup")
    if r and isinstance(r.json(), dict) and "step" in r.json():
        return Finding(t, _find_poc("dify-unauth"), "Likely",
                       "/console/api/setup 匿名可读: " + b2s(r.body, 60),
                       url=t.http_url("/console/api/setup"))
    return None


@poc("triton-unauth", "NVIDIA Triton Inference 未授权", "AI组件", "Medium",
     [8000, 8001, 8002],
     desc="HTTP/gRPC 推理服务无认证, 可调用模型与读取仓库元数据。",
     fix="配置 --strict-model-config 与网关认证; 收口内网。")
def poc_triton(t: Target) -> Optional[Finding]:
    r = t.http_json_200("/v2/models")
    if r is not None:
        return None    # 非标准
    r2 = t.http("/v2/health/ready")
    if r2 is not None and r2.status == 200:
        r3 = t.http_json_200("/v2/repository/index")
        if r3 is not None and isinstance(r3.json(), list):
            return Finding(t, _find_poc("triton-unauth"), "Confirmed",
                           "repository/index 匿名返回模型列表",
                           url=t.http_url("/v2/repository/index"))
    return None


# ==============================================================================
# 5. 引擎: 端口扫描 + POC 调度
# ==============================================================================

def _find_poc(key):
    for p in POCS:
        if p.key == key:
            return p
    raise KeyError(key)


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 443, 445, 465,
    500, 512, 513, 514, 548, 554, 587, 623, 636, 873, 990, 993, 995, 1080,
    1099, 1433, 1521, 1723, 1883, 2049, 2080, 2081, 2083, 2181, 2375, 2376,
    2379, 2380, 2638, 3000, 3001, 3128, 3260, 3306, 3389, 3690, 4444, 4646,
    4848, 5000, 5001, 5044, 5432, 5601, 5672, 5900, 5901, 5984, 5985, 6000,
    6006, 6041, 6066, 6379, 6443, 7001, 7002, 7077, 7080, 7180, 7470, 7547,
    7687, 7777, 8000, 8001, 8008, 8009, 8010, 8020, 8025, 8030, 8040, 8042,
    8060, 8069, 8080, 8081, 8082, 8083, 8086, 8088, 8089, 8090, 8091, 8095,
    8100, 8111, 8118, 8123, 8125, 8140, 8161, 8180, 8188, 8200, 8222, 8243,
    8265, 8280, 8333, 8334, 8443, 8444, 8500, 8545, 8649, 8686, 8700, 8718,
    8761, 8765, 8800, 8848, 8850, 8858, 8866, 8888, 8889, 8943, 8983, 9000,
    9001, 9002, 9009, 9010, 9042, 9043, 9090, 9091, 9092, 9093, 9100, 9200,
    9201, 9230, 9256, 9292, 9300, 9418, 9440, 9443, 9500, 9527, 9529, 9575,
    9600, 9696, 9710, 9800, 9869, 9876, 9879, 9999, 10000, 10001, 10050,
    10051, 10250, 10255, 10443, 10911, 10998, 11211, 11311, 12000, 12222,
    13000, 14000, 15000, 15672, 16010, 16030, 17000, 18080, 18086, 19000,
    19999, 20000, 20880, 21883, 22122, 23000, 25565, 26000, 26257, 27017,
    27018, 27019, 27883, 28017, 28018, 30009, 31031, 32000, 33060, 33290,
    46464, 50070, 50075, 59854, 61616,
]


def all_poc_ports():
    s = set()
    for p in POCS:
        s.update(p.ports)
    return sorted(s)


def parse_ports(spec: str) -> List[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def parse_targets(specs: List[str]) -> List[str]:
    ips = []
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        if os.path.isfile(spec):
            with open(spec, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips.extend(parse_targets([line]))
            continue
        try:
            net = ipaddress.ip_network(spec, strict=False)
            if net.num_addresses > 65536:
                raise ValueError("网段过大: %s (最多 /16)" % spec)
            if net.num_addresses == 1:
                ips.append(str(net.network_address))
            else:
                ips.extend(str(h) for h in net.hosts())
            continue
        except ValueError:
            pass
        # 普通 IP 列表
        for token in re.split(r"[,\s;]+", spec):
            if not token:
                continue
            try:
                ipaddress.ip_address(token)
                ips.append(token)
            except ValueError:
                print(c("[!] 无效目标(跳过): %s" % token, Y))
    return sorted(set(ips))


def scan_port(ip, port, timeout=2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


class Scanner:
    def __init__(self, ips, ports, timeout=4.0, workers=200, fast=False,
                 udp=False, deep=False):
        self.ips = ips
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.fast = fast
        self.udp = udp
        self.deep = deep        # 对所有开放端口执行协议级探针(非默认端口部署也能检出)
        self.open_targets: List[Target] = []
        self.findings: List[Finding] = []
        self.lock = threading.Lock()
        self.stats = {"scanned": 0, "open": 0, "http": 0, "checks": 0}

    def log(self, msg):
        print(msg, flush=True)

    # ---- 阶段 1: 端口扫描 ----
    def scan(self):
        total = len(self.ips) * len(self.ports)
        self.log(c("\n[*] 端口扫描: %d 个目标 x %d 个端口 = %d 项 (workers=%d)"
                   % (len(self.ips), len(self.ports), total, self.workers), C))
        t0 = time.time()
        done = [0]

        def task(ip, port):
            if scan_port(ip, port, timeout=min(2.0, self.timeout)):
                with self.lock:
                    self.open_targets.append(Target(ip, port, self.timeout))
                    self.stats["open"] += 1
                    self.log(c("    [+] open  %s:%d" % (ip, port), G))
            with self.lock:
                done[0] += 1
                self.stats["scanned"] = done[0]
                if done[0] % 500 == 0:
                    rate = done[0] / max(time.time() - t0, 0.001)
                    self.log(c("    [-] 进度 %d/%d (%.0f/s)" %
                               (done[0], total, rate), D))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            list(ex.map(lambda a: task(*a),
                        ((ip, p) for ip in self.ips for p in self.ports)))
        self.log(c("[*] 端口扫描完成: %d 开放 / %d 项, 耗时 %.1fs"
                   % (self.stats["open"], total, time.time() - t0), C))

    # ---- 阶段 2: 服务识别 + POC ----
    def run_pocs(self):
        self.log(c("\n[*] 服务识别与未授权检测: %d 个开放端口, %d 个 POC"
                   % (len(self.open_targets), len(POCS)), C))
        t0 = time.time()
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(self.workers, 64)) as ex:
            list(ex.map(self._check_target, self.open_targets))
        self.log(c("[*] 检测完成: %d 项发现, 耗时 %.1fs"
                   % (len(self.findings), time.time() - t0), C))
        if self.udp:
            self._run_udp()

    def _run_udp(self):
        self.log(c("\n[*] UDP 检测(SNMP/IPMI)...", C))
        for p in POCS:
            if p.proto != "udp":
                continue
            for ip in self.ips:
                for port in p.ports:
                    try:
                        f = p.fn(ip, port, self.timeout)
                        if f:
                            self._add(f)
                    except Exception:
                        pass

    def _add(self, f: Finding):
        with self.lock:
            self.findings.append(f)
            self.log("    %s[%s] %s  %s:%s  %s%s" % (
                SEV_COLOR.get(f.poc.severity, ""),
                f.poc.severity, f.poc.name, f.target.ip, f.target.port,
                f.confidence, RST))

    def _check_target(self, t: Target):
        # 服务识别
        t.identify()
        banner = t.get_banner()
        if t.proto:
            with self.lock:
                self.stats["http"] += 1
        else:
            svc = b2s(banner, 40) if banner else "tcp"
            self.log(c("    [i] %s:%d  %s" % (t.ip, t.port, svc), D))
        # 逐个 POC
        for p in POCS:
            if p.proto == "udp":
                continue
            try:
                if p.kind in ("proto", "cred"):
                    port_match = t.port in p.ports
                    banner_match = bool(p.banner_re and banner and
                                        re.search(p.banner_re,
                                                  banner.decode("latin-1", "replace")))
                    if not (port_match or banner_match or self.deep):
                        continue
                else:  # path
                    if t.proto is None:
                        continue
                    if self.fast and not p.always and t.port not in p.ports:
                        continue
                    if p.default_only and t.port not in p.ports:
                        continue
                with self.lock:
                    self.stats["checks"] += 1
                f = p.fn(t)
                if f:
                    self._add(f)
            except Exception:
                continue


# ==============================================================================
# 6. 报告输出: 控制台 / JSON / CSV / HTML
# ==============================================================================

def findings_sorted(findings):
    return sorted(findings, key=lambda f: f.sev_rank)


def print_console(findings, stats, duration):
    print("\n" + "=" * 78)
    print(c("  扫描结果汇总  (耗时 %.1fs)" % duration, C))
    print("=" * 78)
    if not findings:
        print(c("  未发现未授权访问漏洞。", G))
    for f in findings_sorted(findings):
        print("  %s[%s]%s %s | %s:%d | %s | %s" % (
            SEV_COLOR.get(f.poc.severity, ""), f.poc.severity, RST,
            f.poc.name, f.target.ip, f.target.port, f.confidence,
            f.url or ("tcp://%s:%d" % (f.target.ip, f.target.port))))
        print(c("      证据: %s" % f.evidence, D))
    print("-" * 78)
    print("  扫描: %d 项 | 开放: %d | HTTP: %d | POC 检查: %d | 发现: %d" % (
        stats["scanned"], stats["open"], stats["http"], stats["checks"],
        len(findings)))
    print("=" * 78)


def write_json(path, findings, stats, meta):
    data = {
        "meta": meta,
        "stats": stats,
        "findings": [{
            "ip": f.target.ip, "port": f.target.port,
            "service": f.target.server_header or
                       (f.target.proto or "tcp"),
            "vuln_id": f.poc.key, "name": f.poc.name,
            "category": f.poc.category, "severity": f.poc.severity,
            "confidence": f.confidence, "cve": f.poc.cve,
            "evidence": f.evidence, "url": f.url,
            "description": f.poc.desc, "fix": f.poc.fix,
        } for f in findings_sorted(findings)],
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=2)


def write_csv(path, findings):
    with open(path, "w", encoding="utf-8-sig", newline="") as fp:
        w = csv.writer(fp)
        w.writerow(["IP", "端口", "协议", "漏洞名称", "类别", "严重度",
                    "置信度", "CVE/编号", "URL", "证据", "修复建议"])
        for f in findings_sorted(findings):
            w.writerow([f.target.ip, f.target.port,
                        f.target.proto or "tcp", f.poc.name, f.poc.category,
                        f.poc.severity, f.confidence, f.poc.cve, f.url,
                        f.evidence, f.poc.fix])


SEV_BG = {"Critical": "#c0392b", "High": "#e74c3c", "Medium": "#f39c12",
          "Low": "#3498db", "Info": "#7f8c8d"}


def write_html(path, findings, stats, meta):
    rows = []
    for f in findings_sorted(findings):
        rows.append("""
        <tr>
          <td>%s</td><td>%d</td><td>%s</td>
          <td><span class="sev" style="background:%s">%s</span></td>
          <td>%s</td><td>%s</td>
          <td class="mono">%s</td>
          <td>%s</td><td>%s</td>
        </tr>""" % (
            html_mod.escape(f.target.ip), f.target.port,
            html_mod.escape(f.target.proto or "tcp"),
            SEV_BG.get(f.poc.severity, "#7f8c8d"), f.poc.severity,
            html_mod.escape(f.poc.name),
            html_mod.escape(f.poc.category),
            html_mod.escape(f.url or ("tcp://%s:%d" % (f.target.ip, f.target.port))),
            html_mod.escape(f.evidence[:200]),
            html_mod.escape(f.poc.fix)))
    sev_count = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev_count[f.poc.severity] += 1
    cards = "".join(
        '<div class="card" style="border-top:4px solid %s"><div class="num">%d</div>'
        '<div class="lbl">%s</div></div>' % (SEV_BG[s], sev_count[s], s)
        for s in SEV_ORDER)
    html = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>未授权访问漏洞扫描报告 - UnAuthHunter</title>
<style>
 body{font-family:"Microsoft YaHei","PingFang SC",sans-serif;background:#f5f6fa;margin:0;padding:24px;color:#2c3e50;}
 .wrap{max-width:1200px;margin:0 auto;}
 h1{font-size:22px;border-bottom:3px solid #c0392b;padding-bottom:10px;}
 h2{font-size:16px;margin-top:28px;border-left:4px solid #c0392b;padding-left:8px;}
 .cards{display:flex;gap:14px;margin:18px 0;flex-wrap:wrap;}
 .card{background:#fff;border-radius:8px;padding:16px 28px;box-shadow:0 1px 4px rgba(0,0,0,.08);min-width:110px;text-align:center;}
 .card .num{font-size:30px;font-weight:700;}
 .card .lbl{font-size:12px;color:#7f8c8d;margin-top:4px;}
 table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;}
 th,td{border:1px solid #dcdde1;padding:7px 9px;text-align:left;vertical-align:top;}
 th{background:#2c3e50;color:#fff;font-weight:600;}
 tr:nth-child(even){background:#fafafa;}
 .sev{color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;white-space:nowrap;}
 .mono{font-family:Consolas,monospace;font-size:12px;color:#576574;word-break:break-all;}
 .meta{background:#fff;border-radius:8px;padding:14px 18px;line-height:1.9;box-shadow:0 1px 4px rgba(0,0,0,.08);}
 .dis{margin-top:26px;font-size:12px;color:#95a5a6;border-top:1px solid #dcdde1;padding-top:10px;}
</style></head><body><div class="wrap">
<h1>未授权访问漏洞扫描报告</h1>
<div class="meta">
 <b>生成时间:</b> @@TIME@@ &nbsp;|&nbsp; <b>工具:</b> UnAuthHunter v@@VER@@<br>
 <b>目标:</b> @@TARGETS@@<br>
 <b>扫描统计:</b> 端口项 @@SCANNED@@ | 开放端口 @@OPEN@@ | HTTP 服务 @@HTTP@@ | POC 检查 @@CHECKS@@ | <b>发现漏洞 @@FINDINGS@@</b> | 耗时 @@DUR@@s
</div>
<h2>严重度分布</h2>
<div class="cards">@@CARDS@@</div>
<h2>漏洞明细 (按严重度排序)</h2>
<table>
<tr><th>IP</th><th>端口</th><th>协议</th><th>严重度</th><th>漏洞</th><th>类别</th>
<th>位置</th><th>证据</th><th>修复建议</th></tr>
@@ROWS@@
</table>
<div class="dis">声明: 本报告由 UnAuthHunter 自动生成, 仅用于授权范围内的安全评估。
置信度 Confirmed 表示已验证可未授权访问; Likely 表示存在强特征、建议人工复核。</div>
</div></body></html>"""
    for k, v in {
        "@@TIME@@": html_mod.escape(meta["time"]),
        "@@VER@@": __version__,
        "@@TARGETS@@": html_mod.escape(meta["targets"]),
        "@@SCANNED@@": str(stats["scanned"]),
        "@@OPEN@@": str(stats["open"]),
        "@@HTTP@@": str(stats["http"]),
        "@@CHECKS@@": str(stats["checks"]),
        "@@FINDINGS@@": str(len(findings)),
        "@@DUR@@": "%.1f" % meta["duration"],
        "@@CARDS@@": cards,
        "@@ROWS@@": "".join(rows),
    }.items():
        html = html.replace(k, v)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(html)


# ==============================================================================
# 7. 主入口
# ==============================================================================

BANNER = r"""
   __  __   _   _  _   _   _____  _   _  _   _  _
  |  \/  | / \ | || | | | |_   _|| | | || \ | || |
  | |\/| |/ _ \| || |_| |   | |  | |_| ||  \| || |
  | |  | / ___ \__   _|   | |  |  _  || |\  ||_|
  |_|  |_/_/   \_\ |_|    |_|  |_| |_||_| \_(_)
  多目标端口扫描 + 未授权访问漏洞检测 v%s   (仅限授权使用)
""" % __version__


def list_pocs():
    print("%-28s %-6s %-10s %-40s %s" % ("漏洞ID", "严重度", "类型", "名称", "默认端口"))
    print("-" * 110)
    for p in sorted(POCS, key=lambda x: (SEV_ORDER.get(x.severity, 9), x.key)):
        print("%-28s %-8s %-10s %-40s %s" % (
            p.key, p.severity, p.kind, p.name,
            ",".join(str(x) for x in p.ports) or "-"))


def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(
        description="UnAuthHunter - 多目标端口扫描 + 未授权访问漏洞检测",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-t", "--targets", nargs="+",
                    help="目标: IP / CIDR / 目标文件路径, 空格分隔多个")
    ap.add_argument("-p", "--ports", default="",
                    help="端口: 如 80,443,8080-8090 (默认=TOP端口+全部POC默认端口)")
    ap.add_argument("--fast", action="store_true",
                    help="快速模式: 路径类POC仅在其默认端口执行(默认全端口执行)")
    ap.add_argument("--deep", action="store_true",
                    help="深度模式: 协议类POC对所有开放端口执行(可检出改端口部署的服务)")
    ap.add_argument("--udp", action="store_true", help="附加 UDP 检测(SNMP)")
    ap.add_argument("--timeout", type=float, default=4.0, help="超时秒数(默认4)")
    ap.add_argument("-w", "--workers", type=int, default=300, help="并发线程(默认300)")
    ap.add_argument("-o", "--output", default="reports", help="报告输出目录")
    ap.add_argument("--no-color", action="store_true", help="关闭彩色输出")
    ap.add_argument("--list", action="store_true", help="列出全部内置 POC 并退出")
    args = ap.parse_args()

    if args.no_color or os.name == "nt" and not _win_ansi_ok():
        USE_COLOR = False

    if args.list:
        list_pocs()
        return

    if not args.targets:
        ap.print_help()
        print(c("\n[!] 请通过 -t 指定目标, 例如:\n"
                "    python unauth_scanner.py -t 192.168.1.0/24\n"
                "    python unauth_scanner.py -t targets.txt -p 80,8000-8100\n"
                "    python unauth_scanner.py -t 10.0.0.5 10.0.0.6 --udp\n", Y))
        return

    print(c(BANNER, C))
    ips = parse_targets(args.targets)
    if not ips:
        print(c("[!] 无有效目标", ""))
        return
    ports = parse_ports(args.ports) if args.ports else \
        sorted(set(TOP_PORTS) | set(all_poc_ports()))
    print(c("[*] 目标 %d 个 IP; 端口 %d 个%s" % (
        len(ips), len(ports),
        " (使用 -p 自定义可加速)" if not args.ports else ""), C))

    t_start = time.time()
    sc = Scanner(ips, ports, timeout=args.timeout, workers=args.workers,
                 fast=args.fast, udp=args.udp, deep=args.deep)
    sc.scan()
    sc.run_pocs()
    duration = time.time() - t_start

    print_console(sc.findings, sc.stats, duration)

    outdir = args.output
    os.makedirs(outdir, exist_ok=True)
    base = os.path.join(outdir, "unauth_report_%s" % safe_name())
    meta = {"time": now_str(), "targets": ", ".join(ips[:20]) +
            (" 等%d个" % len(ips) if len(ips) > 20 else ""),
            "duration": duration}
    write_json(base + ".json", sc.findings, sc.stats, meta)
    write_csv(base + ".csv", sc.findings)
    write_html(base + ".html", sc.findings, sc.stats, meta)
    print(c("\n[*] 报告已输出: %s.json / .csv / .html" % base, G))
    print(c("[*] 仅限授权使用; Likely 结果建议人工复核。", D))


def _win_ansi_ok():
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        return bool(kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7))
    except Exception:
        return False


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n[!] 用户中断", Y))
        sys.exit(1)
