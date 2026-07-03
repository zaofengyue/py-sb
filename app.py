"""app.py — py-sb单文件部署。"""

# ========== 预留配置，留空则自动识别 ==========
CONF_UUID           = ""
CONF_PORT           = ""
CONF_ARGO_PORT      = ""
CONF_NAME           = ""
CONF_SUB            = ""
CONF_ARGO_DOMAIN    = ""
CONF_ARGO_AUTH      = ""
# ── 填 "true" 禁用 Argo，留空则启用 ──
CONF_DISABLE_ARGO   = ""
# ── 可选协议，填写端口则启动对应协议，留空不启动 ──
CONF_HY2_PORT       = ""
CONF_TUIC_PORT      = ""
CONF_REALITY_PORT   = ""
CONF_REALITY_DOMAIN = ""
CONF_SS_PORT        = ""
CONF_S5_PORT        = ""
CONF_ANYTLS_PORT    = ""
# =============================================

import base64
import json
import logging
import os
import platform
import re
import socket
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("node-sb")

HOME            = Path(os.environ.get("HOME") or tempfile.gettempdir())
DATA_DIR        = HOME / "py-sb"
UUID_FILE       = DATA_DIR / "uuid.txt"
CONFIG_FILE     = DATA_DIR / "sb-config.json"
SB_DIR          = DATA_DIR / "sing-box"
SB_BIN_PATH     = SB_DIR / "sing-box"
CLOUDFLARED_BIN = DATA_DIR / "cloudflared"

# Argo 三协议 WS 路径
WS_PATH_VMESS  = "/fengyue-vm"
WS_PATH_VLESS  = "/fengyue-vl"
WS_PATH_TROJAN = "/fengyue-tr"

# Argo 三协议固定内部端口
V_VMESS_PORT  = 10000
V_VLESS_PORT  = 10001
V_TROJAN_PORT = 10002

PATH_TO_PORT = {
    WS_PATH_VMESS: V_VMESS_PORT,
    WS_PATH_VLESS: V_VLESS_PORT,
    WS_PATH_TROJAN: V_TROJAN_PORT,
}

CF_PREFER_HOST = "cdns.doon.eu.org"

ARCH_MAP = {
    "x86_64": "amd64", "amd64": "amd64",
    "aarch64": "arm64", "arm64": "arm64",
    "armv7l": "armv7",
    "i386": "386", "i686": "386",
}
CF_ARCH_MAP = {"amd64": "linux-amd64", "arm64": "linux-arm64", "armv7": "linux-arm"}


# ──────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────
def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_get_text(url: str, timeout: int = 5) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode().strip()
    except Exception:
        return ""


def download(url: str, dest: str):
    """跨平台下载：优先 curl，再 wget，最后用 urllib 兜底（urllib 会自动处理重定向）。"""
    for cmd in (["curl", "-fsSL", url, "-o", dest], ["wget", "-q", url, "-O", dest]):
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    urllib.request.urlretrieve(url, dest)


def derive_ss_password(uuid_str: str) -> str:
    """SS2022 密码：2022-blake3-aes-128-gcm 需要 16 字节 key，base64 后 24 字符；
    取 UUID 去横线后前 32 个十六进制字符（即 16 字节）做 base64。"""
    hex_str = uuid_str.replace("-", "")[:32]
    return base64.b64encode(bytes.fromhex(hex_str)).decode()


# ──────────────────────────────────────────────
# 自签证书：每个部署实例都生成独一无二的密钥
# ──────────────────────────────────────────────
FALLBACK_PRIVATE_KEY = """-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa
/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----"""

FALLBACK_CERT = """-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy
MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h
aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR
BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----"""


def secure_file_permissions(path):
    """限制密钥文件权限，仅当前用户可读写，降低同机其他用户/进程读取风险。"""
    try:
        os.chmod(path, 0o600)
    except OSError as e:
        log.warning("设置文件权限失败 %s: %s", path, e)


def generate_self_signed_cert(cert_dir: Path) -> tuple[str, str]:
    """返回 (key_path, cert_path)。优先用系统 openssl 生成独立证书；
    没有 openssl 时退化为源码内置的共享测试证书兜底（见下方安全警示）。
    """
    key_path = cert_dir / "key.pem"
    cert_path = cert_dir / "cert.pem"
    if key_path.exists() and cert_path.exists():
        return str(key_path), str(cert_path)
    cert_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:P-256", "-days", "3650", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-subj", "/CN=bing.com/O=Microsoft/C=US",
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        secure_file_permissions(key_path)
        return str(key_path), str(cert_path)
    except (subprocess.CalledProcessError, FileNotFoundError):
        log.info("系统未检测到 openssl，使用 Python 内置兜底证书现场生成...")

    # ⚠️ 安全警示：以下为共享兜底证书，仅适用于个人测试/学习场景。
    # 该私钥已写入源码、随脚本公开传播，任何使用此兜底路径的部署实例
    # 用的都是同一套私钥。生产环境或对外提供服务，请务必安装 openssl
    # 让上面的分支生成你自己独有的证书，不要依赖这段兜底。
    log.warning(
        "[警告] 系统缺少 openssl，将使用源码内置的共享测试证书"
        "（私钥已公开，仅供个人测试，请勿用于生产/对外服务）"
    )
    key_path.write_text(FALLBACK_PRIVATE_KEY)
    cert_path.write_text(FALLBACK_CERT)
    secure_file_permissions(key_path)
    return str(key_path), str(cert_path)


# ──────────────────────────────────────────────
# 下载 sing-box
# ──────────────────────────────────────────────
def detect_arch() -> str:
    return ARCH_MAP.get(platform.machine(), "amd64")


def _extract_tar_stripped(tar_path: str, dest_dir: Path):
    """等价于 tar --strip-components=1：把包内第一层目录剥掉再解压。"""
    with tarfile.open(tar_path) as tar:
        members = []
        for m in tar.getmembers():
            parts = m.name.split("/", 1)
            if len(parts) == 2 and parts[1]:
                m.name = parts[1]
                members.append(m)
        tar.extractall(dest_dir, members=members)


def download_singbox() -> str:
    if SB_BIN_PATH.exists():
        os.chmod(SB_BIN_PATH, SB_BIN_PATH.stat().st_mode | stat.S_IEXEC)
        return str(SB_BIN_PATH)

    arch = detect_arch()
    log.info("正在获取 sing-box 最新版本 (linux-%s)...", arch)

    # 兜底版本必须 >= 1.12.0，否则 AnyTLS 协议类型无法被识别，
    # sing-box 会在配置校验阶段整体拒绝启动（影响全部协议，不仅是 AnyTLS）
    version = "v1.12.0"
    try:
        data = _http_get_text("https://api.github.com/repos/SagerNet/sing-box/releases")
        if data:
            releases = json.loads(data)
            stable = next((r for r in releases if not r.get("prerelease") and not r.get("draft")), None)
            if stable and stable.get("tag_name"):
                version = stable["tag_name"]
    except Exception:
        pass

    log.info("sing-box 版本: %s", version)
    ver_num = version.lstrip("v")
    tar_name = f"sing-box-{ver_num}-linux-{arch}.tar.gz"
    url = f"https://github.com/SagerNet/sing-box/releases/download/{version}/{tar_name}"

    SB_DIR.mkdir(parents=True, exist_ok=True)
    tar_path = HOME / "sb.tar.gz"
    log.info("正在下载 sing-box...")
    download(url, str(tar_path))

    _extract_tar_stripped(str(tar_path), SB_DIR)
    os.chmod(SB_BIN_PATH, SB_BIN_PATH.stat().st_mode | stat.S_IEXEC)
    tar_path.unlink(missing_ok=True)
    log.info("sing-box 下载完成")
    return str(SB_BIN_PATH)


# ──────────────────────────────────────────────
# 下载 cloudflared
# ──────────────────────────────────────────────
def download_cloudflared() -> str:
    if CLOUDFLARED_BIN.exists():
        os.chmod(CLOUDFLARED_BIN, CLOUDFLARED_BIN.stat().st_mode | stat.S_IEXEC)
        return str(CLOUDFLARED_BIN)

    suffix = CF_ARCH_MAP.get(detect_arch(), "linux-amd64")
    log.info("正在下载 cloudflared (%s)...", suffix)
    url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-{suffix}"
    download(url, str(CLOUDFLARED_BIN))
    os.chmod(CLOUDFLARED_BIN, CLOUDFLARED_BIN.stat().st_mode | stat.S_IEXEC)
    log.info("cloudflared 下载完成")
    return str(CLOUDFLARED_BIN)


# ──────────────────────────────────────────────
# Argo 隧道
# ──────────────────────────────────────────────
def start_argo_tunnel(cf_bin: str, argo_port: int, argo_domain: str, argo_auth: str) -> str:
    if argo_domain and argo_auth:
        log.info("启动固定 Argo 隧道...")
        DATA_DIR / "cloudflared.log"
        log_fd = open(cf_log_file, "a")
        proc = subprocess.Popen(
            [cf_bin, "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "run", "--token", argo_auth],
            stdout=log_fd, stderr=log_fd,
        )

        # cloudflared 因 token 无效/域名未绑定等原因失败时，通常几秒内就会退出。
        # 这里等待期间轮询进程状态，提前退出就如实报错，而不是无脑当作成功。
        check_interval = 0.5
        waited = 0.0
        while waited < 3.0:
            if proc.poll() is not None:
                log_fd.close()
                log.error("================ 固定 Argo 隧道启动失败 ================")
                log.error("cloudflared 进程已退出（退出码 %s），详细日志见 %s", proc.returncode, cf_log_file)
                try:
                    tail = cf_log_file.read_text()[-2000:]
                    log.error(tail.strip())
                except OSError:
                    pass
                log.error("==========================================================")
                log.error("常见原因：ARGO_AUTH token 无效/过期，或 ARGO_DOMAIN 未在 Cloudflare 面板绑定成功")
                return ""
            time.sleep(check_interval)
            waited += check_interval

        log.info("固定 Argo 隧道进程存活，日志见 %s", cf_log_file)
        return argo_domain

    log.info("启动临时 Argo 隧道...")
    proc = subprocess.Popen(
        [cf_bin, "tunnel", "--edge-ip-version", "auto", "--no-autoupdate",
         "--url", f"http://127.0.0.1:{argo_port}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1,
    )
    result = {"host": ""}
    done = threading.Event()
    pattern = re.compile(r"https://([a-z0-9-]+\.trycloudflare\.com)")

    def _read_stderr():
        # 注意：拿到域名后不能 break/close 管道。cloudflared 进程会持续往 stderr
        # 写心跳日志，一旦管道读端被关闭，它下次写入会收到 SIGPIPE 而被杀死，
        # 隧道随之断开（域名已经打印出来，看起来"成功"了，实际已经不通）。
        # 这里让循环一直跑到进程自己退出为止，持续把日志读掉（不处理也要读），
        # 保持管道通畅，等价于 Node 版 `cf.stderr.on('data', ...)` 一直挂着监听的效果。
        for line in iter(proc.stderr.readline, ""):
            m = pattern.search(line)
            if m and not result["host"]:
                result["host"] = m.group(1)
                log.info("临时隧道域名: %s", result["host"])
                done.set()
        proc.stderr.close()

    threading.Thread(target=_read_stderr, daemon=True).start()
    if not done.wait(timeout=30):
        log.info("临时隧道域名获取超时")
    return result["host"]


# ──────────────────────────────────────────────
# 获取公网 IP
# ──────────────────────────────────────────────
def get_public_ip() -> str:
    return _http_get_text("https://ipinfo.io/ip") or _http_get_text("https://ifconfig.co/ip") or ""


# ──────────────────────────────────────────────
# HTTP / WebSocket 转发（原样对应 Node 版的两个 server）
#   argoServer: 只处理 upgrade 请求，转发给 sing-box 对应的内部端口
#   server：伪装页 + 订阅，独立监听 INBOUND_PORT
# ──────────────────────────────────────────────
def _pipe(src: socket.socket, dst: socket.socket):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _recv_headers(sock: socket.socket, max_size: int = 65536) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_size:
            break
    return buf


def _parse_headers(header_part: bytes) -> dict:
    headers = {}
    for line in header_part.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        try:
            headers[k.strip().lower().decode()] = v.strip().decode()
        except UnicodeDecodeError:
            continue
    return headers


def _is_websocket_upgrade(headers: dict) -> bool:
    """等价于 Node http 模块只在真实 upgrade 请求时才触发 'upgrade' 事件的行为。"""
    connection_tokens = {t.strip().lower() for t in headers.get("connection", "").split(",")}
    return "upgrade" in connection_tokens and headers.get("upgrade", "").strip().lower() == "websocket"


def _forward_raw(client_sock: socket.socket, header_part: bytes, rest: bytes, target_port: int):
    client_sock.settimeout(None)
    try:
        upstream = socket.create_connection(("127.0.0.1", target_port), timeout=5)
    except OSError as e:
        log.debug("failed to connect upstream sing-box port %s: %s", target_port, e)
        client_sock.close()
        return

    upstream.sendall(header_part + b"\r\n\r\n" + rest)
    t1 = threading.Thread(target=_pipe, args=(client_sock, upstream), daemon=True)
    t2 = threading.Thread(target=_pipe, args=(upstream, client_sock), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    client_sock.close()
    upstream.close()


def _send_bad_request(client_sock: socket.socket):
    body = b"Bad Request"
    resp = (
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    try:
        client_sock.sendall(resp)
    except OSError:
        pass
    client_sock.close()


def run_argo_forward_server(port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)
    log.info("Argo 转发服务启动，端口 %s", port)

    def handle(client_sock: socket.socket):
        try:
            client_sock.settimeout(10)
            buf = _recv_headers(client_sock)
            if b"\r\n\r\n" not in buf:
                client_sock.close()
                return
            header_part, _, rest = buf.partition(b"\r\n\r\n")
            request_line = header_part.split(b"\r\n", 1)[0].decode(errors="ignore")
            try:
                _, path, _ = request_line.split(" ", 2)
            except ValueError:
                client_sock.close()
                return
            path = path.split("?")[0]
            target_port = PATH_TO_PORT.get(path)
            headers = _parse_headers(header_part)
            if target_port is None or not _is_websocket_upgrade(headers):
                _send_bad_request(client_sock)
                return
            _forward_raw(client_sock, header_part, rest, target_port)
        except Exception as e:
            log.debug("argo forward error: %s", e)
            client_sock.close()

    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


def _load_index_html() -> str:
    p = Path.cwd() / "index.html"
    if p.exists():
        try:
            return p.read_text(encoding="utf-8")
        except Exception as e:
            log.warning("failed to read index.html: %s", e)
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Welcome</title></head>'
        "<body><h1>Hello World</h1></body></html>"
    )


def run_public_server(port: int, sub_path: str, index_html: str, sub_holder: dict):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(128)
    log.info("HTTP 服务启动，端口 %s", port)

    def handle(client_sock: socket.socket):
        try:
            client_sock.settimeout(10)
            buf = _recv_headers(client_sock)
            if b"\r\n\r\n" not in buf:
                client_sock.close()
                return
            header_part, _, _ = buf.partition(b"\r\n\r\n")
            request_line = header_part.split(b"\r\n", 1)[0].decode(errors="ignore")
            try:
                _, path, _ = request_line.split(" ", 2)
            except ValueError:
                client_sock.close()
                return
            path = path.split("?")[0]

            if path == sub_path:
                body = sub_holder.get("content", "").encode()
                headers = (
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode()
            else:
                body = index_html.encode("utf-8")
                headers = (
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode()

            client_sock.sendall(headers + body)
            client_sock.close()
        except Exception as e:
            log.debug("public server error: %s", e)
            client_sock.close()

    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────
def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    disable_argo = (CONF_DISABLE_ARGO or os.environ.get("DISABLE_ARGO", "")) == "true"

    # UUID
    env_uuid = CONF_UUID or os.environ.get("UUID", "")
    if env_uuid:
        node_uuid = env_uuid
        UUID_FILE.write_text(node_uuid)
    elif UUID_FILE.exists():
        node_uuid = UUID_FILE.read_text().strip()
    else:
        node_uuid = str(uuid.uuid4())
        UUID_FILE.write_text(node_uuid)
    secure_file_permissions(UUID_FILE)

    trojan_pass = node_uuid
    ss_pass = derive_ss_password(node_uuid)

    # 对外端口（伪装页 + 订阅）
    port_env = CONF_PORT or os.environ.get("PORT", "")
    inbound_port = int(port_env) if port_env else get_free_port()

    sub_raw = CONF_SUB or os.environ.get("SUB", "sub")
    sub_path = "/" + sub_raw.lstrip("/")

    argo_domain = CONF_ARGO_DOMAIN or os.environ.get("ARGO_DOMAIN", "")
    argo_auth = CONF_ARGO_AUTH or os.environ.get("ARGO_AUTH", "")

    if argo_domain and argo_auth:
        argo_port = int(CONF_ARGO_PORT or os.environ.get("ARGO_PORT", "8001"))
    else:
        argo_port = get_free_port()

    # 可选协议端口
    hy2_port = int(CONF_HY2_PORT or os.environ.get("HY2_PORT", "") or 0)
    tuic_port = int(CONF_TUIC_PORT or os.environ.get("TUIC_PORT", "") or 0)
    reality_port = int(CONF_REALITY_PORT or os.environ.get("REALITY_PORT", "") or 0)
    ss_port = int(CONF_SS_PORT or os.environ.get("SS_PORT", "") or 0)
    s5_port = int(CONF_S5_PORT or os.environ.get("S5_PORT", "") or 0)
    anytls_port = int(CONF_ANYTLS_PORT or os.environ.get("ANYTLS_PORT", "") or 0)

    reality_domain = CONF_REALITY_DOMAIN or os.environ.get("REALITY_DOMAIN", "") or "www.iij.ad.jp"

    # 节点名称
    country = _http_get_text("https://ipinfo.io/country") or _http_get_text("https://ifconfig.co/country-iso")
    name = CONF_NAME or os.environ.get("NAME", "")
    if not name:
        asn_org = _http_get_text("https://ipinfo.io/org") or _http_get_text("https://ifconfig.co/org")
        if asn_org:
            asn_org = re.sub(r"^AS\d+\s+", "", asn_org)
            asn_org = re.sub(r",?\s*Inc\.?$", "", asn_org)
            asn_org = re.sub(r",?\s*LLC\.?", "", asn_org)
            asn_org = re.sub(r",?\s*Ltd\.?", "", asn_org)
            asn_org = re.sub(r",?\s*Corp\.?", "", asn_org)
            asn_org = asn_org.strip()[:20]
        name = f"{country}-{asn_org}" if country and asn_org else (f"{country}-sb" if country else "sb")

    # 公网 IP（可选协议订阅需要）
    public_ip = get_public_ip() if (hy2_port or tuic_port or reality_port or ss_port or s5_port or anytls_port) else ""

    # ── sing-box 配置：Argo 三协议 ──
    inbounds = [] if disable_argo else [
        {
            "type": "vmess", "tag": "vmess-in", "listen": "127.0.0.1", "listen_port": V_VMESS_PORT,
            "users": [{"uuid": node_uuid, "alterId": 0}],
            "transport": {"type": "ws", "path": WS_PATH_VMESS},
        },
        {
            "type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": V_VLESS_PORT,
            "users": [{"uuid": node_uuid, "flow": ""}],
            "transport": {"type": "ws", "path": WS_PATH_VLESS},
        },
        {
            "type": "trojan", "tag": "trojan-in", "listen": "127.0.0.1", "listen_port": V_TROJAN_PORT,
            "users": [{"password": trojan_pass}],
            "transport": {"type": "ws", "path": WS_PATH_TROJAN},
        },
    ]

    # ── 先下载/找到 sing-box，Reality 密钥生成依赖它 ──
    sb_bin = ""
    if SB_BIN_PATH.exists():
        os.chmod(SB_BIN_PATH, SB_BIN_PATH.stat().st_mode | stat.S_IEXEC)
        sb_bin = str(SB_BIN_PATH)
    else:
        for candidate in ("/usr/local/bin/sing-box", "/usr/bin/sing-box"):
            if Path(candidate).exists():
                sb_bin = candidate
                break
    if not sb_bin:
        sb_bin = download_singbox()

    # ── 端口唯一性检测：预先占位已被脚本自身占用的端口，
    #    这样可选协议如果撞上 PORT/ARGO_PORT/Argo 内部端口，也能被查出来 ──
    used_ports = set()
    used_ports.add(f"tcp:{inbound_port}")
    used_ports.add(f"tcp:{argo_port}")
    if not disable_argo:
        used_ports.add(f"tcp:{V_VMESS_PORT}")
        used_ports.add(f"tcp:{V_VLESS_PORT}")
        used_ports.add(f"tcp:{V_TROJAN_PORT}")

    def port_ok(p: int, proto: str) -> bool:
        if not p or p < 1 or p > 65535:
            return False
        key = f"{proto}:{p}"
        if key in used_ports:
            return False
        used_ports.add(key)
        return True

    hy2_active = port_ok(hy2_port, "udp")
    tuic_active = port_ok(tuic_port, "udp")
    reality_active = port_ok(reality_port, "tcp")
    ss_active = port_ok(ss_port, "tcp")
    s5_active = port_ok(s5_port, "tcp")
    anytls_active = port_ok(anytls_port, "tcp")

    if hy2_port and not hy2_active:
        log.warning("HY2_PORT(%s) 端口冲突或无效，Hysteria2 已跳过", hy2_port)
    if tuic_port and not tuic_active:
        log.warning("TUIC_PORT(%s) 端口冲突或无效，TUIC 已跳过", tuic_port)
    if reality_port and not reality_active:
        log.warning("REALITY_PORT(%s) 端口冲突或无效，Reality 已跳过", reality_port)
    if ss_port and not ss_active:
        log.warning("SS_PORT(%s) 端口冲突或无效，Shadowsocks 已跳过", ss_port)
    if s5_port and not s5_active:
        log.warning("S5_PORT(%s) 端口冲突或无效，Socks5 已跳过", s5_port)
    if anytls_port and not anytls_active:
        log.warning("ANYTLS_PORT(%s) 端口冲突或无效，AnyTLS 已跳过", anytls_port)

    # 自签证书（Hysteria2 / TUIC / AnyTLS 需要）
    # 证书生成失败只影响这三个依赖证书的协议，不应让整个脚本崩溃退出
    cert_path = key_path = ""
    cert_ready = False
    if hy2_active or tuic_active or anytls_active:
        try:
            key_path, cert_path = generate_self_signed_cert(DATA_DIR / "certs")
            cert_ready = True
        except Exception as e:
            log.error("证书生成失败，Hysteria2/TUIC/AnyTLS 将被跳过: %s", e)
            cert_ready = False
    if not cert_ready:
        if hy2_active:
            log.warning("因证书不可用，Hysteria2 已跳过")
        if tuic_active:
            log.warning("因证书不可用，TUIC 已跳过")
        if anytls_active:
            log.warning("因证书不可用，AnyTLS 已跳过")

    hy2_final = hy2_active and cert_ready
    tuic_final = tuic_active and cert_ready
    anytls_final = anytls_active and cert_ready

    # Hysteria2（可选，UDP）
    if hy2_final:
        log.info("启用 Hysteria2，端口 %s", hy2_port)
        inbounds.append({
            "type": "hysteria2", "tag": "hy2-in", "listen": "::", "listen_port": hy2_port,
            "users": [{"password": node_uuid}], "masquerade": "https://bing.com",
            "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": cert_path, "key_path": key_path},
        })

    # TUIC v5（可选，UDP）
    if tuic_final:
        log.info("启用 TUIC v5，端口 %s", tuic_port)
        inbounds.append({
            "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": tuic_port,
            "users": [{"uuid": node_uuid, "password": node_uuid}], "congestion_control": "bbr",
            "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": cert_path, "key_path": key_path},
        })

    # VLESS Reality（可选，TCP）
    reality_pub_key = ""
    if reality_active:
        log.info("启用 VLESS Reality，端口 %s", reality_port)
        reality_key_file = DATA_DIR / "reality-keys.json"
        reality_priv_key = ""

        if reality_key_file.exists():
            try:
                saved = json.loads(reality_key_file.read_text())
                if saved.get("privKey") and saved.get("pubKey"):
                    reality_priv_key = saved["privKey"]
                    reality_pub_key = saved["pubKey"]
                    log.info("已从文件读取 Reality 密钥对")
                else:
                    raise ValueError("密钥文件字段不完整")
            except Exception as e:
                log.warning("reality-keys.json 读取失败（%s），重新生成...", e)
                try:
                    reality_key_file.unlink()
                except OSError:
                    pass

        if not reality_priv_key or not reality_pub_key:
            try:
                key_out = subprocess.run(
                    [sb_bin, "generate", "reality-keypair"],
                    check=True, capture_output=True, text=True,
                ).stdout
                priv_match = re.search(r"PrivateKey:\s*(\S+)", key_out)
                pub_match = re.search(r"PublicKey:\s*(\S+)", key_out)
                if priv_match and pub_match:
                    reality_priv_key = priv_match.group(1)
                    reality_pub_key = pub_match.group(1)
                    reality_key_file.write_text(json.dumps({
                        "privKey": reality_priv_key, "pubKey": reality_pub_key,
                    }))
                    secure_file_permissions(reality_key_file)
                    log.info("Reality 密钥对生成并保存成功")
                else:
                    raise ValueError("密钥输出格式异常")
            except Exception as e:
                log.error("Reality 密钥生成失败: %s", e)

        # 密钥没拿到就不要塞一个 private_key 为空的 inbound 指望 sing-box check 兜底，
        # 直接跳过这个协议，效果上和其它协议"依赖资源不可用则整体跳过"保持一致
        if not reality_priv_key or not reality_pub_key:
            log.warning("因密钥不可用，VLESS Reality 已跳过")
            reality_active = False
        else:
            inbounds.append({
                "type": "vless", "tag": "reality-in", "listen": "::", "listen_port": reality_port,
                "users": [{"uuid": node_uuid, "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": True, "server_name": reality_domain,
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": reality_domain, "server_port": 443},
                        "private_key": reality_priv_key, "short_id": [""],
                    },
                },
            })

    # Shadowsocks 2022（可选，TCP）
    if ss_active:
        log.info("启用 Shadowsocks 2022，端口 %s", ss_port)
        inbounds.append({
            "type": "shadowsocks", "tag": "ss-in", "listen": "::", "listen_port": ss_port,
            "network": "tcp", "method": "2022-blake3-aes-128-gcm", "password": ss_pass,
        })

    # Socks5（可选，TCP）
    if s5_active:
        log.info("启用 Socks5，端口 %s", s5_port)
        inbounds.append({
            "type": "socks", "tag": "s5-in", "listen": "::", "listen_port": s5_port,
            "users": [{"username": node_uuid[:8], "password": node_uuid[-12:]}],
        })

    # AnyTLS（可选，TCP）
    if anytls_final:
        log.info("启用 AnyTLS，端口 %s", anytls_port)
        inbounds.append({
            "type": "anytls", "tag": "anytls-in", "listen": "::", "listen_port": anytls_port,
            "users": [{"password": node_uuid}],
            "tls": {"enabled": True, "certificate_path": cert_path, "key_path": key_path},
        })

    config = {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2))

    # 打印实际拿到的 sing-box 版本，方便排查"协议不支持"类问题
    try:
        ver_out = subprocess.run([sb_bin, "version"], capture_output=True, text=True, check=True).stdout
        log.info("sing-box 版本信息:\n%s", ver_out.strip())
    except Exception as e:
        log.warning("无法获取 sing-box 版本信息: %s", e)

    # 启动前先做一次配置校验。sing-box 对配置文件是整体原子校验的——
    # 任何一个 inbound 类型不被当前版本识别，都会导致进程拒绝启动，
    # 进而连累所有协议（包括 Argo 转发依赖的 vmess/vless/trojan）。
    # 提前 check 可以在真正启动前就发现问题，并把错误打印出来，
    # 而不是让 sing-box 静默崩溃、什么日志都看不到。
    sb_log_file = SB_DIR / "run.log"
    sb_start_failed = False
    try:
        subprocess.run(
            [sb_bin, "check", "-c", str(CONFIG_FILE)],
            check=True, capture_output=True, text=True,
        )
        log.info("sing-box 配置校验通过")
    except subprocess.CalledProcessError as e:
        detail = (e.stdout or "") + (e.stderr or "")
        log.error("================ sing-box 配置校验失败 ================")
        log.error(detail.strip())
        log.error("========================================================")
        log.error(
            "常见原因：当前 sing-box 版本过旧，不支持某个已启用的协议类型"
            "（例如 AnyTLS 需要 sing-box >= 1.12.0）。"
            "请删除本地 sing-box 二进制后重新运行脚本以下载最新版本，"
            "或关闭对应协议端口变量后重试。"
        )
        sb_log_file.write_text(f"[CONFIG CHECK FAILED]\n{detail}\n")
        log.info("详细日志已写入: %s", sb_log_file)
        log.info("配置校验未通过，跳过启动 sing-box（Argo/HTTP订阅服务仍会继续运行）。")
        sb_start_failed = True

    try:
        subprocess.run(["pkill", "-f", str(SB_BIN_PATH)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    time.sleep(0.8)

    sb_proc = None
    if not sb_start_failed:
        # 不再用 DEVNULL 丢弃输出，改为写入日志文件，这样在翼龙/Pterodactyl
        # 等只能看面板日志的环境下，sing-box 启动失败时也能看到具体报错原因。
        log_fd = open(sb_log_file, "a")
        sb_env = os.environ.copy()
        sb_env.pop("PORT", None)
        sb_proc = subprocess.Popen(
            [sb_bin, "run", "-c", str(CONFIG_FILE)],
            stdout=log_fd, stderr=log_fd, env=sb_env, start_new_session=True,
        )
        log.info("sing-box 已在后台启动，PID: %s", sb_proc.pid)
        log.info("运行日志: %s", sb_log_file)

    time.sleep(1.5)

    # ── Argo 三协议 WS 转发（仅本地）──
    if not disable_argo:
        threading.Thread(target=run_argo_forward_server, args=(argo_port,), daemon=True).start()

    # ── HTTP 服务（伪装页 + 订阅）──
    index_html = _load_index_html()
    sub_holder = {"content": ""}
    threading.Thread(
        target=run_public_server, args=(inbound_port, sub_path, index_html, sub_holder), daemon=True,
    ).start()

    # ── 启动 cloudflared ──
    host = "your-domain.com"
    if not disable_argo:
        cf_bin = download_cloudflared()
        argo_host = start_argo_tunnel(cf_bin, argo_port, argo_domain, argo_auth)
        host = argo_host or "your-domain.com"
    else:
        log.info("Argo 隧道已禁用，跳过 cloudflared")

    # ── 生成订阅链接 ──
    links = []

    if not disable_argo:
        vmess_obj = {
            "v": "2", "ps": name, "add": CF_PREFER_HOST, "port": "443",
            "id": node_uuid, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
            "host": host, "path": WS_PATH_VMESS, "tls": "tls", "sni": host,
        }
        links.append("vmess://" + base64.b64encode(json.dumps(vmess_obj).encode()).decode())

        links.append(
            f"vless://{node_uuid}@{CF_PREFER_HOST}:443"
            f"?encryption=none&security=tls&sni={host}&type=ws&host={host}"
            f"&path={urllib.parse.quote(WS_PATH_VLESS)}#{urllib.parse.quote(name)}"
        )

        links.append(
            f"trojan://{trojan_pass}@{CF_PREFER_HOST}:443"
            f"?security=tls&sni={host}&type=ws&host={host}"
            f"&path={urllib.parse.quote(WS_PATH_TROJAN)}#{urllib.parse.quote(name)}"
        )

    if hy2_final and public_ip:
        links.append(
            f"hysteria2://{node_uuid}@{public_ip}:{hy2_port}"
            f"?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#{urllib.parse.quote(name)}"
        )

    if tuic_final and public_ip:
        links.append(
            f"tuic://{node_uuid}:{node_uuid}@{public_ip}:{tuic_port}"
            f"?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1"
            f"#{urllib.parse.quote(name)}"
        )

    if reality_active and public_ip and reality_pub_key:
        links.append(
            f"vless://{node_uuid}@{public_ip}:{reality_port}"
            f"?encryption=none&flow=xtls-rprx-vision&security=reality"
            f"&sni={reality_domain}&fp=firefox&pbk={reality_pub_key}"
            f"&type=tcp&headerType=none#{urllib.parse.quote(name)}"
        )

    if ss_active and public_ip:
        ss_user_info = base64.b64encode(f"2022-blake3-aes-128-gcm:{ss_pass}".encode()).decode()
        links.append(f"ss://{ss_user_info}@{public_ip}:{ss_port}#{urllib.parse.quote(name)}")

    if s5_active and public_ip:
        s5_user_info = base64.b64encode(f"{node_uuid[:8]}:{node_uuid[-12:]}".encode()).decode()
        links.append(f"socks://{s5_user_info}@{public_ip}:{s5_port}#{urllib.parse.quote(name)}")

    if anytls_final and public_ip:
        links.append(
            f"anytls://{node_uuid}@{public_ip}:{anytls_port}"
            f"?security=tls&sni=www.bing.com&fp=chrome&insecure=1&allowInsecure=1#{urllib.parse.quote(name)}"
        )

    sub_b64 = base64.b64encode("\n".join(links).encode()).decode()
    sub_holder["content"] = sub_b64
    sub_file = DATA_DIR / "sub.txt"
    sub_file.write_text(sub_b64)

    print("================= 订阅内容 =================")
    print(sub_b64)
    print("============================================")
    print(f"订阅地址: https://{host}{sub_path}")
    print(f"节点文件: {sub_file}")

    print("============== 已启用协议 ==============")
    if not disable_argo:
        print("✓ VMess  + WS + Argo TLS")
        print("✓ VLESS  + WS + Argo TLS")
        print("✓ Trojan + WS + Argo TLS")
    if hy2_final:
        print(f"✓ Hysteria2     端口 {hy2_port} (UDP)")
    if tuic_final:
        print(f"✓ TUIC v5       端口 {tuic_port} (UDP)")
    if reality_active:
        print(f"✓ VLESS Reality 端口 {reality_port}  PubKey: {reality_pub_key or '生成中'}")
    if ss_active:
        print(f"✓ Shadowsocks   端口 {ss_port} (TCP)  密码: {ss_pass}")
    if s5_active:
        print(f"✓ Socks5        端口 {s5_port} (TCP)  账号: {node_uuid[:8]}")
    if anytls_final:
        print(f"✓ AnyTLS        端口 {anytls_port} (TCP)")
    if disable_argo:
        print("✗ Argo 隧道已禁用")
    print(f"运行环境: linux-{detect_arch()}")
    print("========================================")

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log.info("shutting down")
        if sb_proc:
            sb_proc.terminate()


if __name__ == "__main__":
    main()
