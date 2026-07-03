# py-sb

基于 python + [sing-box](https://github.com/SagerNet/sing-box) 的一键代理节点部署工具，支持 VMess / VLESS / Trojan + WebSocket + Argo 隧道，以及 Hysteria2 / TUIC v5 / VLESS Reality / Shadowsocks 2022。

---


## 部署方式

### Docker 部署

```bash
docker run -d --restart=always \
  -e UUID=your-uuid \
  -e ARGO_DOMAIN=your.domain \
  -e ARGO_AUTH="your-token" \
  -p 3000:3000 \
  ghcr.io/zaofengyue/py-sb:latest
```

启用可选协议（需开放对应端口）：

```bash
docker run -d --restart=always \
  -e UUID=your-uuid \
  -e ARGO_DOMAIN=your.domain \
  -e ARGO_AUTH="your-token" \
  -e HY2_PORT=8443 \
  -e TUIC_PORT=9443 \
  -e REALITY_PORT=7443 \
  -e SS_PORT=6443 \
  -p 3000:3000 \
  -p 8443:8443/udp \
  -p 9443:9443/udp \
  -p 7443:7443 \
  -p 6443:6443 \
  ghcr.io/zaofengyue/py-sb:latest
```

持久化 UUID 和 Reality 密钥：

```bash
docker run -d --restart=always \
  -e ARGO_DOMAIN=your.domain \
  -e ARGO_AUTH="your-token" \
  -v $HOME/py-sb-data:/root \
  -p 3000:3000 \
  ghcr.io/zaofengyue/py-sb:latest
```

---

### 源码部署（手动）

```bash
git clone https://github.com/zaofengyue/py-sb.git
cd py-sb && node index.js
```

---

## 环境变量

### 基础变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `UUID` | 节点 UUID，Trojan/Hysteria2/TUIC/Reality 密码同此 | 自动生成并持久化 |
| `PORT` | HTTP 服务对外端口（伪装页 + 订阅） | 自动分配 |
| `ARGO_PORT` | Argo 内部转发端口 | 固定隧道默认 8001，临时随机 |
| `NAME` | 节点名称前缀 | 自动识别 |
| `SUB` | 订阅路径 | `sub`（即 `/sub`） |
| `ARGO_DOMAIN` | 固定隧道域名 | 空则使用临时隧道 |
| `ARGO_AUTH` | 固定隧道 Token | 空则使用临时隧道 |

### 可选协议变量

| 变量 | 协议 | 说明 |
|------|------|------|
| `HY2_PORT` | Hysteria2 | 设置端口启用，需开放 UDP |
| `TUIC_PORT` | TUIC v5 | 设置端口启用，需开放 UDP |
| `REALITY_PORT` | VLESS Reality | 设置端口启用，需开放 TCP |
| `REALITY_DOMAIN` | VLESS Reality 伪装域名 | 默认 `www.iij.ad.jp` |
| `SS_PORT` | Shadowsocks 2022 | 设置端口启用，需开放 TCP |

> Hysteria2 / TUIC 使用自签证书，客户端需开启跳过证书验证。
> Reality 密钥对自动生成并持久化，重启后 PublicKey 不变。
> Shadowsocks 密码由 UUID 自动派生，加密方式 `2022-blake3-aes-128-gcm`。

---

## 伪装页

默认伪装页为简单 Hello World，将自定义 `index.html` 放入运行目录即可替换。

Docker 部署时挂载文件：

```bash
-v /your/path/index.html:/app/index.html
```

---



## License

MIT
