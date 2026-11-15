# ACME SSL Certificate Manager for Home Assistant

纯 Python 实现的 Home Assistant 自定义集成：用 certbot 官方的 `acme` 库走 ACME（RFC 8555）
的 dns-01 流程签发证书，用 `dns-lexicon` 操作各家 DNS 的 TXT 记录。

不需要 add-on、不需要 Supervisor、不需要 openssl 命令行，因此 **HA Container（docker）环境可以直接用**。

## 特点

- **100+ DNS 服务商**：Cloudflare、阿里云、DNSPod、GoDaddy、deSEC、DuckDNS、HE、OVH……
  列表直接来自 dns-lexicon，配置界面里可搜索，也可以手动输入名称。
- **多个 CA**：Let's Encrypt（正式 / Staging）、ZeroSSL、Google Trust Services、SSL.com、Actalis，
  或者填任意自定义 ACME 目录地址。
- **EAB 支持**：ZeroSSL、Google Trust Services、SSL.com 需要 EAB 凭证，配置时会额外要求填写。
- **密钥类型**：RSA 2048 / 3072 / 4096，EC P-256 / P-384。
- **通配符与多域名**：`example.com,*.example.com` 会作为同一张证书的 SAN 一起签发。
- **自动续期**：按剩余天数阈值 + 定时检查，续期成功后可自动调用指定服务（例如重启 HA）。
- **证书状态传感器**：到期时间、剩余天数、颁发者、序列号、证书路径。
- **等待 DNS 真正生效**：写入 TXT 后会向该域名的权威 NS 轮询确认，再提交 challenge，
  避免 CA 侧报 “incorrect TXT value”。

## 依赖

`manifest.json` 的 `requirements` 里钉死了版本，由 Home Assistant 在加载集成前自动安装：

- `acme==5.10.0`（certbot 官方 ACME 库，依赖 josepy、PyOpenSSL、cryptography）
- `dns-lexicon==3.26.0`（DNS 操作，依赖 dnspython、tldextract 等）

条件是容器内可写 site-packages（root）且能访问 PyPI。容器重建后 HA 会自动重装，
那一刻同样需要能连 PyPI，否则集成会加载失败并在日志里报 `Unable to install package`。

## 安装

### HACS（推荐）

1. HACS → 集成 → 右上角 ⋮ → 自定义仓库
2. 仓库地址 `https://github.com/kylin7226/ha-acme-sh`，类别选 **集成**
3. 搜索 “ACME SSL Certificate Manager” → 下载 → 重启 Home Assistant

### 手动

把 `custom_components/acme_cert` 复制到 Home Assistant 配置目录下的 `custom_components/`，然后重启。

## 配置

1. **设置 → 设备与服务 → 添加集成 → ACME SSL Certificate Manager**
2. 第一步填写：域名、ACME 服务器、账户邮箱、密钥长度、续期阈值、DNS 服务商
3. 第二步填写 DNS 服务商凭证：字段由所选服务商决定，页面上会列出每个字段的用途；
   提交时会真的调用一次服务商 API 校验凭证，凭证不对会直接报错而不是等到签发时才失败
4. 保存后会立即签发一次证书，之后每隔 `check_hours` 小时检查一次

## 证书位置

优先使用 `/ssl`（HAOS / Supervised 的共享目录）；没有 `/ssl` 时（HA Container）使用
`<配置目录>/ssl`，一般就是 `/config/ssl`：

| 文件 | 说明 |
|------|------|
| `<domain>.pem` | 完整证书链，Home Assistant 的 `http:` 用这个 |
| `<domain>-key.pem` | 私钥（权限 0600） |
| `<domain>-cert.pem` | 仅服务器证书 |
| `<domain>-ca.pem` | 中间证书链 |

内部状态放在 `<配置目录>/acme_cert/`：

- `accounts/<ca>/account_key.pem`、`accounts/<ca>/registration.json`：ACME 账户密钥与注册信息
- `live/<domain>/privkey.pem`、`cert.pem`、`chain.pem`、`fullchain.pem`：证书与私钥的原始副本

在 `configuration.yaml` 中使用：

```yaml
http:
  ssl_certificate: /config/ssl/example.com.pem
  ssl_key: /config/ssl/example.com-key.pem
```

## 证书状态传感器

- 状态：`valid` / `renewal_required` / `expired` / `not_found` / `error`
- 属性：`domain`、`domains`、`expiry_date`、`days_remaining`、`issuer`、`serial_number`、
  `certificate_path`、`key_path`、`auto_renew`、`last_issued`、`last_error`

```yaml
automation:
  - alias: "SSL 证书即将到期"
    trigger:
      - platform: numeric_state
        entity_id: sensor.example_com_lets_encrypt_certificate
        attribute: days_remaining
        below: 15
    action:
      - service: notify.notify
        data:
          message: "SSL 证书将在 15 天内到期，请检查续期情况"
```

## 服务

`acme_cert.issue_certificate`

| 字段 | 必填 | 说明 |
|------|------|------|
| `config_entry_id` | 是 | 要签发证书的条目 |
| `force` | 否 | 重新生成私钥并强制申请，即使还没到续期时间 |

## 续期逻辑

- 每 `check_hours` 小时读取一次证书：剩余天数 ≤ `days` 时在后台自动签发（复用原私钥）
- 开启自动续期且证书不存在（`not_found`）时也会尝试签发
- 签发成功后调用 `reload_service`（例如 `homeassistant.restart`，让 HA 换上新证书）
- 事件：`acme_cert_issued` / `acme_cert_failed`

## DNS 服务商凭证示例

| 服务商 | provider 名称 | 凭证字段 |
|--------|---------------|----------|
| Cloudflare | `cloudflare` | `auth_token`（API Token）；或 `auth_username` + `auth_token`（Global API Key）；可选 `zone_id` |
| 阿里云 | `aliyun` | `auth_key_id` + `auth_secret` |
| DNSPod | `dnspod` | `auth_username`（API ID）+ `auth_token` |
| GoDaddy | `godaddy` | `auth_key` + `auth_secret` |
| Hurricane Electric | `henet` | `auth_username` + `auth_password` |
| deSEC | `desec` | `auth_token` |
| DuckDNS | `duckdns` | `auth_token` |

注意：部分服务商在 dns-lexicon 里需要额外的 Python 包（extra），例如 `route53` 需要 `boto3`、
`qcloud` 需要 `tencentcloud-sdk-python`。Home Assistant 只会安装 `requirements` 里列出的包，
不会安装 extra，这类服务商需要你在容器内自行安装对应依赖后才能使用。

## 常见问题

1. **集成加载失败，日志里有 `Unable to install package`**
   容器访问不了 PyPI。解决出网问题后重启 HA，依赖会自动装上。

2. **配置第二步报 “DNS 服务商拒绝了这些凭证”**
   凭证错误，或该凭证权限不足（例如 Cloudflare API Token 需要 `Zone → DNS → Edit`）。

3. **签发报 TXT 记录未生效**
   调大选项里的 `propagation_timeout`（默认 180 秒）。

4. **调试阶段频繁失败**
   先把 ACME 服务器选成 `Let's Encrypt (Staging)`，避免撞上正式环境的速率限制。

5. **CA 拒绝已保存的账户**
   删除 `<配置目录>/acme_cert/accounts/<ca>/registration.json` 后重启 HA，
   集成会用同一个账户密钥重新注册。

## 许可

集成本身为 MIT；依赖库各自遵循其许可（`acme` 为 Apache-2.0，`dns-lexicon` 为 MIT）。

## 致谢

- [certbot / acme](https://github.com/certbot/certbot) —— ACME 协议实现
- [dns-lexicon](https://github.com/AnalogJ/lexicon) —— 各家 DNS 的统一操作接口
- [acme.sh](https://github.com/acmesh-official/acme.sh) —— 功能范围的参考
