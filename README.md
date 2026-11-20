# ha-certbot for Home Assistant

纯 Python 实现的 Home Assistant 自定义集成：用 certbot 官方的 `acme` 库走 ACME（RFC 8555）
的 dns-01 流程签发证书，用 `dns-lexicon` 操作各家 DNS 的 TXT 记录。

不需要 add-on、不需要 Supervisor、不需要 openssl 命令行，因此 **HA Container（docker）环境可以使用**。
最低目标版本为 **Home Assistant 2026.11.1**；实际签发仍需可用的 DNS API 凭据和网络。

## 特点

- **100+ DNS 服务商**：Cloudflare、阿里云、DNSPod、GoDaddy、deSEC、DuckDNS、HE、OVH……
  列表直接来自 dns-lexicon，配置界面里可搜索，也可以手动输入名称。
- **多个 CA**：Let's Encrypt（正式 / Staging）、ZeroSSL、Google Trust Services、SSL.com、Actalis，
  或者填任意自定义 ACME 目录地址。
- **EAB 支持**：ZeroSSL、Google Trust Services、SSL.com 必填；自定义 CA 可以选填完整的一对 EAB 凭据。
- **凭据更新**：条目菜单中的“重新配置”可更换 DNS / EAB 凭据，验证通过后自动重新加载。
- **密钥类型**：RSA 2048 / 3072 / 4096，EC P-256 / P-384。
- **通配符与多域名**：`example.com,*.example.com` 会作为同一张证书的 SAN 一起签发。
- **自动续期**：按剩余天数阈值 + 定时检查，续期成功后可自动调用指定服务（例如重启 HA）。
- **证书状态传感器**：到期时间、剩余天数、颁发者、序列号、证书路径。
- **等待 DNS 真正生效**：写入 TXT 后会向该域名的权威 NS 轮询确认，再提交 challenge，
  避免 CA 侧报 “incorrect TXT value”。

## 依赖

`manifest.json` 的 `requirements` 里钉死了版本，由 Home Assistant 在加载集成前自动安装：

- `acme==5.7.0`（certbot 官方 ACME 库，与 HA 2026.11.1 的 hass-nabucasa 依赖保持一致）
- `dns-lexicon==3.26.0`（DNS 操作，依赖 dnspython、tldextract 等）

条件是容器内可写 site-packages（root）且能访问 PyPI。容器重建后 HA 会自动重装，
那一刻同样需要能连 PyPI，否则集成会加载失败并在日志里报 `Unable to install package`。

## 安装

### HACS（推荐）

1. HACS → 集成 → 右上角 ⋮ → 自定义仓库
2. 仓库地址 `https://github.com/kylin7226/ha-certbot`，类别选 **集成**
3. 搜索 “ha-certbot” → 下载 → 重启 Home Assistant

### 手动

把 `custom_components/ha_certbot` 复制到 Home Assistant 配置目录下的 `custom_components/`，然后重启。

### 从旧名称升级

HA 内部标识与组件目录统一为 `ha_certbot`，显示名为 `ha-certbot`。
已配置旧版 `acme_cert` 的用户，先**禁用而不是删除旧条目**，更新代码并重启 HA。
添加 `ha-certbot` 时选择“导入旧 acme_cert 配置”，选择旧条目后会复制配置、DNS 凭据和续期选项。
可确认 CA 归属的账户和独立目录证书会复制到新目录；原条目、账户和证书不删除，也不覆盖已有新证书。
旧式共享证书和无法确认 CA 地址的自定义账户不会盲目导入，将重新签发；关闭自动续期的条目需手动调用签发服务。
确认新证书可用后，按传感器的新路径修改 HTTPS 配置，
并将自动化中的服务和事件名更新为 `ha_certbot.issue_certificate`、`ha_certbot_issued` 和 `ha_certbot_failed`。
HA 不支持通过公共接口直接修改配置条目的 domain，因此跨名称升级需要上述确认导入步骤。
ACME 是协议名称，`acme` 是 certbot 的依赖库名称，不属于需要改名的项目标识。

## 配置

1. **设置 → 设备与服务 → 添加集成 → ha-certbot**
2. 第一步填写：域名、ACME 服务器、账户邮箱、密钥长度、续期阈值、DNS 服务商
3. 第二步填写 DNS 服务商凭证：字段由所选服务商决定，页面上会列出每个字段的用途；
   提交时会真的调用一次服务商 API 校验凭证，凭证不对会直接报错而不是等到签发时才失败
4. 保存后会立即签发一次证书，之后每隔 `check_hours` 小时检查一次

内置 CA 只使用其内置地址；只有选择 Custom 时才使用自定义 HTTPS 地址。
同一主域名可以配置不同的 CA 地址，正式环境与 Staging 不会互相占用配置标识。

更换凭据时，在集成条目的菜单中选择“重新配置”。密钥字段不会回显，留空表示保留原值；
勾选“替换全部 DNS 凭据”会丢弃旧 DNS 凭据，仅保存此次输入的字段，可用于切换 Cloudflare 认证方式。
验证失败不会更改原配置；验证成功后重新加载条目，新任务使用新凭据。
若需更换 DNS 服务商、域名或 CA，请新增相应证书配置。

## 证书位置

优先使用 `/ssl`（HAOS / Supervised 的共享目录）；没有 `/ssl` 时（HA Container）使用
`<配置目录>/ssl`，一般就是 `/config/ssl`：

每个配置条目和 CA 使用独立目录：`ha_certbot/<entry_id>/<ca_id>/<domain>/current/`。
`ca_id` 由 ACME 目录 URL 生成，正式和 Staging 不会共用文件。

| 文件 | 说明 |
|------|------|
| `fullchain.pem` | 完整证书链，Home Assistant 的 `http:` 用这个 |
| `privkey.pem` | 私钥（创建时即为 0600） |
| `cert.pem` | 仅服务器证书 |
| `chain.pem` | 中间证书链 |

签发结果先写入独立的 `generation-*` 目录，检查私钥匹配、域名和有效期后，
一次切换 `current` 符号链接。写入失败不会覆盖原证书，之前的版本保留在同级目录中。
ACME 账户放在 `<配置目录>/ha_certbot/accounts/<ca_id>/<entry_id>/`，条目之间不共享账户文件。

在 `configuration.yaml` 中使用传感器属性 `certificate_path` 和 `key_path` 的实际值，例如：

```yaml
http:
  ssl_certificate: /config/ssl/ha_certbot/<entry_id>/<ca_id>/example.com/current/fullchain.pem
  ssl_key: /config/ssl/ha_certbot/<entry_id>/<ca_id>/example.com/current/privkey.pem
```

升级后原来的 `/config/ssl/<domain>.pem` 等根目录文件不会被覆盖，也不会继续更新。
请在新证书签发成功后，按传感器提供的新路径调整 HTTPS 配置；不要直接照抄上述占位符。

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

`ha_certbot.issue_certificate`

| 字段 | 必填 | 说明 |
|------|------|------|
| `config_entry_id` | 是 | 要签发证书的条目 |
| `force` | 否 | 重新生成私钥并强制申请，即使还没到续期时间 |

## 续期逻辑

- 每 `check_hours` 小时读取一次证书：剩余天数 ≤ `days` 时在后台自动签发（复用原私钥）
- 开启自动续期且证书不存在（`not_found`）、损坏或私钥/域名不匹配（`error`）时也会尝试签发
- 卸载条目时停止新任务，并等待正在运行的签发线程结束；DNS 传播等待可被中断
- 签发成功后调用 `reload_service`（例如 `homeassistant.restart`，让 HA 换上新证书）
- 事件：`ha_certbot_issued` / `ha_certbot_failed`

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

阿里云选择 `aliyun`，`auth_key_id` 填 RAM 用户的 AccessKey ID，`auth_secret` 填 AccessKey Secret。
该用户需要读取域名信息、查询、新增及删除目标域名 DNS 记录的权限；建议限制到需要签发的域名。
阿里云不需要额外的 SDK 或手动 pip 安装。集成修正了 Lexicon 3.26.0 的 UTC 时间戳，
并为阿里云、Cloudflare API 请求设置 30 秒网络超时。已覆盖离线签名、认证、TXT 创建与清理测试；
真实阿里云账户及 CA 签发仍需部署后验证，建议先使用 Staging。
创建前检查既有同名同值 TXT；只按记录 ID 清理本次新增且内容未改变的记录。
如果服务商无法列出新记录或返回稳定 ID，将明确报错并保留记录供人工检查，不进行无法确认归属的删除。

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

5. **账户注册信息丢失或损坏**
   保留 `account_key.pem`，重新执行签发即可。集成会使用原密钥查询并恢复已存在的账户注册信息。
   网络故障不会被当成账户失效而重复注册；已停用的账户会明确报错，需要向 CA 核实，不能靠删除文件恢复。

## 开发验证

使用 Python 3.14，在独立虚拟环境中运行：

```bash
python -m pip install -r requirements-test.txt
python -m pytest tests -q -p no:cacheprovider
```

测试禁止真实网络访问，覆盖签发、DNS 清理、凭据更新、配置迁移、表单序列化和任务生命周期。
GitHub Actions 运行回归测试，并另行安装 HA 2026.11.1 检查真实 HA 类与表单接口。
离线测试及 CI 接口检查不能替代真实 HA 配置页面、依赖安装和 DNS/CA 签发验收。

## 许可

集成本身为 MIT；依赖库各自遵循其许可（`acme` 为 Apache-2.0，`dns-lexicon` 为 MIT）。

## 致谢

- [certbot / acme](https://github.com/certbot/certbot) —— ACME 协议实现
- [dns-lexicon](https://github.com/AnalogJ/lexicon) —— 各家 DNS 的统一操作接口
- [acme.sh](https://github.com/acmesh-official/acme.sh) —— 功能范围的参考
