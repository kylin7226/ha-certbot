"""Constants for the ACME certificate integration."""
from __future__ import annotations

DOMAIN = "acme_cert"

CONF_DOMAINS = "domains"
CONF_EMAIL = "email"
CONF_ACME_SERVER = "acme_server"
CONF_ACME_SERVER_URL = "acme_server_url"
CONF_EAB_KID = "eab_kid"
CONF_EAB_HMAC_KEY = "eab_hmac_key"
CONF_KEYLENGTH = "keylength"
CONF_DAYS = "days"
CONF_DNS_PROVIDER = "dns_provider"
CONF_DNS_CREDENTIALS = "dns_credentials"
CONF_AUTO_RENEW = "auto_renew"
CONF_CHECK_HOURS = "check_hours"
CONF_PROPAGATION_TIMEOUT = "propagation_timeout"
CONF_PROPAGATION_INTERVAL = "propagation_interval"
CONF_RELOAD_SERVICE = "reload_service"

DEFAULT_KEYLENGTH = "ec-256"
DEFAULT_DAYS = 30
DEFAULT_AUTO_RENEW = True
DEFAULT_CHECK_HOURS = 6
DEFAULT_PROPAGATION_TIMEOUT = 180
DEFAULT_PROPAGATION_INTERVAL = 5
DEFAULT_ACME_SERVER = "letsencrypt"
DEFAULT_DNS_PROVIDER = "cloudflare"

CUSTOM_SERVER = "custom"

ACME_SERVERS: dict[str, str] = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt_test": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
    "googletest": "https://dv.acme-v02.test-api.pki.goog/directory",
    "sslcom_rsa": "https://acme.ssl.com/sslcom-dv-rsa",
    "sslcom_ecc": "https://acme.ssl.com/sslcom-dv-ecc",
    "actalis": "https://acme-api.actalis.com/acme/directory",
}

ACME_SERVER_LABELS: dict[str, str] = {
    "letsencrypt": "Let's Encrypt",
    "letsencrypt_test": "Let's Encrypt (Staging)",
    "zerossl": "ZeroSSL (EAB)",
    "google": "Google Trust Services (EAB)",
    "googletest": "Google Trust Services Test (EAB)",
    "sslcom_rsa": "SSL.com RSA (EAB)",
    "sslcom_ecc": "SSL.com ECC (EAB)",
    "actalis": "Actalis",
    CUSTOM_SERVER: "Custom directory URL",
}

EAB_REQUIRED_SERVERS = frozenset(
    {"zerossl", "google", "googletest", "sslcom_rsa", "sslcom_ecc"}
)

KEYLENGTH_OPTIONS = ("2048", "3072", "4096", "ec-256", "ec-384")

DATA_DIR_NAME = "acme_cert"
ACCOUNTS_DIR_NAME = "accounts"
LIVE_DIR_NAME = "live"
SSL_DIR_NAME = "ssl"

CERT_SUFFIX_FULLCHAIN = ".pem"
CERT_SUFFIX_KEY = "-key.pem"
CERT_SUFFIX_CERT = "-cert.pem"
CERT_SUFFIX_CA = "-ca.pem"

STATUS_VALID = "valid"
STATUS_RENEWAL_REQUIRED = "renewal_required"
STATUS_EXPIRED = "expired"
STATUS_NOT_FOUND = "not_found"
STATUS_ERROR = "error"

SERVICE_ISSUE = "issue_certificate"
ATTR_CONFIG_ENTRY_ID = "config_entry_id"
ATTR_FORCE = "force"

EVENT_ISSUED = f"{DOMAIN}_issued"
EVENT_FAILED = f"{DOMAIN}_failed"

USER_AGENT = "home-assistant-acme-cert/1.0"
NETWORK_TIMEOUT = 30
ORDER_TIMEOUT = 180
