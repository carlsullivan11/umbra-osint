from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

AuthBasis = Literal[
    "own_asset",
    "client_engagement",
    "public_cti",
    "training_lab",
    "other",
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="UMBRA_",
        env_file=".env",
        extra="ignore",
    )

    data_dir: Path = Field(default_factory=lambda: Path.home() / "umbra" / "data")
    db_filename: str = "umbra.db"
    # When set (postgresql://…), preferred over SQLite. Env: UMBRA_DATABASE_URL
    database_url: str | None = None
    user_agent: str = (
        "UmbraOSINT/0.2 (https://umbra-osint.com; security@umbra-osint.com)"
    )
    default_depth: int = 2
    default_max_entities: int = 500
    request_timeout_s: float = 20.0
    # Phase B4 / S1 — bound slow collectors so a hung upstream cannot occupy a
    # worker forever. 0 disables the limit (deliberate opt-out).
    collector_timeout_s: float = 45.0
    # Wall-clock ceiling for one orchestrator run. Many individually-tolerable
    # collectors must still not add up to an unbounded job.
    job_max_seconds: float = 1800.0
    allow_person_entity: bool = False
    github_token: str | None = None
    hibp_api_key: str | None = None
    hibp_user_agent: str = "Umbra-BreachCheck/0.1 (authorized self-monitoring)"
    # Reputation / threat-intel. All optional — reputation collectors work with
    # zero keys via key-free sources (Spamhaus DNSBL, abuse.ch feeds).
    abuseipdb_api_key: str | None = None
    # abuse.ch added API auth in 2024; URLhaus queries now need a free Auth-Key
    # from auth.abuse.ch. Key-free domain sources (Spamhaus DBL, OpenPhish feed)
    # still give a usable verdict without it.
    abusech_auth_key: str | None = None
    reputation_feed_ttl_s: float = 21600.0  # 6h cache for downloadable blocklists

    # DNS resolver (Phase 1). Primary resolver for collectors that do DNS/DNSBL
    # lookups. Set to an IP (e.g. "127.0.0.1") or a hostname resolvable to one
    # (e.g. "unbound" inside Docker). IMPORTANT: DNSBLs (Spamhaus) refuse queries
    # from public resolvers like 1.1.1.1, so for reputation to work this should
    # point at a *local recursive* resolver. See docs/DNS-SERVICE.md.
    dns_resolver: str | None = None

    # Dark-web / exposure monitoring (passive, defensive — docs/ETHICS.md).
    ransomwarelive_api_key: str | None = None
    dehashed_api_key: str | None = None
    dehashed_username: str | None = None
    intelx_api_key: str | None = None
    darkweb_feed_ttl_s: float = 3600.0  # 1h cache for exposure feeds

    # Optional: TronGrid serves address history key-free and a key only
    # raises the rate limit.
    trongrid_api_key: str | None = None

    # Free key from https://api.data.gov/signup/ . Without it the FTC index
    # simply stays empty and every phone page says it was not checked — which is
    # the honest rendering, not a silent zero.
    ftc_api_key: str | None = None

    # Optional WiGLE (https://api.wigle.net/). Without it wifi_maps is portal-only.
    wigle_api_name: str | None = None
    wigle_api_token: str | None = None

    # Case retention. 0 = keep everything, which is the only safe default for a
    # library: a self-hoster upgrading Umbra must not silently lose last
    # quarter's work to a window they never chose. The hosted service sets
    # UMBRA_CASE_RETENTION_DAYS and says so in docs/legal/PRIVACY.md.
    case_retention_days: int = 0

    # Data lake (owned primary-source corpora, e.g. Certificate Transparency).
    # SQLite at data/lake/lake.db by default; set to a postgresql://… DSN to scale.
    lake_url: str | None = None

    # Intent LLM planner (OpenAI-compatible: LocalAI, OpenAI, etc.)
    llm_base_url: str | None = None  # e.g. http://127.0.0.1:8080/v1
    llm_api_key: str | None = None
    llm_model: str = "gpt-4o-mini"
    llm_timeout_s: float = 60.0
    llm_enabled: bool = False  # default off; enable via UMBRA_LLM_ENABLED=true or --llm
    llm_temperature: float = 0.1
    llm_max_tokens: int = 2000

    # Jev (TypeSafe AI) second-opinion verdicts — docs/JEV.md. Off by default;
    # with it off or no key, verdicts are exactly the deterministic ones.
    # Routed through OpenRouter for now (one key, OpenRouter billing); set
    # UMBRA_JEV_PROVIDER=typesafe + UMBRA_TYPESAFE_API_KEY to go direct.
    jev_enabled: bool = False
    jev_provider: Literal["openrouter", "typesafe"] = "openrouter"
    openrouter_api_key: str | None = None
    typesafe_api_key: str | None = None
    # Overrides the provider's default base (…/v1/systemone is appended).
    jev_base_url: str | None = None
    # Pinned, not "latest": answers record the model they came from, and a
    # version bump reruns the J0 eval first.
    jev_model: str = "jev-1.13"
    jev_timeout_s: float = 3.0
    jev_min_confidence: float = 0.70
    # Input tokens per UTC day; 0 = unlimited. Bounds abuse, not cost.
    jev_daily_token_budget: int = 2_000_000

    @property
    def jev_api_key(self) -> str | None:
        return self.openrouter_api_key if self.jev_provider == "openrouter" else self.typesafe_api_key

    @property
    def jev_endpoint_base(self) -> str:
        from umbra.jev.client import PROVIDER_BASE_URLS
        return self.jev_base_url or PROVIDER_BASE_URLS[self.jev_provider]

    @property
    def jev_configured(self) -> bool:
        return bool(self.jev_enabled and self.jev_api_key)

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_filename

    @property
    def sqlalchemy_url(self) -> str:
        """Return SQLAlchemy URL: Postgres if configured, else local SQLite."""
        if self.database_url:
            url = self.database_url.strip()
            # Normalize common postgres:// → postgresql+psycopg://
            if url.startswith("postgres://"):
                url = "postgresql+psycopg://" + url[len("postgres://") :]
            elif url.startswith("postgresql://") and "+psycopg" not in url and "+psycopg2" not in url:
                url = "postgresql+psycopg://" + url[len("postgresql://") :]
            return url
        return f"sqlite:///{self.db_path}"

    @property
    def using_postgres(self) -> bool:
        u = (self.database_url or "").lower()
        return u.startswith("postgres")

    @property
    def primary_dns(self) -> str | None:
        """The configured primary DNS resolver (IP or resolvable hostname)."""
        return self.dns_resolver

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def exports_dir(self) -> Path:
        return self.data_dir / "exports"

    @property
    def llm_configured(self) -> bool:
        return bool(self.llm_base_url and self.llm_model)

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
