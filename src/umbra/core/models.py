from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str = "") -> str:
    u = uuid4().hex[:12]
    return f"{prefix}{u}" if prefix else u


class EntityType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    URL = "url"
    USERNAME = "username"
    ORG = "org"
    PERSON = "person"
    CERT = "cert"
    ASN = "asn"
    PHONE = "phone"
    REPO = "repo"
    TECHNOLOGY = "technology"
    NAMESERVER = "nameserver"
    REGISTRAR = "registrar"
    BREACH = "breach"
    PASTE = "paste"
    MAC = "mac"
    LOCATION = "location"
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    CRYPTO_ADDRESS = "crypto_address"
    AIRCRAFT = "aircraft"


class EdgeType(str, Enum):
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    OWNS = "owns"
    USES_EMAIL = "uses_email"
    MENTIONS = "mentions"
    REDIRECTS_TO = "redirects_to"
    ISSUED_FOR = "issued_for"
    SUBDOMAIN_OF = "subdomain_of"
    SAME_AS = "same_as"
    WORKS_AT = "works_at"
    REGISTERED_BY = "registered_by"
    OBSERVED_AT = "observed_at"
    LINKED_FROM = "linked_from"
    USES_TECH = "uses_tech"
    MEMBER_OF = "member_of"
    HAS_MX = "has_mx"
    HAS_NS = "has_ns"
    HAS_TXT = "has_txt"
    PARENT_DOMAIN = "parent_domain"
    HAS_PROFILE = "has_profile"
    ASSOCIATED_WITH = "associated_with"
    # Person-graph: family/kinship from obituaries & records (weak until confirmed)
    RELATED_TO = "related_to"
    LOCATED_IN = "located_in"
    # Wikidata graph patterns (references/wikidata-schema.md)
    FOUNDED_BY = "founded_by"
    HEADQUARTERED_IN = "headquartered_in"
    CITIZEN_OF = "citizen_of"
    AFFECTED_BY = "affected_by"
    EXPOSED_IN = "exposed_in"
    REMEDIATED = "remediated"
    LOOKALIKE_OF = "lookalike_of"
    SECURITY_CONTACT = "security_contact"
    INDICATOR_OF = "indicator_of"


class EntityIn(BaseModel):
    type: EntityType
    value: str
    display_name: str | None = None
    props: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.8


class EdgeIn(BaseModel):
    source_key: str  # type:value normalized key
    target_key: str
    rel: EdgeType
    confidence: float = 0.7
    props: dict[str, Any] = Field(default_factory=dict)


class EvidenceIn(BaseModel):
    collector: str
    source_name: str
    source_url: str | None = None
    summary: str
    confidence: float = 0.7
    raw: dict[str, Any] | str | None = None
    entity_key: str | None = None


class CollectorResult(BaseModel):
    entities: list[EntityIn] = Field(default_factory=list)
    edges: list[EdgeIn] = Field(default_factory=list)
    evidence: list[EvidenceIn] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
