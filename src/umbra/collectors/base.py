from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterable

import httpx

from umbra.core.config import Settings
from umbra.core.models import CollectorResult, EntityType
from umbra.db.schema import Entity


@dataclass
class CollectorContext:
    settings: Settings
    case_id: str
    run_id: str
    http: httpx.Client


class BaseCollector(ABC):
    name: str = "base"
    version: str = "0.1.0"
    inputs: set[EntityType] = set()
    description: str = ""

    #: Seconds this collector may take before the orchestrator abandons it.
    #: None means "use the global default" (settings.collector_timeout_s, 45s).
    #:
    #: One number for every collector is wrong in both directions. A DNS lookup
    #: that has not answered in three seconds is not going to; giving it 45
    #: means a dead resolver holds the run open fifteen times longer than
    #: necessary. A git clone or a CT log query legitimately needs longer than
    #: 45, so the global default truncates real work — `github_commits` timing
    #: out at 45s in a real run was that, not a hang.
    #:
    #: Declared per collector so the number sits next to the work it bounds.
    timeout_s: float | None = None

    def supports(self, entity: Entity) -> bool:
        try:
            return EntityType(entity.type) in self.inputs
        except ValueError:
            return False

    @abstractmethod
    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        raise NotImplementedError


class CollectorRegistry:
    def __init__(self) -> None:
        self._by_name: dict[str, BaseCollector] = {}

    def register(self, collector: BaseCollector) -> None:
        self._by_name[collector.name] = collector

    def get(self, name: str) -> BaseCollector | None:
        return self._by_name.get(name)

    def list(self) -> list[BaseCollector]:
        return sorted(self._by_name.values(), key=lambda c: c.name)

    def resolve_many(self, names: Iterable[str] | None = None) -> list[BaseCollector]:
        if not names:
            return self.list()
        out: list[BaseCollector] = []
        for n in names:
            c = self.get(n.strip())
            if c:
                out.append(c)
        return out


def default_registry() -> CollectorRegistry:
    from umbra.collectors.asn_cymru import AsnCymruCollector
    from umbra.collectors.court_records import CourtRecordsCollector
    from umbra.collectors.crtsh import CrtshCollector
    from umbra.collectors.ddg_search import DdgSearchCollector
    from umbra.collectors.dns_email_auth import DnsEmailAuthCollector
    from umbra.collectors.dns_resolve import DnsResolveCollector
    from umbra.collectors.edgar_search import EdgarSearchCollector
    from umbra.collectors.email_split import EmailSplitCollector
    from umbra.collectors.github_commits import GithubCommitsCollector
    from umbra.collectors.github_user import GithubUserCollector
    from umbra.collectors.gravatar import GravatarCollector
    from umbra.collectors.hibp_breach import HibpBreachCollector
    from umbra.collectors.html_links import HtmlLinksCollector
    from umbra.collectors.http_probe import HttpProbeCollector
    from umbra.collectors.opencorporates import OpenCorporatesCollector
    from umbra.collectors.public_records_portals import PublicRecordsPortalsCollector
    from umbra.collectors.obituary_search import ObituarySearchCollector
    from umbra.collectors.county_records import CountyRecordsCollector
    from umbra.collectors.wifi_maps import WifiMapsCollector
    from umbra.collectors.sex_offender_registry import SexOffenderRegistryCollector
    from umbra.collectors.rdap_domain import RdapDomainCollector
    from umbra.collectors.rdap_ip import RdapIpCollector
    from umbra.collectors.ip_geo import IpGeoCollector
    from umbra.collectors.tech_fingerprint import TechFingerprintCollector
    from umbra.collectors.tls_cert import TlsCertCollector
    from umbra.collectors.username_presence import UsernamePresenceCollector
    from umbra.collectors.wayback_cdx import WaybackCdxCollector
    from umbra.collectors.lookalike_domains import LookalikeDomainCollector
    from umbra.collectors.security_txt import SecurityTxtCollector
    from umbra.collectors.reputation import (
        DomainReputationCollector,
        IpReputationCollector,
    )
    from umbra.collectors.darkweb import RansomwareExposureCollector
    from umbra.collectors.ct_lake import CtLakeCollector
    from umbra.collectors.mac_oui import MacOuiCollector
    from umbra.collectors.phone_validate import PhoneValidateCollector
    from umbra.collectors.crypto_screen import CryptoScreenCollector
    from umbra.collectors.cve_lookup import CveLookupCollector
    from umbra.collectors.wikidata import WikidataCollector
    from umbra.collectors.malware_infra import MalwareInfraCollector
    from umbra.collectors.sslbl_cert import SslblCertCollector

    reg = CollectorRegistry()
    for c in (
        DnsResolveCollector(),
        DnsEmailAuthCollector(),
        RdapDomainCollector(),
        RdapIpCollector(),
        AsnCymruCollector(),
        IpGeoCollector(),
        CrtshCollector(),
        TlsCertCollector(),
        HttpProbeCollector(),
        TechFingerprintCollector(),
        HtmlLinksCollector(),
        SecurityTxtCollector(),
        LookalikeDomainCollector(),
        EmailSplitCollector(),
        GravatarCollector(),
        GithubUserCollector(),
        GithubCommitsCollector(),
        UsernamePresenceCollector(),
        WaybackCdxCollector(),
        DdgSearchCollector(),
        PublicRecordsPortalsCollector(),
        ObituarySearchCollector(),
        CountyRecordsCollector(),
        WifiMapsCollector(),
        SexOffenderRegistryCollector(),
        HibpBreachCollector(),
        EdgarSearchCollector(),
        OpenCorporatesCollector(),
        IpReputationCollector(),
        DomainReputationCollector(),
        RansomwareExposureCollector(),
        CtLakeCollector(),
        MacOuiCollector(),
        PhoneValidateCollector(),
        CryptoScreenCollector(),
        WikidataCollector(),
        CveLookupCollector(),
        MalwareInfraCollector(),
        SslblCertCollector(),
        CourtRecordsCollector(),
    ):
        reg.register(c)
    return reg
