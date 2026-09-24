"""What is in each owned lake right now, as data rather than as display text.

`umbra doctor` and the lake-health analytics need the same six readings. Two
independent readers is how two surfaces start disagreeing, and a monitor that
contradicts the diagnostic is worse than no monitor: the operator now has to
work out which one is lying before they can act on either.

So the reads live here once. `doctor` formats these into its check rows;
`umbra.analytics.lakes` snapshots them into a series.

Each reader is a module-level function so a caller (or a test) can replace one
without touching the rest, and so a single broken lake cannot take the whole
inventory down — a report you open *because* something is wrong must survive
the thing that is wrong.
"""
from __future__ import annotations

from datetime import datetime, timezone

from umbra.analytics.lakes import LakeReading
from umbra.core.config import Settings, get_settings


def _as_datetime(stamp) -> datetime | None:
    """Lake stores stamp things as ISO strings; the series wants datetimes."""
    if stamp is None:
        return None
    if isinstance(stamp, datetime):
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    try:
        text = str(stamp).replace("Z", "+00:00")
        when = datetime.fromisoformat(text)
        return when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _newest(values) -> datetime | None:
    stamps = [_as_datetime(v) for v in values]
    real = [s for s in stamps if s is not None]
    return max(real) if real else None


def _abuse_and_ct_readings(settings: Settings) -> list[LakeReading]:
    """Both live in one store, so one open serves both."""
    from umbra.lake.store import LakeStore

    store = LakeStore.from_settings(settings)
    try:
        abuse = store.abuse_stats()
        feeds = (abuse.get("feeds") or {}).values()
        rows = (int(abuse.get("urls", 0)) + int(abuse.get("iocs", 0))
                + int(abuse.get("certs", 0)))
        ct = store.stats()
        cps = (ct.get("checkpoints") or {}).values()
        return [
            LakeReading("abuse.ch", rows,
                        _newest(f.get("synced_at") for f in feeds)),
            LakeReading("certificate transparency", int(ct.get("certs", 0)),
                        _newest(c.get("updated_at") for c in cps)),
        ]
    finally:
        close = getattr(store, "close", None)
        if close:
            close()


def _geoip_reading(settings: Settings) -> LakeReading:
    from umbra.lake.geoip import GeoIpStore

    st = GeoIpStore().status()
    return LakeReading("geoip", int(st.get("rows", 0)),
                       _as_datetime(st.get("imported_at")))


def _epss_reading(settings: Settings) -> LakeReading:
    from umbra.lake.epss import EpssLake

    st = EpssLake.from_settings(settings).status()
    return LakeReading("epss", int(st.get("rows", 0)),
                       _as_datetime(st.get("imported_at")))


def _psl_reading(settings: Settings) -> LakeReading:
    from umbra.lake.psl import PublicSuffixList

    st = PublicSuffixList.from_settings(settings).status()
    return LakeReading("public suffix", int(st.get("rules", 0)),
                       _as_datetime(st.get("updated_at")))


def _people_reading(settings: Settings) -> LakeReading:
    from umbra.lake.people import PeopleLake

    lake = PeopleLake.from_settings(settings)
    try:
        st = lake.status()
        # The people lake does not record an ingest time. None, not now() —
        # claiming a sync time we do not have would make a cold lake read fresh.
        return LakeReading("people", int(getattr(st, "people", 0)), None)
    finally:
        lake.close()


def _faa_reading(settings: Settings) -> LakeReading:
    from umbra.lake.faa import FaaLake

    st = FaaLake().status()
    # The FAA file has no ingest timestamp of its own, so the honest stamp is
    # when *we* imported it — which is what the lake records.
    return LakeReading("faa registry", int(st.get("aircraft", 0)),
                       _as_datetime(st.get("imported_at")))


def lake_inventory(settings: Settings | None = None) -> list[LakeReading]:
    """Read every owned lake. Never raises.

    A lake that cannot be read comes back with `error` set and `rows=None`,
    which is a different fact from `rows=0` and is kept different all the way
    through: `record_snapshot` refuses to store it, so an unreadable lake never
    later renders as one that lost everything it had.
    """
    s = settings or get_settings()
    out: list[LakeReading] = []

    try:
        out.extend(_abuse_and_ct_readings(s))
    except Exception as exc:  # noqa: BLE001
        out.append(LakeReading("abuse.ch", None, None, error=f"unreadable: {exc}"))
        out.append(LakeReading("certificate transparency", None, None,
                               error=f"unreadable: {exc}"))

    for name, reader in (
        ("geoip", _geoip_reading),
        ("epss", _epss_reading),
        ("public suffix", _psl_reading),
        ("people", _people_reading),
        ("faa registry", _faa_reading),
    ):
        try:
            out.append(reader(s))
        except Exception as exc:  # noqa: BLE001
            out.append(LakeReading(name, None, None, error=f"unreadable: {exc}"))

    return out
