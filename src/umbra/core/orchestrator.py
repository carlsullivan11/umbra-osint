from __future__ import annotations

import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Iterable

import httpx  # noqa: F401 - used by collectors via ctx.http

from umbra.core.http_guard import GuardedClient
from rich.console import Console

from umbra.collectors.base import CollectorContext, CollectorRegistry, default_registry
from umbra.core.config import Settings, get_settings
from umbra.db.repository import Repository
from umbra.db.schema import Entity

console = Console()


# High-value types eligible for automatic pivot expansion beyond depth 0
_PIVOT_TYPES = {
    "domain",
    "ip",
    "email",
    "url",
    "username",
    "repo",
    "person",
    "org",
    # A cert was a dead end: tls_cert and ct_lake produced them, nothing was
    # ever allowed to expand one, and sslbl_cert — whose only input is a cert —
    # could therefore never be handed anything. Production showed the shape
    # exactly: 2,195 cert entities, 190 tls_cert runs, zero sslbl_cert
    # evidence. Listing sslbl_cert in a plan without this is a name that never
    # fires. The expansion is cheap because its one consumer reads a local
    # lake and makes no request.
    "cert",
}


class Orchestrator:
    """Breadth-first pivot engine: seed entities → collectors → new entities."""

    def __init__(
        self,
        repo: Repository,
        settings: Settings | None = None,
        registry: CollectorRegistry | None = None,
    ):
        self.repo = repo
        self.settings = settings or get_settings()
        self.registry = registry or default_registry()

    def _seed_apexes(self, seeds: list[Entity]) -> set[str]:
        apexes: set[str] = set()
        for s in seeds:
            if s.type == "domain" and s.value:
                parts = s.value.lower().split(".")
                if len(parts) >= 2:
                    apexes.add(".".join(parts[-2:]))
                else:
                    apexes.add(s.value.lower())
            if s.type == "email" and "@" in s.value:
                dom = s.value.split("@", 1)[1].lower()
                parts = dom.split(".")
                if len(parts) < 2:
                    continue
                apex = ".".join(parts[-2:])
                # An address at a free-mail provider is not a reason to
                # investigate the provider. `umbra.email.plan.FREE_MAIL` already
                # makes this judgement for header analysis — "a scan of a mail
                # provider that happens to have a billion other customers" —
                # and `intent.extract` refuses to seed the domain for the same
                # reason. The pivot layer did not, so `email_split` re-created
                # the domain entity downstream and it pivoted anyway: one
                # production search of a yahoo.com address returned 51 rows
                # about Yahoo's hosting and 2 about the address.
                #
                # A corporate mail domain still pivots. There the domain *is*
                # the organisation, which is the whole point of asking.
                from umbra.email.plan import FREE_MAIL

                if dom in FREE_MAIL or apex in FREE_MAIL:
                    continue
                apexes.add(apex)
        return apexes

    def _should_pivot(self, ent: Entity, seeds: list[Entity], apexes: set[str]) -> bool:
        if ent.is_seed:
            return True
        if ent.type not in _PIVOT_TYPES:
            return False
        if not ent.value:
            return False
        if ent.type == "domain":
            v = ent.value.lower()
            # only pivot domains under seed apex (or exact seed)
            if any(v == s.value.lower() for s in seeds if s.type == "domain"):
                return True
            return any(v == a or v.endswith("." + a) for a in apexes)
        if ent.type == "url":
            return any(a in ent.value.lower() for a in apexes) if apexes else True
        return True

    def _collect_with_timeout(self, col, ent, ctx, timeout_s: float):
        """Run one collector, abandoning it if it exceeds `timeout_s`.

        Collectors are third-party-ish, synchronous and I/O-bound; a hung
        upstream with no socket timeout would otherwise occupy the worker
        indefinitely (Phase B4). `timeout_s <= 0` disables the bound.

        The executor is intentionally NOT shut down with wait=True on timeout:
        blocking until the stuck call returns would defeat the entire purpose.
        Threads are daemons, so an abandoned one cannot keep the process alive.
        """
        if not timeout_s or timeout_s <= 0:
            return col.collect(ent, ctx)

        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"collect-{col.name}")
        try:
            future = pool.submit(col.collect, ent, ctx)
            return future.result(timeout=timeout_s)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def run(
        self,
        case_id: str,
        depth: int | None = None,
        max_entities: int | None = None,
        collectors: Iterable[str] | None = None,
        max_seconds: float | None = None,
    ) -> dict:
        """Run collectors over a case.

        `max_seconds` overrides the global `job_max_seconds` for this run only.
        A synchronous caller — the public reputation page — needs a budget sized
        to what a visitor will wait, not the 1800s ceiling that suits a
        background job. Exceeding it stops the run and records a note; it is
        never a silent truncation.
        """
        depth = depth if depth is not None else self.settings.default_depth
        max_entities = max_entities if max_entities is not None else self.settings.default_max_entities
        cols = self.registry.resolve_many(list(collectors) if collectors else None)
        if not cols:
            raise ValueError("No collectors selected")

        case = self.repo.get_case(case_id)
        if not case:
            raise ValueError(f"Unknown case: {case_id}")
        if not case.authorization_basis:
            raise ValueError("Case missing authorization_basis")

        run = self.repo.create_run(
            case_id,
            depth=depth,
            max_entities=max_entities,
            collectors=[c.name for c in cols],
        )

        # Phase B4: bound the whole run, not just individual collectors.
        started_at = time.monotonic()
        job_budget = (
            float(max_seconds) if max_seconds is not None
            else float(getattr(self.settings, "job_max_seconds", 0) or 0)
        )
        collector_timeout = float(getattr(self.settings, "collector_timeout_s", 0) or 0)

        # queue: (entity_id, depth_from_seed)
        entities = self.repo.list_entities(case_id)
        seeds = [e for e in entities if e.is_seed] or entities[:1]
        if not seeds:
            self.repo.finish_run(run, "failed", {"error": "no seeds"})
            raise ValueError("No seed entities on case")

        apexes = self._seed_apexes(seeds)
        q: deque[tuple[str, int]] = deque((s.id, 0) for s in seeds)
        seen_pair: set[tuple[str, str]] = set()  # (entity_id, collector)
        # Counted, not inferred: the run_empty quality signal (E2) needs an
        # exact "did this run discover anything", and comparing list lengths
        # after the fact races with merges and dedupe.
        entities_before = len(entities)
        stats = {
            "processed": 0,
            "collector_runs": 0,
            "errors": 0,
            "notes": [],
            "entities_added": 0,
            # Per-collector wall clock. Slow sources were folklore — "crtsh feels
            # slow" — with nothing to check it against. Recorded so a budget can
            # be set from evidence next time rather than from a guess.
            "collector_seconds": {},
        }

        headers = {"User-Agent": self.settings.user_agent}
        try:
            # Guarded: /run is public, so a visitor chooses these URLs. The
            # client validates the resolved IP before connecting and re-checks
            # every redirect hop (umbra.core.http_guard).
            with GuardedClient(
                headers=headers,
                timeout=self.settings.request_timeout_s,
            ) as http:
                ctx_base = {"settings": self.settings, "case_id": case_id, "run_id": run.id, "http": http}

                while q:
                    if job_budget and (time.monotonic() - started_at) >= job_budget:
                        stats["notes"].append(
                            f"job wall-clock budget reached ({job_budget:.0f}s); stopping early"
                        )
                        break
                    if len(self.repo.list_entities(case_id)) >= max_entities:
                        stats["notes"].append("max_entities reached")
                        break

                    ent_id, d = q.popleft()
                    # refresh entity
                    ent = next((e for e in self.repo.list_entities(case_id) if e.id == ent_id), None)
                    if not ent or not ent.value:
                        continue
                    if getattr(ent, "verification", None) == "false":
                        continue
                    if getattr(ent, "merged_into_id", None):
                        continue
                    if d > 0 and not self._should_pivot(ent, seeds, apexes):
                        continue
                    stats["processed"] += 1

                    for col in cols:
                        if not col.supports(ent):
                            continue
                        pair = (ent.id, col.name)
                        if pair in seen_pair:
                            continue
                        seen_pair.add(pair)

                        if job_budget and (time.monotonic() - started_at) >= job_budget:
                            stats["notes"].append(
                                f"job wall-clock budget reached ({job_budget:.0f}s); stopping early"
                            )
                            q.clear()
                            break

                        ctx = CollectorContext(**ctx_base)
                        # A collector's own declared budget wins over the global
                        # default. One number for all of them is wrong in both
                        # directions: a DNS lookup that has not answered in 15s
                        # never will, and a git clone legitimately needs longer
                        # than 45 — `github_commits` hitting the global 45s in a
                        # real run was truncation, not a hang.
                        budget = float(getattr(col, "timeout_s", None) or collector_timeout)
                        col_started = time.monotonic()
                        try:
                            result = self._collect_with_timeout(col, ent, ctx, budget)
                        except FuturesTimeout:
                            # The thread may still be blocked on I/O; we abandon
                            # the result rather than wait. Daemon threads die
                            # with the process, so a hung collector cannot keep
                            # the worker alive either.
                            stats["errors"] += 1
                            stats["collector_seconds"][col.name] = round(
                                stats["collector_seconds"].get(col.name, 0.0)
                                + (time.monotonic() - col_started), 2)
                            # Name the budget it exceeded, not the global one —
                            # otherwise the note points at a number the operator
                            # cannot find in the code.
                            # "%g" not "%.0f": a sub-second budget rendered as
                            # "0s", which reads as a misconfiguration rather than
                            # a deliberately tight bound.
                            stats["notes"].append(
                                f"{col.name} timed out after its {budget:g}s budget "
                                f"on {ent.norm_key} — not checked, so this is "
                                f"unknown rather than clean"
                            )
                            continue
                        except Exception as exc:  # noqa: BLE001
                            stats["errors"] += 1
                            stats["notes"].append(f"{col.name} on {ent.norm_key}: {exc}")
                            continue

                        stats["collector_runs"] += 1
                        stats["collector_seconds"][col.name] = round(
                            stats["collector_seconds"].get(col.name, 0.0)
                            + (time.monotonic() - col_started), 2)
                        # Check again AFTER the work: a collector that ran to
                        # completion can still have pushed the run over budget,
                        # and an overrun must be visible rather than silent.
                        if job_budget and (time.monotonic() - started_at) >= job_budget:
                            over = time.monotonic() - started_at
                            stats["notes"].append(
                                f"job wall-clock budget exceeded ({over:.1f}s > {job_budget:.0f}s); stopping early"
                            )
                            self.repo.apply_result(case_id, run.id, result)
                            self.repo.session.commit()
                            q.clear()
                            break

                        before_ids = {e.id for e in self.repo.list_entities(case_id)}
                        self.repo.apply_result(case_id, run.id, result)
                        self.repo.session.commit()
                        if result.notes:
                            stats["notes"].extend(result.notes[:5])

                        if d < depth:
                            after = self.repo.list_entities(case_id)
                            for e in after:
                                if e.id not in before_ids and self._should_pivot(e, seeds, apexes):
                                    q.append((e.id, d + 1))

            self.repo.finish_run(run, "ok", stats)
            # Phase B: any public IP that entered the graph this run without
            # passive markers gets one in-place pass (same allowlist as sentinel).
            try:
                from umbra.ip_corpus import ensure_case_ips_enriched

                extra = ensure_case_ips_enriched(
                    self.repo, case_id, settings=self.settings
                )
                if extra.get("ips"):
                    stats["ip_backfill_ips"] = extra["ips"]
                    stats["ip_backfill_runs"] = extra.get("collector_runs", 0)
            except Exception as exc:  # noqa: BLE001 - enrichment must not fail the run
                stats["notes"].append(f"ip_backfill: {exc}")
            # Re-score graph after collection
            try:
                from umbra.core.scoring import score_case

                scored = score_case(self.repo, case_id, persist=True)
                stats["scored_entities"] = len(scored)
                stats["score_high"] = sum(1 for s in scored if s.band == "high")
            except Exception as exc:  # noqa: BLE001
                stats["notes"].append(f"scoring: {exc}")
        except Exception as exc:  # noqa: BLE001
            stats["errors"] += 1
            stats["notes"].append(str(exc))
            self.repo.finish_run(run, "failed", stats)
            raise

        try:
            stats["entities_added"] = max(
                0, len(self.repo.list_entities(case_id)) - entities_before
            )
        except Exception:  # noqa: BLE001 - a stat must not fail a finished run
            pass
        return {"run_id": run.id, **stats}
