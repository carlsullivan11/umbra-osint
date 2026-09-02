"""Graph shaping for display — which seed does each entity belong to.

A case can start from several seeds at once: paste three domains and two IPs,
or upload a blocklist, and one flat list of everything the collectors returned
is unreadable. Worse, it is *misleading* — it implies the findings are one
undifferentiated pile when in fact each one traces back to a particular thing
the analyst asked about.

`group_by_seed` walks the case graph outward from every seed at once and
assigns each entity to the seed it is nearest to, so the UI can render one card
per seed with that seed's findings inside it.

Three details matter.

**The walk is undirected.** Collectors write edges in whichever direction reads
naturally — `org --owns--> ip` but `ip --member_of--> asn` — so following edge
direction would strand half the graph.

**It is transitive.** `AS60729 --owns--> stiftung erneuerbare freiheit` is two
hops from the seed, and it is still that seed's finding.

**Nothing is dropped.** An entity with no path to any seed goes into an
explicit unattached group rather than vanishing, for the same reason an
unreachable source is never rendered as a clean result: a page that quietly
omits rows is lying about what was found.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class SeedGroup:
    """One seed and everything the collectors found from it.

    `seed` is `None` for the group holding entities that no seed reaches.
    """

    seed: Any | None
    entities: list[Any] = field(default_factory=list)
    # Entities in this group that another seed can also reach. A shared entity
    # is a finding in its own right — it is the thing connecting two of the
    # analyst's seeds — so the UI marks it rather than silently picking one.
    shared_ids: set[str] = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.entities)


def _adjacency(edges: Iterable[Any]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for edge in edges:
        source = getattr(edge, "source_id", None)
        target = getattr(edge, "target_id", None)
        if not source or not target:
            continue
        graph.setdefault(source, set()).add(target)
        graph.setdefault(target, set()).add(source)
    return graph


def _distances(start: str, graph: dict[str, set[str]]) -> dict[str, int]:
    """Hop count from one seed to everything it can reach."""
    seen = {start: 0}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbour in graph.get(node, ()):
            if neighbour not in seen:
                seen[neighbour] = seen[node] + 1
                queue.append(neighbour)
    return seen


def group_by_seed(entities: Iterable[Any], edges: Iterable[Any]) -> list[SeedGroup]:
    """Partition a case's entities into one group per seed.

    Seeds keep the order they arrive in, which is the caller's ordering
    (confidence first), so the strongest seed leads. Within a group entities are
    ordered by how far they sit from the seed, then by confidence — nearest and
    most certain first, which is the order an analyst reads in.
    """
    entities = list(entities)
    # Cards follow the order the seeds were entered, which is the order the
    # analyst is holding in their head. The caller sorts entities by confidence
    # for the flat views, and every seed carries the same confidence, so
    # without this the cards come out alphabetised by type — domains before
    # IPs — which matches nothing the user did.
    seeds = sorted(
        (e for e in entities if getattr(e, "is_seed", False)),
        key=lambda e: (getattr(e, "first_seen", None) is None,
                       getattr(e, "first_seen", None)),
    )
    graph = _adjacency(edges)

    reach = {seed.id: _distances(seed.id, graph) for seed in seeds}

    # Nearest seed owns the entity; a tie at that distance means it genuinely
    # sits between two seeds.
    #
    # "Shared" deliberately means *equally near to more than one seed*, not
    # "reachable from more than one". Reachability marks almost everything:
    # once two seeds are joined anywhere, their whole component is reachable
    # from both, and the badge lands on every row — the same
    # everything-is-flagged noise the old `unknown` verification column had. A
    # nameserver one hop from one domain and three hops from another belongs to
    # the first; only the address they both resolve to is the link.
    distance: dict[str, int] = {}
    owners: dict[str, list[str]] = {}
    for seed in seeds:  # seed order breaks ties, so the result is stable
        for entity_id, hops in reach[seed.id].items():
            if entity_id not in distance or hops < distance[entity_id]:
                distance[entity_id] = hops
                owners[entity_id] = [seed.id]
            elif hops == distance[entity_id]:
                owners[entity_id].append(seed.id)

    # ...and only at distance 1. Two seeds pointing *directly* at one thing —
    # two domains resolving to the same address — is unambiguous and rare.
    # Allowing deeper ties re-floods the badge: everything hanging off that
    # shared address is then equidistant from both seeds too, so five orgs
    # behind one shared IP all light up while adding nothing the IP did not
    # already say. Narrow and meaningful beats broad and ignored.
    shared = {eid for eid, holders in owners.items()
              if len(holders) > 1 and distance[eid] == 1}
    owner = {eid: holders[0] for eid, holders in owners.items()}

    groups = [SeedGroup(seed=seed) for seed in seeds]
    index = {group.seed.id: group for group in groups}

    unattached = SeedGroup(seed=None)
    for entity in entities:
        if getattr(entity, "is_seed", False):
            continue  # a seed heads its own card; it is not its own finding
        group = index.get(owner.get(entity.id, ""), unattached)
        group.entities.append(entity)
        if entity.id in shared:
            group.shared_ids.add(entity.id)

    for group in groups:
        group.entities.sort(key=lambda e: (
            distance.get(e.id, 99),
            -(getattr(e, "confidence", 0) or 0),
            str(getattr(e, "type", "")),
            str(getattr(e, "value", "")),
        ))
    unattached.entities.sort(key=lambda e: (
        -(getattr(e, "confidence", 0) or 0),
        str(getattr(e, "type", "")),
        str(getattr(e, "value", "")),
    ))

    # Kept last and only when non-empty: it is a real bucket, not a placeholder.
    if unattached.entities:
        groups.append(unattached)
    return groups


def hops_from_seed(entity_id: str, seed_id: str,
                   edges: Iterable[Any]) -> int | None:
    """How far one entity sits from one seed, or None if unreachable."""
    return _distances(seed_id, _adjacency(edges)).get(entity_id)
