"""One card per seed (Carl, 2026-08-20, with a phone screenshot).

> "the UI needs work. especially if users can drop multiple IPs and domains in
> one search. each seed should be its own card then the entities are within the
> card with easy to read formatting for all devices."

The screenshot showed a six-column table on a phone: `185.191.171.3` wrapped
across three lines, the word `location` rendered vertically as `lo/ca/tio/n`,
and every entity from every seed in one flat confidence-sorted list. With one
seed that is merely ugly. With five, it is unusable — nothing tells you which
finding came from which thing you asked about.

Grouping is graph work, not template work, so it lives in Python where it can
be tested. The awkward parts are all real properties of the case graph:
collectors write edges in whichever direction reads naturally, findings can sit
several hops out, and two seeds can share one.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field

warnings.filterwarnings("ignore")

from umbra.graph import group_by_seed  # noqa: E402


@dataclass
class E:
    id: str
    value: str
    type: str = "domain"
    is_seed: bool = False
    confidence: float = 0.5
    props: dict = field(default_factory=dict)


@dataclass
class Edge:
    source_id: str
    target_id: str
    rel: str = "related"


def values(group):
    return [e.value for e in group.entities]


# --- the basic shape -------------------------------------------------------

def test_each_seed_gets_its_own_group():
    entities = [E("a", "one.example", is_seed=True),
                E("b", "two.example", is_seed=True)]
    groups = group_by_seed(entities, [])
    assert [g.seed.value for g in groups] == ["one.example", "two.example"]


def test_a_finding_lands_under_its_seed():
    entities = [E("a", "one.example", is_seed=True),
                E("b", "two.example", is_seed=True),
                E("x", "1.2.3.4", type="ip")]
    groups = group_by_seed(entities, [Edge("a", "x")])
    assert values(groups[0]) == ["1.2.3.4"]
    assert values(groups[1]) == []


def test_a_seed_is_not_listed_as_its_own_finding():
    """The seed heads the card. Repeating it inside is noise."""
    entities = [E("a", "one.example", is_seed=True), E("x", "1.2.3.4", type="ip")]
    groups = group_by_seed(entities, [Edge("a", "x")])
    assert "one.example" not in values(groups[0])


def test_the_group_counts_what_it_holds():
    entities = [E("a", "one.example", is_seed=True),
                E("x", "1.2.3.4"), E("y", "5.6.7.8")]
    groups = group_by_seed(entities, [Edge("a", "x"), Edge("a", "y")])
    assert groups[0].count == 2


# --- the graph is not as tidy as it looks ---------------------------------

def test_edge_direction_does_not_matter():
    """Collectors write whichever direction reads naturally — `org owns ip` but
    `ip member_of asn`. Following direction would strand half the graph."""
    entities = [E("a", "1.2.3.4", type="ip", is_seed=True),
                E("o", "example ltd", type="org"),
                E("n", "AS123", type="asn")]
    groups = group_by_seed(entities, [Edge("o", "a", "owns"),
                                      Edge("a", "n", "member_of")])
    assert set(values(groups[0])) == {"example ltd", "AS123"}


def test_findings_several_hops_out_still_belong_to_the_seed():
    """`AS60729 --owns--> stiftung erneuerbare freiheit` is two hops from the
    seed and is still that seed's finding."""
    entities = [E("a", "1.2.3.4", type="ip", is_seed=True),
                E("n", "AS123", type="asn"),
                E("o", "far org", type="org")]
    groups = group_by_seed(entities, [Edge("a", "n"), Edge("n", "o")])
    assert set(values(groups[0])) == {"AS123", "far org"}


def test_the_nearest_seed_wins():
    entities = [E("a", "one.example", is_seed=True),
                E("b", "two.example", is_seed=True),
                E("n", "AS123", type="asn"),
                E("x", "shared-org", type="org")]
    # x is 1 hop from b, 2 hops from a
    groups = group_by_seed(entities, [Edge("a", "n"), Edge("n", "x"),
                                      Edge("b", "x")])
    assert "shared-org" in values(groups[1])
    assert "shared-org" not in values(groups[0])


def test_nearest_first_within_a_card():
    """An analyst reads top-down. The thing one hop from what they asked about
    should not be below something four hops away."""
    entities = [E("a", "1.2.3.4", type="ip", is_seed=True),
                E("near", "AS123", type="asn", confidence=0.4),
                E("far", "far org", type="org", confidence=0.9)]
    groups = group_by_seed(entities, [Edge("a", "near"), Edge("near", "far")])
    assert values(groups[0]) == ["AS123", "far org"]


# --- what connects two seeds is itself a finding --------------------------

def test_an_entity_reachable_from_two_seeds_is_marked_shared():
    """Two domains resolving to one IP is the most interesting thing on the
    page, and a flat list buries it."""
    entities = [E("a", "one.example", is_seed=True),
                E("b", "two.example", is_seed=True),
                E("x", "1.2.3.4", type="ip")]
    groups = group_by_seed(entities, [Edge("a", "x"), Edge("b", "x")])
    assert "x" in groups[0].shared_ids


def test_an_unshared_entity_is_not_marked():
    entities = [E("a", "one.example", is_seed=True),
                E("b", "two.example", is_seed=True),
                E("x", "1.2.3.4", type="ip")]
    groups = group_by_seed(entities, [Edge("a", "x")])
    assert groups[0].shared_ids == set()


# --- nothing is dropped ----------------------------------------------------

def test_an_entity_no_seed_reaches_is_still_shown():
    """A page that quietly omits rows is lying about what was found."""
    entities = [E("a", "one.example", is_seed=True),
                E("orphan", "nobody-linked-me", type="org")]
    groups = group_by_seed(entities, [])
    assert groups[-1].seed is None
    assert values(groups[-1]) == ["nobody-linked-me"]


def test_the_unattached_group_is_absent_when_empty():
    entities = [E("a", "one.example", is_seed=True), E("x", "1.2.3.4")]
    groups = group_by_seed(entities, [Edge("a", "x")])
    assert all(g.seed is not None for g in groups)


def test_every_entity_appears_exactly_once():
    """The invariant. Losing one is a lie; showing one twice is a miscount."""
    entities = [E("a", "one.example", is_seed=True),
                E("b", "two.example", is_seed=True),
                *[E(f"x{i}", f"host{i}.example") for i in range(20)],
                E("orphan", "unlinked")]
    edges = [Edge("a", f"x{i}") for i in range(10)]
    edges += [Edge("b", f"x{i}") for i in range(10, 20)]
    groups = group_by_seed(entities, edges)
    seen = [e.value for g in groups for e in g.entities]
    assert len(seen) == len(set(seen)) == 21


def test_a_case_with_no_seeds_still_shows_everything():
    entities = [E("x", "1.2.3.4"), E("y", "5.6.7.8")]
    groups = group_by_seed(entities, [])
    assert len(groups) == 1 and groups[0].seed is None
    assert len(groups[0].entities) == 2


# --- shape and hostile input ----------------------------------------------

def test_no_entities_is_no_groups():
    assert group_by_seed([], []) == []


def test_edges_pointing_at_missing_entities_do_not_raise():
    entities = [E("a", "one.example", is_seed=True)]
    group_by_seed(entities, [Edge("a", "ghost"), Edge("ghost", "phantom")])


def test_malformed_edges_do_not_raise():
    entities = [E("a", "one.example", is_seed=True), E("x", "1.2.3.4")]
    groups = group_by_seed(entities, [Edge(None, "x"), Edge("a", None)])
    assert groups[-1].seed is None  # x could not be attached, so it is shown


def test_a_cycle_does_not_hang():
    entities = [E("a", "one.example", is_seed=True),
                E("x", "1.2.3.4"), E("y", "5.6.7.8")]
    groups = group_by_seed(entities,
                           [Edge("a", "x"), Edge("x", "y"), Edge("y", "a"),
                            Edge("y", "x")])
    assert len(groups[0].entities) == 2


def test_a_wide_case_is_handled():
    entities = [E("a", "seed.example", is_seed=True)]
    entities += [E(f"x{i}", f"h{i}.example") for i in range(500)]
    edges = [Edge("a", f"x{i}") for i in range(500)]
    assert group_by_seed(entities, edges)[0].count == 500


# --- "shared" has to mean something ---------------------------------------

def test_an_entity_nearer_one_seed_is_not_shared():
    """Reachability is the wrong test. Once two seeds are joined anywhere their
    whole component is reachable from both, so the badge lands on every row —
    the same everything-is-flagged noise the old `unknown` column had.

    Here `ns1` is one hop from A and three from B. It belongs to A.
    """
    entities = [E("a", "a.example", is_seed=True),
                E("b", "b.example", is_seed=True),
                E("ip", "1.2.3.4", type="ip"),
                E("ns", "ns1.a.example", type="nameserver")]
    # a—ns, a—ip, b—ip  → ns is 1 from a, 3 from b; ip is 1 from both
    groups = group_by_seed(entities, [Edge("a", "ns"), Edge("a", "ip"),
                                      Edge("b", "ip")])
    a_group = next(g for g in groups if g.seed.value == "a.example")
    assert "ns" not in a_group.shared_ids
    assert "ip" in a_group.shared_ids


def test_only_the_link_itself_is_marked_not_everything_behind_it():
    """The five orgs behind the shared address are equidistant from both seeds
    too, so a distance-agnostic rule lights all of them up while adding nothing
    the address did not already say. Only the direct link is marked."""
    entities = [E("a", "a.example", is_seed=True),
                E("b", "b.example", is_seed=True),
                E("ip", "1.2.3.4", type="ip"),
                *[E(f"o{i}", f"org{i}", type="org") for i in range(5)]]
    edges = [Edge("a", "ip"), Edge("b", "ip")]
    edges += [Edge("ip", f"o{i}") for i in range(5)]
    marked = {i for g in group_by_seed(entities, edges) for i in g.shared_ids}
    assert marked == {"ip"}


# --- card order ------------------------------------------------------------

def test_cards_follow_the_order_the_seeds_were_entered():
    """Every seed carries the same confidence, so the caller's sort leaves them
    alphabetised by type — domains before IPs — which matches nothing the user
    typed."""
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 8, 20, tzinfo=timezone.utc)

    @dataclass
    class Timed:
        id: str
        value: str
        type: str = "domain"
        is_seed: bool = False
        confidence: float = 0.99
        first_seen: object = None
        props: dict = field(default_factory=dict)

    entities = [
        Timed("ip1", "185.191.171.3", "ip", True, first_seen=now),
        Timed("d1", "typed-second.example", "domain", True,
              first_seen=now + timedelta(seconds=1)),
        Timed("ip2", "66.249.66.1", "ip", True,
              first_seen=now + timedelta(seconds=2)),
    ]
    groups = group_by_seed(entities, [])
    assert [g.seed.value for g in groups] == [
        "185.191.171.3", "typed-second.example", "66.249.66.1"]
