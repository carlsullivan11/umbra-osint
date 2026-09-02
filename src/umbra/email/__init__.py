"""Email header analysis — parse, judge, and hand off to the existing planner.

Named `umbra.email` rather than `umbra.mail` because that is what it is. It
does not shadow the standard library: Python 3 resolves `import email` inside
this package to the stdlib module, and ours is only ever reachable as
`umbra.email`.

Three steps, deliberately separate:

* `parse`   — headers in, structure out. Marks the Received chain and refuses
              to name an origin the chain cannot justify. No network, no I/O.
* `verdict` — pure judgement over the parse: alignment, authentication, and the
              mismatches that actually indicate spoofing.
* `plan`    — turns the parse into an `IntentPlan`, at which point the existing
              confirm page, narrowing rules, worker dispatch and budgets all
              apply unchanged.
"""

from umbra.email.parse import ParsedEmail, Trust, parse_headers
from umbra.email.plan import plan_from_headers
from umbra.email.verdict import Finding, judge

__all__ = [
    "Finding",
    "ParsedEmail",
    "Trust",
    "judge",
    "parse_headers",
    "plan_from_headers",
]
