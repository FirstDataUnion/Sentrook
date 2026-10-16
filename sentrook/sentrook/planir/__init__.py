"""PlanIR 2.0: the request a plugin sends (skeleton section 1).

`models` holds the pydantic models; `validate` (WP1) the 1.7 invariants that JSON Schema cannot express;
`canonical` (WP1) the per-platform argument canonicalisation tables.
"""

from .models import PlanIR

__all__ = ["PlanIR"]
