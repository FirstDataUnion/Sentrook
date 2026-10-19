"""PlanIR 2.0: the request a plugin sends.

`models` holds the pydantic models; `validate` the structural invariants that JSON Schema cannot express;
`canonical` the per-platform argument canonicalisation tables.
"""

from .models import PlanIR

__all__ = ["PlanIR"]
