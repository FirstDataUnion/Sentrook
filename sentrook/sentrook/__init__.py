"""Sentrook 2.0: a runtime security scanner for AI agents.

The scanner takes a PlanIR 2.0 request (the agent's pending tool call with its trajectory), runs a set
of independent probes over it, converges their contributions into a risk tree and returns Response 2.0.
Design: Notion, "Sentrook 2.0" and its "Data structure skeleton"; build plan and work packages in
"Sentrook 2.0 build plan".
"""

__version__ = "2.0.0a1"
