"""AIRA (WP3): consequence detectors as code over the prepared call, siblings and history, with
versioned YAML data lists under `lists/` (sensitive paths, guardrail, destructive and remote verbs,
privilege, egress, installers, self-modification, extent, weights). Mechanism in code, knowledge in
data (build plan D1, D2).

- `exec_shape`: tree-sitter-bash structure of a shell command (ported from 1.x).
- `path_classes`: path location and group classification, URL hosts (ported from 1.x).
- `normalize`: base64 / hex / quote-concat deobfuscation for matching (ported from 1.x).
- `sensitive_paths`: compiles the path groups of `lists/sensitive_paths.yaml` (ported loader).
- `lists`: the list loader with the `SENTROOK_LISTS_DIR` overlay and the combined ruleset version.
- `analysis`: the shared per-call analysis every detector reads.
- `detectors`: one function per consequence class; `probes.aira.AiraProbe` runs them.
"""

AIRA_VERSION = "aira/2.0.0a1"

__all__ = ["AIRA_VERSION"]
