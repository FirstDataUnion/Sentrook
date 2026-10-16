# PlanIR test fixtures

Synthetic PlanIR 2.0 requests for unit tests. None of these come from the TestNest suite, which is private
and never enters this repository.

- `worked-example-attack.json`, `worked-example-twin.json`: the worked example from the design page
  ("Data structure skeleton", section 6) and its benign twin. Invented hosts (`cl0ud-sync.io`,
  `backup.mycorp.com`) do not resolve; the agent is `clawbot`; secrets are placeholders. Each file holds
  the PlanIR under `fixture` plus the `state_seed` and `oracle_seed` the test-mode endpoint takes.
