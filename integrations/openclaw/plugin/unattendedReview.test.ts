import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  OPENCLAW_UNATTENDED_PLUGIN_APPROVAL_ISSUE,
  SENTROOK_UNATTENDED_REVIEW_ISSUE,
  UNATTENDED_BLOCK_DECISION,
  unattendedReviewBlockReason,
} from "./unattendedReview.ts";

describe("unattendedReviewBlockReason", () => {
  it("includes allowlist add, sensitivity, and the OpenClaw issue", () => {
    const text = unattendedReviewBlockReason({
      eventId: "sr_abc123",
      sessionKey: "agent:main:cron:nightly:run:r1",
      command: "python3 backup.py --dest /data",
    });
    assert.match(text, /Look at this command\. If you trust it/);
    assert.match(text, /python3 backup\.py --dest \/data/);
    assert.match(text, /\/sentrook allowlist add sr_abc123/);
    assert.match(text, /openclaw sentrook allowlist add sr_abc123/);
    assert.match(text, /\/sentrook sensitivity unattended warning/);
    assert.match(text, /\/sentrook sensitivity session agent:main:cron:nightly:run:r1 unattended warning/);
    assert.match(text, /Allow always/);
    assert.match(text, /Allow-all and quiet do not apply/);
    assert.match(text, /Pipes and curl\|bash cannot be allowlisted/);
    assert.match(text, /specific host and path/);
    assert.ok(text.includes(OPENCLAW_UNATTENDED_PLUGIN_APPROVAL_ISSUE));
    assert.ok(SENTROOK_UNATTENDED_REVIEW_ISSUE.includes("/issues/59"));
    assert.equal(UNATTENDED_BLOCK_DECISION, "unattended-block");
  });
});

describe("unattendedReviewBlockReason — hard reviews", () => {
  const base = { eventId: "sr_deadbeef01", sessionKey: "sess-1", command: "cat ~/.ssh/id_rsa" };

  it("does not offer the sensitivity floor for a hard review", () => {
    // The bug this exists for: the message offered "raise the unattended floor
    // so this severity auto-approves" for every block, and that stopped being
    // true when `review_authority` reached the plugin. An operator following it
    // changes a global setting, the job blocks again, and the setting stays
    // changed.
    const hard = unattendedReviewBlockReason({ ...base, reviewAuthority: "hard" });
    assert.ok(!hard.includes("sensitivity unattended warning"), hard);
    assert.match(hard, /hard review/);
    assert.match(hard, /allowlist above is the only way/);
    // The allowlist route must still be there — it is now the *only* route.
    assert.match(hard, /allowlist add sr_deadbeef01/);
  });

  it("still offers the floor for a soft review", () => {
    // Without this the test above passes against a message that never mentions
    // the floor at all, which would be a regression for every other rule.
    for (const authority of ["soft", undefined]) {
      const soft = unattendedReviewBlockReason({ ...base, reviewAuthority: authority });
      assert.match(soft, /sensitivity unattended warning/, String(authority));
      assert.ok(!soft.includes("hard review"), String(authority));
    }
  });

  it("an engine that does not send the field behaves as before", () => {
    const before = unattendedReviewBlockReason(base);
    const soft = unattendedReviewBlockReason({ ...base, reviewAuthority: "soft" });
    assert.equal(before, soft);
  });
});
