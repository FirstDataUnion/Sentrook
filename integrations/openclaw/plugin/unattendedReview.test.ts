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
