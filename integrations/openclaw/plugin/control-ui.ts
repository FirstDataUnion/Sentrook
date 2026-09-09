/**
 * Native Control UI entry for Sentrook.
 *
 * Loaded by OpenClaw 2026.9.2+ when Settings → Labs → Custom plugin UI is on.
 * The host injects this module into the Control UI origin and calls ``activate``.
 * Mutations go through ``plugins.sessionAction`` on the signed-in operator
 * connection — not the GET-only iframe grant.
 */

import "./control-ui.css";
import { SENTROOK_PLUGIN_ID, STATE_EVENTS, type SentrookState } from "./featureContract.ts";
import { createSentrookClient, type FeatureTransport } from "./featureClient.ts";
import { renderNativePage, type NativeTab } from "./controlUiView.ts";
import { SETUP_SUCCESS_RESTART_TOAST, SETUP_SUCCESS_TOAST, quietRemainingPhrase } from "./policyCopy.ts";
import pluginPackage from "./package.json";

const PLUGIN_VERSION = typeof pluginPackage.version === "string" ? pluginPackage.version : "";

type Host = FeatureTransport & {
  connection: FeatureTransport["connection"] & {
    canWrite?: boolean;
    connected: boolean;
  };
  ui: {
    registerPage: (page: {
      id: string;
      label: string;
      mount: (
        container: HTMLElement,
        context: { host: Host; signal: AbortSignal; presented: boolean },
      ) => { update?: (context: { presented: boolean }) => void; dispose?: () => void } | void;
    }) => () => void;
    registerNavigation: (item: {
      id: string;
      label: string;
      page: { id: string };
      icon?: string;
      order?: number;
      defaultVisible?: boolean;
    }) => () => void;
  };
};

const TABS = new Set<NativeTab>(["reviews", "timeline", "allowlist", "settings"]);
const TAB_ALIAS: Record<string, NativeTab> = {
  sessions: "settings",
  log: "settings",
  configure: "settings",
  "set-sessions": "settings",
};

function resolveTab(id: string): NativeTab | null {
  const aliased = TAB_ALIAS[id] ?? id;
  return TABS.has(aliased as NativeTab) ? (aliased as NativeTab) : null;
}

function tabFromHash(hash: string): NativeTab {
  const raw = hash.replace(/^#/, "");
  if (raw.startsWith("tl-")) return "timeline";
  return resolveTab(raw) ?? "reviews";
}

function canWrite(host: Host): boolean {
  return host.connection.canWrite !== false;
}

function emptyState(): SentrookState {
  return {
    pending: [],
    history: [],
    audit: { scanned: 0, allow: 0, review: 0, block: 0, error: 0 },
    sessions: [],
    sensitivity: "strict",
    unattendedSensitivity: "strict",
    allowAll: false,
    quietUntilMs: null,
    feedbackMode: "submit",
    onScanError: "review",
    log: { enabled: true, path: "", bytes: 0, lines: 0, maxAgeDays: 14, maxBytes: 32 * 1024 * 1024 },
    allowlist: [],
    resolveAvailable: false,
    setupNeeded: false,
  };
}

function confirmDialog(root: HTMLElement, message: string): Promise<boolean> {
  const box = root.querySelector("#confirm");
  const msg = root.querySelector("#confirm-msg");
  if (!(box instanceof HTMLElement) || !(msg instanceof HTMLElement)) {
    return Promise.resolve(true);
  }
  msg.textContent = message;
  box.hidden = false;
  return new Promise((resolve) => {
    const done = (ok: boolean) => {
      box.hidden = true;
      box.removeEventListener("click", onClick, true);
      resolve(ok);
    };
    const onClick = (event: Event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.closest("[data-confirm-ok]")) {
        event.preventDefault();
        event.stopPropagation();
        done(true);
      } else if (target.closest("[data-confirm-cancel]")) {
        event.preventDefault();
        event.stopPropagation();
        done(false);
      }
    };
    box.addEventListener("click", onClick, true);
  });
}

function fmtAge(fromMs: number): string {
  const sec = Math.max(0, Math.round((Date.now() - fromMs) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  return `${Math.round(min / 60)}h ago`;
}

function fmtRemain(created: number, timeout: number): string {
  const left = created + timeout - Date.now();
  if (left <= 0) return "timed out";
  const sec = Math.round(left / 1000);
  if (sec < 60) return `${sec}s left`;
  const min = Math.floor(sec / 60);
  return `${min}m ${sec % 60}s left`;
}

function tickClocks(root: HTMLElement): void {
  root.querySelectorAll("article.review[data-created]").forEach((el) => {
    const created = Number(el.getAttribute("data-created"));
    const timeout = Number(el.getAttribute("data-timeout") || "0");
    const age = el.querySelector(".age");
    const remain = el.querySelector(".remain");
    if (age) age.textContent = fmtAge(created);
    if (remain && timeout) remain.textContent = fmtRemain(created, timeout);
  });
  root.querySelectorAll("[data-quiet-until]").forEach((el) => {
    const until = Number(el.getAttribute("data-quiet-until"));
    if (!Number.isFinite(until)) return;
    el.textContent = quietRemainingPhrase(until, Date.now());
  });
}

function escText(value: unknown): string {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setPressed(root: ParentNode, clicked: Element, selector: string): void {
  const group = clicked.closest("[role='group']") || clicked.parentElement || root;
  group.querySelectorAll(selector).forEach((btn) => {
    btn.setAttribute("aria-pressed", btn === clicked ? "true" : "false");
  });
}

function detailsOpenKey(el: HTMLDetailsElement): string {
  if (el.id) return el.id;
  const owner = el.closest("[id]");
  const summary = el.querySelector(":scope > summary");
  const label = (summary?.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 100);
  return `${owner instanceof HTMLElement && owner.id ? owner.id : "anon"}::${label}`;
}

function collectOpenDetails(root: HTMLElement): string[] {
  return [...root.querySelectorAll("details[open]")].flatMap((el) =>
    el instanceof HTMLDetailsElement ? [detailsOpenKey(el)] : [],
  );
}

function restoreOpenDetails(root: HTMLElement, keys: readonly string[]): void {
  if (!keys.length) return;
  const want = new Set(keys);
  root.querySelectorAll("details").forEach((el) => {
    if (el instanceof HTMLDetailsElement && want.has(detailsOpenKey(el))) el.open = true;
  });
}

function openHashTarget(root: HTMLElement): void {
  const id = location.hash.replace(/^#/, "");
  if (!id || resolveTab(id) || id === "sessions" || id === "log" || id === "configure" || id === "set-sessions") {
    return;
  }
  const el = root.querySelector(`[id="${CSS.escape(id)}"]`);
  if (!(el instanceof HTMLElement)) return;
  if (el instanceof HTMLDetailsElement) el.open = true;
  const page = root.querySelector(".page");
  if (page instanceof HTMLElement) {
    const br = el.getBoundingClientRect();
    const pr = page.getBoundingClientRect();
    page.scrollTop += br.top - pr.top - 24;
  } else {
    el.scrollIntoView({ block: "start" });
  }
}

function mountSentrookPage(
  container: HTMLElement,
  context: { host: Host; signal: AbortSignal; presented: boolean },
): { dispose: () => void } {
  const host = context.host;
  const client = createSentrookClient(host);
  const root = document.createElement("div");
  root.className = "srk";
  container.replaceChildren(root);

  let state = emptyState();
  let tab: NativeTab = tabFromHash(location.hash);
  let flash: { text: string; kind: "ok" | "error" } | null = null;
  let flashTimer: ReturnType<typeof setTimeout> | undefined;
  let clockTimer: ReturnType<typeof setInterval> | undefined;
  let preserveScroll = false;
  let pageScroll = 0;
  let verifyHtml: string | null = null;

  let tlSearch = "";
  let tlDecision = "";
  let tlView = "stream";
  let tlSession = "";

  let setupClientId = "";
  let setupClientSecret = "";
  let setupFeedback: "off" | "submit" = "submit";
  let setupScanError: "allow" | "deny" | "review" = "review";

  const timelinePanel = (): HTMLElement | null => {
    const panel = root.querySelector('[data-panel="timeline"]');
    return panel instanceof HTMLElement ? panel : null;
  };

  const timelineItems = (panel: HTMLElement): HTMLElement[] =>
    [...panel.querySelectorAll("[data-tl-item]")].filter((el): el is HTMLElement => el instanceof HTMLElement);

  const applyTimelineLayout = (panel: HTMLElement) => {
    const view = panel.getAttribute("data-filter-view") || "stream";
    const list = panel.querySelector("[data-tl-list]");
    const grouped = panel.querySelector("[data-tl-grouped]");
    if (!(list instanceof HTMLElement) || !(grouped instanceof HTMLElement)) return;
    const items = timelineItems(panel).sort(
      (a, b) => Number(a.getAttribute("data-i")) - Number(b.getAttribute("data-i")),
    );
    if (view !== "session") {
      items.forEach((el) => list.appendChild(el));
      grouped.replaceChildren();
      grouped.hidden = true;
      list.hidden = false;
      return;
    }
    const order: string[] = [];
    const map = new Map<string, HTMLElement[]>();
    for (const el of items) {
      const key = el.getAttribute("data-session") || "No session";
      if (!map.has(key)) {
        map.set(key, []);
        order.push(key);
      }
      map.get(key)!.push(el);
    }
    grouped.replaceChildren();
    for (const key of order) {
      const sec = document.createElement("section");
      sec.className = "tl-group";
      const h = document.createElement("h3");
      h.textContent = key;
      const ol = document.createElement("div");
      ol.className = "stream";
      const els = map.get(key) || [];
      for (const el of els) ol.appendChild(el);
      sec.appendChild(h);
      sec.appendChild(ol);
      sec.hidden = !els.some((el) => !el.hidden);
      grouped.appendChild(sec);
    }
    list.hidden = true;
    grouped.hidden = false;
  };

  const applyTimelineFilters = () => {
    const panel = timelinePanel();
    if (!panel) return;
    panel.setAttribute("data-filter-session", tlSession);
    panel.setAttribute("data-filter-decision", tlDecision);
    panel.setAttribute("data-filter-q", tlSearch);
    panel.setAttribute("data-filter-view", tlView);
    const search = panel.querySelector("[data-tl-search]");
    if (search instanceof HTMLInputElement && search.value !== tlSearch) search.value = tlSearch;
    const decision = tlDecision;
    const session = tlSession;
    const q = tlSearch.trim().toLowerCase();
    const view = tlView || "stream";
    let visible = 0;
    const items = timelineItems(panel);
    items.forEach((el) => {
      const okD = !decision || el.getAttribute("data-tone") === decision;
      const okS = !session || el.getAttribute("data-session") === session;
      const blob = (el.getAttribute("data-tl-blob") || "").toLowerCase();
      const okQ = !q || blob.includes(q);
      el.hidden = !(okD && okS && okQ);
      if (!el.hidden) visible += 1;
    });
    applyTimelineLayout(panel);
    panel.querySelectorAll("[data-tl-decision]").forEach((b) => {
      b.setAttribute("aria-pressed", b.getAttribute("data-tl-decision") === decision ? "true" : "false");
    });
    panel.querySelectorAll("[data-tl-session-filter]").forEach((b) => {
      b.setAttribute(
        "aria-pressed",
        (b.getAttribute("data-tl-session-filter") || "") === session ? "true" : "false",
      );
    });
    panel.querySelectorAll("[data-tl-view]").forEach((b) => {
      b.setAttribute("aria-pressed", b.getAttribute("data-tl-view") === view ? "true" : "false");
    });
    const empty = panel.querySelector("[data-tl-empty]");
    if (empty instanceof HTMLElement) empty.hidden = visible > 0;
    const count = panel.querySelector("[data-tl-count]");
    if (count instanceof HTMLElement) {
      count.textContent = items.length
        ? visible === items.length
          ? `Newest ${items.length} scans`
          : `Showing ${visible} of ${items.length} newest`
        : "";
    }
  };

  const restoreSetupFields = () => {
    const idEl = root.querySelector("[data-setup-client-id]");
    const secretEl = root.querySelector("[data-setup-client-secret]");
    if (idEl instanceof HTMLInputElement) idEl.value = setupClientId;
    if (secretEl instanceof HTMLInputElement) secretEl.value = setupClientSecret;
    root.querySelectorAll("[data-setup-feedback]").forEach((el) => {
      el.setAttribute(
        "aria-pressed",
        el.getAttribute("data-setup-feedback") === setupFeedback ? "true" : "false",
      );
    });
    root.querySelectorAll("[data-setup-scan-error]").forEach((el) => {
      el.setAttribute(
        "aria-pressed",
        el.getAttribute("data-setup-scan-error") === setupScanError ? "true" : "false",
      );
    });
  };

  const restoreVerify = () => {
    if (!verifyHtml) return;
    const box = root.querySelector("[data-verify-result]");
    if (box instanceof HTMLElement) {
      box.hidden = false;
      box.innerHTML = verifyHtml;
    }
  };

  const paint = () => {
    const page = root.querySelector(".page");
    if (preserveScroll && page instanceof HTMLElement) pageScroll = page.scrollTop;
    const openKeys = collectOpenDetails(root);
    root.innerHTML = renderNativePage(state, {
      tab,
      canWrite: canWrite(host),
      connected: host.connection.connected,
      now: Date.now(),
      version: PLUGIN_VERSION,
      flash,
    });
    restoreOpenDetails(root, openKeys);
    restoreSetupFields();
    applyTimelineFilters();
    restoreVerify();
    tickClocks(root);
    const nextPage = root.querySelector(".page");
    if (preserveScroll && nextPage instanceof HTMLElement) nextPage.scrollTop = pageScroll;
    else if (nextPage instanceof HTMLElement) nextPage.scrollTop = 0;
    if (preserveScroll) {
      const id = location.hash.replace(/^#/, "");
      if (id.startsWith("tl-")) {
        const el = root.querySelector(`[id="${CSS.escape(id)}"]`);
        if (el instanceof HTMLDetailsElement) el.open = true;
      }
    } else {
      openHashTarget(root);
    }
  };

  const showFlash = (text: string, kind: "ok" | "error") => {
    flash = { text, kind };
    preserveScroll = true;
    paint();
    if (flashTimer) clearTimeout(flashTimer);
    flashTimer = setTimeout(() => {
      flash = null;
      preserveScroll = true;
      paint();
    }, kind === "error" ? 14000 : 4000);
  };

  const run = async (work: () => Promise<unknown>, okText = "Saved") => {
    try {
      const result = await work();
      if (result && typeof result === "object" && "ok" in result && (result as { ok?: boolean }).ok === false) {
        showFlash(String((result as { error?: string }).error || "Failed"), "error");
        return result;
      }
      if (result && typeof result === "object" && "persisted" in result && (result as { persisted?: boolean }).persisted === false) {
        showFlash(
          String((result as { error?: string }).error || "Applied now, but not saved to openclaw.json."),
          "error",
        );
        return result;
      }
      showFlash(okText, "ok");
      return result;
    } catch (err) {
      showFlash(err instanceof Error ? err.message : String(err), "error");
      return undefined;
    }
  };

  const onSessionSensChange = async (event: Event) => {
    const target = event.target;
    if (!(target instanceof HTMLSelectElement)) return;
    const scope = target.getAttribute("data-session-sens");
    if (scope !== "attended" && scope !== "unattended") return;
    if (!canWrite(host)) {
      target.value = target.getAttribute("data-current") || "default";
      return;
    }
    const value = target.value.trim().toLowerCase();
    const prev = target.getAttribute("data-current") || "default";
    if (value === "critical") {
      const msg =
        scope === "unattended"
          ? "Auto-approve every unattended review in this session, including critical? This overrides the global unattended floor for this session until you set Default."
          : "Auto-approve every attended review in this session, including critical? This overrides the global attended floor, allow-all, and quiet for this session until you set Default.";
      if (!(await confirmDialog(root, msg))) {
        target.value = prev;
        return;
      }
    }
    const field = scope === "unattended" ? "sessionUnattendedSensitivity" : "sessionAttendedSensitivity";
    await run(() =>
      client.invoke("policy", {
        sessionId: target.getAttribute("data-sid") || undefined,
        sessionKey: target.getAttribute("data-skey") || undefined,
        [field]: value,
      }),
    );
  };

  const showTab = (rawId: string, keepScroll = false) => {
    const next = resolveTab(rawId) ?? (rawId.startsWith("tl-") ? "timeline" : null);
    if (!next) return;
    tab = next;
    const hash = rawId.startsWith("tl-") ? rawId : next;
    try {
      history.replaceState(null, "", `#${hash}`);
    } catch {
      /* host may disallow */
    }
    preserveScroll = keepScroll;
    paint();
  };

  const openTimelineSession = (key: string) => {
    tlSession = key || "";
    tlDecision = "";
    tlSearch = "";
    tab = "timeline";
    try {
      history.replaceState(null, "", "#timeline");
    } catch {
      /* host may disallow */
    }
    preserveScroll = false;
    paint();
  };

  const onClick = async (event: Event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.closest("#confirm")) return;

    if (target.id === "flash" || target.closest("#flash")) {
      flash = null;
      preserveScroll = true;
      paint();
      return;
    }

    const tabLink = target.closest("[data-tab]");
    if (tabLink instanceof HTMLElement) {
      event.preventDefault();
      const next = tabLink.getAttribute("data-tab");
      if (next) showTab(next);
      return;
    }

    const openSess = target.closest("[data-tl-open-session]");
    if (openSess instanceof HTMLElement) {
      event.preventDefault();
      openTimelineSession(openSess.getAttribute("data-tl-open-session") || "");
      return;
    }

    const tlDecisionBtn = target.closest("[data-tl-decision]");
    if (tlDecisionBtn instanceof HTMLElement) {
      tlDecision = tlDecisionBtn.getAttribute("data-tl-decision") || "";
      applyTimelineFilters();
      return;
    }
    const tlViewBtn = target.closest("[data-tl-view]");
    if (tlViewBtn instanceof HTMLElement) {
      tlView = tlViewBtn.getAttribute("data-tl-view") || "stream";
      applyTimelineFilters();
      return;
    }
    const tlSessBtn = target.closest("[data-tl-session-filter]");
    if (tlSessBtn instanceof HTMLElement) {
      tlSession = tlSessBtn.getAttribute("data-tl-session-filter") || "";
      applyTimelineFilters();
      return;
    }

    const copyBtn = target.closest("[data-copy-target]");
    if (copyBtn instanceof HTMLElement) {
      const id = copyBtn.getAttribute("data-copy-target") || "";
      const src = id ? root.querySelector(`#${CSS.escape(id)}`) : null;
      const text = src ? src.textContent || "" : "";
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        showFlash("Could not copy", "error");
        return;
      }
      const prev = copyBtn.textContent;
      copyBtn.textContent = "Copied";
      setTimeout(() => {
        copyBtn.textContent = prev;
      }, 1200);
      return;
    }

    if (!canWrite(host)) return;

    const setupFb = target.closest("[data-setup-feedback]");
    if (setupFb instanceof HTMLElement) {
      setupFeedback = setupFb.getAttribute("data-setup-feedback") === "off" ? "off" : "submit";
      const group = setupFb.closest("[data-setup-feedback-group]") || root;
      group.querySelectorAll("[data-setup-feedback]").forEach((el) => {
        el.setAttribute("aria-pressed", el === setupFb ? "true" : "false");
      });
      return;
    }
    const setupErr = target.closest("[data-setup-scan-error]");
    if (setupErr instanceof HTMLElement) {
      const value = setupErr.getAttribute("data-setup-scan-error");
      if (value === "allow") {
        const ok = await confirmDialog(
          root,
          "Continue tool calls without scanning when Sentrook is unreachable? Auth failures still block.",
        );
        if (!ok) return;
      }
      if (value === "allow" || value === "deny" || value === "review") setupScanError = value;
      const group = setupErr.closest("[data-setup-scan-error-group]") || root;
      group.querySelectorAll("[data-setup-scan-error]").forEach((el) => {
        el.setAttribute("aria-pressed", el === setupErr ? "true" : "false");
      });
      return;
    }
    if (target.closest("[data-setup-save]")) {
      const id = (root.querySelector("[data-setup-client-id]") as HTMLInputElement | null)?.value ?? "";
      const secret = (root.querySelector("[data-setup-client-secret]") as HTMLInputElement | null)?.value ?? "";
      const feedbackBtn = root.querySelector("[data-setup-feedback][aria-pressed='true']");
      const scanBtn = root.querySelector("[data-setup-scan-error][aria-pressed='true']");
      const feedbackMode =
        feedbackBtn instanceof HTMLElement && feedbackBtn.getAttribute("data-setup-feedback") === "off"
          ? "off"
          : "submit";
      const onScanErrorRaw = scanBtn instanceof HTMLElement ? scanBtn.getAttribute("data-setup-scan-error") : "review";
      const onScanError =
        onScanErrorRaw === "allow" || onScanErrorRaw === "deny" || onScanErrorRaw === "review"
          ? onScanErrorRaw
          : "review";
      setupClientId = id;
      setupClientSecret = secret;
      try {
        const result = await client.invoke("setup", {
          clientId: id,
          clientSecret: secret,
          feedbackMode,
          onScanError,
        });
        if (!result.ok) {
          showFlash(result.error || "Those credentials were not accepted. Try again.", "error");
          return;
        }
        showFlash(result.restartHint ? SETUP_SUCCESS_RESTART_TOAST : SETUP_SUCCESS_TOAST, "ok");
      } catch (err) {
        showFlash(err instanceof Error ? err.message : String(err), "error");
      }
      return;
    }

    const actBtn = target.closest("[data-act]");
    if (actBtn instanceof HTMLElement && actBtn.getAttribute("data-tool")) {
      const decision = actBtn.getAttribute("data-act");
      const toolCallId = actBtn.getAttribute("data-tool") || "";
      if (decision === "allow-once" || decision === "allow-always" || decision === "deny") {
        const cardEl = actBtn.closest("article.review");
        if (decision === "allow-always" && cardEl instanceof HTMLElement && cardEl.getAttribute("data-severity") === "critical") {
          const ok = await confirmDialog(
            root,
            "Allow always on a critical review? Only confirm if you trust this pattern.",
          );
          if (!ok) return;
        }
        const pending = state.pending.find((card) => card.toolCallId === toolCallId);
        await run(
          () =>
            client.invoke("resolve", {
              decision,
              toolCallId,
              approvalId: pending?.approvalId,
            }),
          `Resolved ${decision}`,
        );
      }
      return;
    }

    const rm = target.closest("[data-allow-rm]");
    if (rm instanceof HTMLElement) {
      const index = Number(rm.getAttribute("data-allow-rm"));
      const ok = await confirmDialog(root, "Remove this allowlist entry?");
      if (!ok) return;
      await run(() => client.invoke("allowlist.rm", { index }), "Removed from allowlist");
      return;
    }

    const allowMode = target.closest("[data-allow-mode]");
    if (allowMode instanceof HTMLElement) {
      const mode = allowMode.getAttribute("data-allow-mode");
      if (mode === "on" || mode === "off") {
        if (mode === "on" && !state.allowAll) {
          const ok = await confirmDialog(
            root,
            "Auto-accept every attended review, including critical? Scan still runs. Blocks, scan errors, and unattended runs still stop. Cards already waiting are not resolved.",
          );
          if (!ok) return;
        }
        await run(() => client.invoke("policy", { allowAllMode: mode }));
        setPressed(root, allowMode, "[data-allow-mode]");
      }
      return;
    }

    const quietGlobal = target.closest("[data-quiet-global]");
    if (quietGlobal instanceof HTMLElement) {
      const value = quietGlobal.getAttribute("data-quiet-global");
      if (value) {
        await run(() => client.invoke("policy", { globalQuiet: value }));
        setPressed(root, quietGlobal, "[data-quiet-global]");
      }
      return;
    }

    const policyBtn = target.closest("[data-policy]");
    if (policyBtn instanceof HTMLElement) {
      const kind = policyBtn.getAttribute("data-policy");
      await run(() =>
        client.invoke("policy", {
          sessionId: policyBtn.getAttribute("data-sid") || undefined,
          sessionKey: policyBtn.getAttribute("data-skey") || undefined,
          allowAll: kind === "allow-all" ? policyBtn.getAttribute("data-on") === "1" : undefined,
          quiet: kind === "quiet" ? (policyBtn.getAttribute("data-on") === "1" ? "30m" : "off") : undefined,
        }),
      );
      return;
    }

    const sens = target.closest("[data-sens]");
    if (sens instanceof HTMLElement) {
      const value = sens.getAttribute("data-sens");
      const scope = sens.getAttribute("data-sens-scope") === "unattended" ? "unattended" : "attended";
      if (value === "critical") {
        const msg =
          scope === "unattended"
            ? "Auto-approve every review on cron, heartbeat, and jobs they spawn, including critical? Nobody will be asked. Blocks and scan errors still stop. This persists in openclaw.json."
            : "Auto-approve every review, including critical ones? Blocks, scan errors, and the unattended floor are separate. This persists in openclaw.json.";
        if (!(await confirmDialog(root, msg))) return;
      }
      if (value) {
        await run(() =>
          client.invoke(
            "policy",
            scope === "unattended" ? { unattendedSensitivity: value as never } : { sensitivity: value as never },
          ),
        );
        setPressed(
          root,
          sens,
          scope === "unattended" ? "[data-sens-scope='unattended']" : "[data-sens]:not([data-sens-scope='unattended'])",
        );
      }
      return;
    }

    const fb = target.closest("[data-feedback]");
    if (fb instanceof HTMLElement) {
      const value = fb.getAttribute("data-feedback");
      if (value === "off" || value === "submit") {
        await run(() => client.invoke("policy", { feedbackMode: value }));
        setPressed(root, fb, "[data-feedback]");
      }
      return;
    }

    const scanErr = target.closest("[data-scan-error]");
    if (scanErr instanceof HTMLElement) {
      const value = scanErr.getAttribute("data-scan-error");
      if (value === "allow") {
        if (
          !(await confirmDialog(
            root,
            "Continue tool calls without scanning when Sentrook is unreachable? Auth failures still block.",
          ))
        ) {
          return;
        }
      }
      if (value === "allow" || value === "deny" || value === "review") {
        await run(() => client.invoke("policy", { onScanError: value }));
        setPressed(root, scanErr, "[data-scan-error]");
      }
      return;
    }

    const logBtn = target.closest("[data-log]");
    if (logBtn instanceof HTMLElement) {
      const kind = logBtn.getAttribute("data-log");
      if (kind === "save") {
        const daysEl = root.querySelector("[data-log-days]");
        const mibEl = root.querySelector("[data-log-mib]");
        const maxAgeDays = daysEl instanceof HTMLInputElement ? Number(daysEl.value) : undefined;
        const mib = mibEl instanceof HTMLInputElement ? Number(mibEl.value) : undefined;
        await run(() =>
          client.invoke("log", {
            maxAgeDays,
            maxBytes: Number.isFinite(mib) ? Math.round(mib * 1024 * 1024) : undefined,
          }),
        );
      } else if (kind === "purge") {
        const ok = await confirmDialog(
          root,
          "Drop operator-log lines older than the retention window? This cannot be undone.",
        );
        if (!ok) return;
        await run(() => client.invoke("log", { purge: "confirm" }), "Purged");
      } else if (kind === "wipe") {
        const ok = await confirmDialog(
          root,
          "Delete the entire local operator log, including the rotated copy? Timeline will go empty. This cannot be undone.",
        );
        if (!ok) return;
        await run(() => client.invoke("log", { wipe: "confirm" }), "Deleted");
      }
      return;
    }

    if (target.closest("[data-verify]")) {
      await run(async () => {
        const result = await client.invoke("verify", {});
        const checks = Array.isArray(result.checks) ? result.checks : [];
        verifyHtml = `<ul>${checks
          .map((c) => {
            const rec = c && typeof c === "object" ? (c as { ok?: boolean; name?: unknown; detail?: unknown }) : {};
            const name = escText(rec.name);
            const detail = escText(rec.detail);
            return `<li class="${rec.ok ? "ok" : "fail"}">${rec.ok ? "Pass" : "Fail"} · ${name} — ${detail}</li>`;
          })
          .join("")}</ul>`;
        const box = root.querySelector("[data-verify-result]");
        if (box instanceof HTMLElement) {
          box.hidden = false;
          box.innerHTML = verifyHtml;
        }
        if (!result.ok) throw new Error("Connection checks failed. See the list below.");
        return result;
      }, "Connection checks passed.");
    }
  };

  root.addEventListener("click", (event) => {
    void onClick(event);
  });

  root.addEventListener("change", (event) => {
    void onSessionSensChange(event);
  });

  root.addEventListener("input", (event) => {
    const t = event.target;
    if (!(t instanceof HTMLInputElement)) return;
    if (t.dataset.setupClientId != null) setupClientId = t.value;
    if (t.dataset.setupClientSecret != null) setupClientSecret = t.value;
    if (t.dataset.tlSearch != null) {
      tlSearch = t.value;
      applyTimelineFilters();
    }
  });

  const onHashChange = () => {
    const id = location.hash.replace(/^#/, "");
    if (resolveTab(id) || id.startsWith("tl-") || !id) showTab(id || "reviews", true);
    else openHashTarget(root);
  };
  window.addEventListener("hashchange", onHashChange);

  const stopWatch = client.watch("state", {}, {
    events: STATE_EVENTS,
    onChange: (next) => {
      state = next;
      preserveScroll = true;
      paint();
    },
    onError: (error) => showFlash(error.message, "error"),
  });

  paint();
  clockTimer = setInterval(() => tickClocks(root), 1000);

  return {
    dispose: () => {
      stopWatch();
      window.removeEventListener("hashchange", onHashChange);
      if (flashTimer) clearTimeout(flashTimer);
      if (clockTimer) clearInterval(clockTimer);
      root.replaceChildren();
    },
  };
}

function activate(host: Host): () => void {
  const page = host.ui.registerPage({
    id: "sentrook-page",
    label: "Sentrook",
    mount: (container, context) => mountSentrookPage(container, context),
  });
  const nav = host.ui.registerNavigation({
    id: "sentrook-nav",
    label: "Sentrook",
    page: { id: "sentrook-page" },
    icon: "shield",
    order: 25,
    defaultVisible: true,
  });
  return () => {
    page();
    nav();
  };
}

const plugin = { id: SENTROOK_PLUGIN_ID, activate };
export default plugin;
