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

function tabFromHash(hash: string): NativeTab {
  const id = hash.replace(/^#/, "") as NativeTab;
  return TABS.has(id) ? id : "reviews";
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
    return Promise.resolve(window.confirm(message));
  }
  msg.textContent = message;
  box.hidden = false;
  return new Promise((resolve) => {
    const done = (ok: boolean) => {
      box.hidden = true;
      box.removeEventListener("click", onClick);
      resolve(ok);
    };
    const onClick = (event: Event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.closest("[data-confirm-ok]")) done(true);
      else if (target.closest("[data-confirm-cancel]") || target === box) done(false);
    };
    box.addEventListener("click", onClick);
  });
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
  let setupFeedback: "off" | "submit" = "submit";
  let setupScanError: "allow" | "deny" | "review" = "review";

  const paint = () => {
    root.innerHTML = renderNativePage(state, {
      tab,
      canWrite: canWrite(host),
      connected: host.connection.connected,
      now: Date.now(),
      flash,
    });
  };

  const showFlash = (text: string, kind: "ok" | "error") => {
    flash = { text, kind };
    paint();
    if (flashTimer) clearTimeout(flashTimer);
    flashTimer = setTimeout(() => {
      flash = null;
      paint();
    }, 4000);
  };

  const run = async (work: () => Promise<unknown>, okText = "Saved") => {
    try {
      const result = await work();
      if (result && typeof result === "object" && "persisted" in result && (result as { persisted?: boolean }).persisted === false) {
        showFlash(
          String((result as { error?: string }).error || "Applied now, but not saved to openclaw.json."),
          "error",
        );
        return;
      }
      if (result && typeof result === "object" && "ok" in result && (result as { ok?: boolean }).ok === false) {
        showFlash(String((result as { error?: string }).error || "Failed"), "error");
        return;
      }
      showFlash(okText, "ok");
    } catch (err) {
      showFlash(err instanceof Error ? err.message : String(err), "error");
    }
  };

  const onClick = async (event: Event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;

    const tabLink = target.closest("[data-tab]");
    if (tabLink instanceof HTMLElement) {
      event.preventDefault();
      const next = tabLink.getAttribute("data-tab");
      if (next && TABS.has(next as NativeTab)) {
        tab = next as NativeTab;
        history.replaceState(null, "", `#${tab}`);
        paint();
      }
      return;
    }

    if (target.closest("[id='flash']")) {
      flash = null;
      paint();
      return;
    }

    const setupFb = target.closest("[data-setup-feedback]");
    if (setupFb instanceof HTMLElement) {
      setupFeedback = setupFb.getAttribute("data-setup-feedback") === "off" ? "off" : "submit";
      root.querySelectorAll("[data-setup-feedback]").forEach((el) => {
        el.setAttribute("aria-pressed", el === setupFb ? "true" : "false");
      });
      return;
    }
    const setupErr = target.closest("[data-setup-scan-error]");
    if (setupErr instanceof HTMLElement) {
      const value = setupErr.getAttribute("data-setup-scan-error");
      if (value === "allow" || value === "deny" || value === "review") setupScanError = value;
      root.querySelectorAll("[data-setup-scan-error]").forEach((el) => {
        el.setAttribute("aria-pressed", el === setupErr ? "true" : "false");
      });
      return;
    }
    if (target.closest("[data-setup-save]")) {
      const id = (root.querySelector("[data-setup-client-id]") as HTMLInputElement | null)?.value ?? "";
      const secret = (root.querySelector("[data-setup-client-secret]") as HTMLInputElement | null)?.value ?? "";
      await run(
        () =>
          client.invoke("setup", {
            clientId: id,
            clientSecret: secret,
            feedbackMode: setupFeedback,
            onScanError: setupScanError,
          }),
        "Credentials saved",
      );
      return;
    }

    const resolveBtn = target.closest("[data-resolve]");
    if (resolveBtn instanceof HTMLElement) {
      const decision = resolveBtn.getAttribute("data-resolve");
      const id = resolveBtn.getAttribute("data-id") || "";
      if (decision === "allow-once" || decision === "allow-always" || decision === "deny") {
        if (decision === "allow-always") {
          const ok = await confirmDialog(root, "Allow always records a local matcher for this shape. Continue?");
          if (!ok) return;
        }
        const card = root.querySelector(`article.review[data-id="${CSS.escape(id)}"]`);
        const approvalId = card instanceof HTMLElement ? card.getAttribute("data-approval") || undefined : undefined;
        await run(() => client.invoke("resolve", { decision, toolCallId: id, approvalId }), "Resolved");
      }
      return;
    }

    const rm = target.closest("[data-allowlist-rm]");
    if (rm instanceof HTMLElement) {
      const index = Number(rm.getAttribute("data-allowlist-rm"));
      const ok = await confirmDialog(root, "Remove this allowlist entry?");
      if (!ok) return;
      await run(() => client.invoke("allowlist.rm", { index }), "Removed");
      return;
    }

    const sens = target.closest("[data-policy-sensitivity]");
    if (sens instanceof HTMLElement) {
      const value = sens.getAttribute("data-policy-sensitivity");
      if (value) await run(() => client.invoke("policy", { sensitivity: value as never }));
      return;
    }
    const una = target.closest("[data-policy-unattended]");
    if (una instanceof HTMLElement) {
      const value = una.getAttribute("data-policy-unattended");
      if (value) await run(() => client.invoke("policy", { unattendedSensitivity: value as never }));
      return;
    }
    const fb = target.closest("[data-policy-feedback]");
    if (fb instanceof HTMLElement) {
      const value = fb.getAttribute("data-policy-feedback");
      if (value === "off" || value === "submit") await run(() => client.invoke("policy", { feedbackMode: value }));
      return;
    }
    const scanErr = target.closest("[data-policy-scan-error]");
    if (scanErr instanceof HTMLElement) {
      const value = scanErr.getAttribute("data-policy-scan-error");
      if (value === "allow" || value === "deny" || value === "review") {
        await run(() => client.invoke("policy", { onScanError: value }));
      }
      return;
    }
    const allowAll = target.closest("[data-policy-allowall]");
    if (allowAll instanceof HTMLElement) {
      const value = allowAll.getAttribute("data-policy-allowall");
      if (value === "on" || value === "off") await run(() => client.invoke("policy", { allowAllMode: value }));
      return;
    }
    if (target.closest("[data-quiet-set]")) {
      const mode = target.closest("[data-quiet-set]")?.getAttribute("data-quiet-set");
      const raw = (root.querySelector("[data-quiet-value]") as HTMLInputElement | null)?.value?.trim() || "off";
      await run(() => client.invoke("policy", { globalQuiet: mode === "off" ? "off" : raw }));
      return;
    }

    const logBtn = target.closest("[data-log]");
    if (logBtn instanceof HTMLElement) {
      const kind = logBtn.getAttribute("data-log");
      if (kind === "retention") {
        const days = Number((root.querySelector("[data-log-days]") as HTMLInputElement | null)?.value);
        await run(() => client.invoke("log", { maxAgeDays: days }));
      } else if (kind === "purge") {
        const ok = await confirmDialog(root, "Drop operator-log lines older than the retention window?");
        if (!ok) return;
        await run(() => client.invoke("log", { purge: "confirm" }), "Purged");
      } else if (kind === "wipe") {
        const ok = await confirmDialog(root, "Delete the entire operator log? This cannot be undone.");
        if (!ok) return;
        await run(() => client.invoke("log", { wipe: "confirm" }), "Deleted");
      }
      return;
    }

    if (target.closest("[data-verify]")) {
      await run(async () => {
        const result = await client.invoke("verify", {});
        if (!result.ok) throw new Error("Verify failed");
        return result;
      }, "Connection ok");
    }
  };

  root.addEventListener("click", (event) => {
    void onClick(event);
  });

  const stopWatch = client.watch("state", {}, {
    events: STATE_EVENTS,
    onChange: (next) => {
      state = next;
      paint();
    },
    onError: (error) => showFlash(error.message, "error"),
  });

  paint();

  return {
    dispose: () => {
      stopWatch();
      if (flashTimer) clearTimeout(flashTimer);
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
