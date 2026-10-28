/**
 * Host-side redaction, applied to everything that leaves the host (the PlanIR sent to Sentrook and
 * the local traffic log).
 *
 * `standard` replaces secrets with `⟦secret:<kind>:<ref>⟧`. The ref is a keyed hash of the value, so
 * the same secret gets the same placeholder across steps of a session without the value ever being
 * stored. Recipients, hosts and email addresses stay: the scanner needs them to judge whether a call
 * matches the request. Content is capped head and tail, since a payload placed after a cut-off is
 * the obvious evasion.
 *
 * Every pattern does bounded work per position (no nested quantifiers; quoted values use the
 * unrolled `[^"\\]*(?:\\.[^"\\]*)*` form).
 */

import { createHmac } from "node:crypto";

export type RedactionLevel = "off" | "standard" | "strict";

export interface Redactor {
  level: RedactionLevel;
  string(text: string): string;
  value<T>(value: T): T;
}

interface Shape {
  kind: string;
  re: RegExp;
  /** Replace only this named group; the rest of the match (a key, a scheme) stays. */
  group?: string;
  /** A match counts only when its value passes this check. */
  check?: (value: string) => boolean;
}

const KEY_NAMES =
  "api[_-]?key|apikey|secret[_-]?key|secret|token|access[_-]?key|private[_-]?key|passw(?:or)?d|passwd|passphrase" +
  "|client[_-]?secret|auth[_-]?token|bearer";
/**
 * A key that ends in a credential word: `GITHUB_TOKEN`, `api_key`, `secretAccessKey`, `logintoken`, and `tok`.
 * A key with letters before its credential word starts at a word boundary; a bare credential word may follow
 * `_` (`MY_VERY_LONG_SERVICE_NAME_TOKEN`). A key right after `/` (a URL segment) or `⟦` (a placeholder label)
 * does not count.
 */
const CREDENTIAL_KEY =
  `(?:(?<![A-Za-z0-9/⟦_.-])[A-Za-z0-9_.-]{1,40}(?:${KEY_NAMES})|(?<![A-Za-z0-9/⟦])(?:${KEY_NAMES}|tok))(?![A-Za-z0-9])`;

/** Words that introduce a secret in prose: "the database password is X", "gateway token X". */
const PROSE_CUES = "password|passwd|passphrase|token|secret|api[ _-]?key|bearer";
/** A prose value: up to 200 characters without spaces or quotes; trailing punctuation is not part of it. */
const PROSE_VALUE = "[\"'`]?(?![0-9]{1,5}(?![0-9A-Za-z]))(?<v>[^\\s\"'`⟦⟧$<>\\\\]{5,199}[^\\s\"'`⟦⟧$<>\\\\.,;:!?)\\]])";
/**
 * Words, not secrets: one or more words with at most a capital first letter, maybe hyphenated (`required`,
 * `Read-only`, `ENABLED`), an identifier (`accessToken`, `GITHUB_TOKEN`), or a hyphenated name with two or
 * more plain words in it (`gpt-4o-mini`, `min-length-12`).
 */
const ORDINARY_WORD = /^(?:[A-Za-z][a-z]*(?:-[A-Za-z][a-z]*)*|[A-Z]+|[a-z]+(?:[A-Z][a-z]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)$/;
const isOrdinary = (v: string) => ORDINARY_WORD.test(v) || v.split("-").filter((p) => /^[a-z]{2,}$/.test(p)).length >= 2;
/**
 * What a sentence names: paths, URLs, masks and templates, code, dates, hex addresses, key fingerprints,
 * email addresses, host and file names (a host may carry a port and a path) and relative paths to a file.
 */
const NAMED_THING =
  /^[/~.*{\[(]|:\/\/|\(|^[0-9]{4}-[0-9]{2}-[0-9]{2}|^0x[0-9a-fA-F]{40}$|^(?:SHA256|MD5):|^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$|^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.[a-z]{2,24}(?::[0-9]{1,5})?(?:\/[A-Za-z0-9._~%\/-]*)?$|^(?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_-]+\.[a-z0-9]{1,8}$/;

/**
 * Not a key's value: a URL (the URL rule takes any password inside it and the host stays) or the name of
 * an environment variable (`token: GITHUB_TOKEN`).
 */
const keyValue = (v: string) => !v.includes("://") && !/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v);
/** An upper-case name with a credential word inside it names many things; only a long value counts. */
const innerKeyValue = (v: string) => v.length >= 12 && keyValue(v);
/** After "password is" or "token:": six or more characters that are not words or a number. */
const statedValue = (v: string) => v.length >= 6 && !isOrdinary(v) && !/^[0-9]+$/.test(v) && !NAMED_THING.test(v);
/** Straight after a cue word ("backup key X"): twelve or more characters with letters and digits. */
const bareValue = (v: string) =>
  v.length >= 12 && /[A-Za-z]/.test(v) && /[0-9]/.test(v) && !isOrdinary(v) && !NAMED_THING.test(v);

/**
 * A command-line value: not a variable reference (`$DB_PASSWORD`) and not something a sentence names (a path,
 * URL, mask or template), so `--secret-file PATH` keeps its path.
 */
const flagValue = (v: string) => !v.startsWith("$") && !NAMED_THING.test(v);
/**
 * After a flag with a suffix, which often names a setting (`--token-ttl 3600`, `--auth-type basic`,
 * `--password-file secrets/db`): also not a word, a number or a path.
 */
const suffixedFlagValue = (v: string) => flagValue(v) && !isOrdinary(v) && !/^[0-9]+$/.test(v) && !/[/\\]/.test(v);
/**
 * After a MySQL client's `-p`: also not a word or a port mapping, which belong to another command on the line
 * (`find / -name mysql -prune`, `docker run --name mysql -p3306:3306`).
 */
const mysqlPassword = (v: string) => flagValue(v) && !isOrdinary(v) && !/^[0-9]{1,5}:[0-9]/.test(v);
/**
 * A command-line value, without its quotes: quoted, up to 256 characters (plain, or with escaped quotes as in a
 * JSON-encoded result), or bare up to a quote or the end of the command. A bare value keeps an escaped
 * character but ends at an escaped quote, newline or tab, so the JSON around it stays.
 */
const FLAG_VALUE = `(?:\\\\?["'])?(?<v>(?!⟦)(?:(?<=\\\\")[^"\\\\]{1,256}(?=\\\\")|(?<=")(?<!\\\\")(?:[^"\\\\]|\\\\.){1,256}(?=")|(?<=')(?:[^'\\\\]|\\\\.){1,256}(?=')|(?<![\\\\"'])[^\\s;|&⟦"'\\\\-](?:[^\\s;|&"'\\\\]|\\\\[^\\s"nrt])*))`;

/**
 * "password is X", "the password is now X", "the token for prod: X". The words between cue and value stay
 * inside one clause and one quoted string and never reach into a placeholder; a cue inside a path, host or
 * name (`/token:8443`, `x.secret`) does not count.
 */
const proseStated = (cues: string) =>
  new RegExp(
    `(?<![A-Za-z0-9_/.⟦-])(?:${cues})(?![A-Za-z0-9_])[^\\n:.;=\"'\`⟦]{0,40}?` +
      `(?:\\s(?:is|was)(?:\\s+(?:now|still|currently|set\\s+to|changed\\s+to))?\\s+|:[ \\t]*)${PROSE_VALUE}`,
    "gi",
  );
/** "gateway token X", "secret X". */
const proseBare = (cues: string) => new RegExp(`(?<![A-Za-z0-9_/.⟦-])(?:${cues})[ \\t]+${PROSE_VALUE}`, "gi");

/**
 * Kinds name a value's own shape (`github`, `jwt`, `private_key`). Every rule that finds a value by its
 * context (a key, a header, a sentence, a URL) says `credential`, so one value gets one placeholder
 * whichever rule found it.
 */
const SHAPES: Shape[] = [
  {
    // The whole block up to its END line, whatever the body holds (escaped `\n` in a JSON-encoded result,
    // PGP armour headers); a block cut off before its END line runs over the base64 body. The body never
    // holds a run of five dashes, so the search for END stops at the next armour line.
    kind: "private_key",
    re: /-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----(?:(?:[^-]|-(?!----)){0,8000}-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----|[A-Za-z0-9+/=\\\r\n \t]{0,8000})/g,
  },
  { kind: "jwt", re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { kind: "openai", re: /sk-(?:proj|svcacct|admin|live)-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g },
  { kind: "anthropic", re: /sk-ant-[A-Za-z0-9_-]{10,}/g },
  { kind: "github", re: /gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/g },
  { kind: "gitlab", re: /glpat-[A-Za-z0-9_-]{20,}/g },
  { kind: "slack", re: /xox[baprs]-[A-Za-z0-9-]{10,}|xoxe(?:\.xox[bp])?-\d-[A-Za-z0-9]+|xapp-\d-[A-Za-z0-9-]+/gi },
  { kind: "slack_webhook", re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/_-]+/g },
  { kind: "discord_webhook", re: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
  { kind: "telegram", re: /\b\d{5,16}:A[A-Za-z0-9_-]{34}\b/g },
  { kind: "npm", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { kind: "aws_access_key", re: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { kind: "google_api_key", re: /AIza[0-9A-Za-z_-]{35}/g },
  { kind: "stripe", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/g },
  { kind: "huggingface", re: /\bhf_[A-Za-z0-9]{20,}/g },
  { kind: "groq", re: /\bgsk_[A-Za-z0-9]{20,}/g },
  {
    kind: "credential",
    re: /(?:authorization["']?[ \t]*[:=][ \t]*["']?)?bearer[ \t]+(?<v>[^\s"'⟦\\][^\s"'\\]{19,})/gi,
    group: "v",
  },
  {
    // The password in `scheme://user:PASS@host` (the user may be empty, the password may hold `@`); user
    // and host stay. A host name and port before a list or a fragment (`cache.test:6379,admin@…`) hold
    // no password.
    kind: "credential",
    re: /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/(?!(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,24}:[0-9]{1,5}[,;#])[^\s/?#@:"'<>\\⟦]{0,256}:(?<v>[^\s/?@"'<>\\⟦$*{][^\s/?"'<>\\]{0,255})@/g,
    group: "v",
  },
  {
    // A private calendar feed: `…/private-<token>/basic.ics`.
    kind: "credential",
    re: /\/private-(?<v>[A-Za-z0-9]{16,128})(?![A-Za-z0-9])/g,
    group: "v",
    check: (v) => /[0-9]/.test(v),
  },
  {
    // `--password x`, `--api-key=x`, `--token "x"`.
    kind: "credential",
    re: new RegExp(`--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)(?:\\s*=\\s*|\\s+)${FLAG_VALUE}`, "gi"),
    group: "v",
    check: flagValue,
  },
  {
    // `--token-value x`. After a suffixed flag a path, URL or setting stays (`--secret-file /etc/app/x`,
    // `--token-url https://…`, `--token-ttl 3600`).
    kind: "credential",
    re: new RegExp(`--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)-\\w+(?:\\s*=\\s*|\\s+)${FLAG_VALUE}`, "gi"),
    group: "v",
    check: suffixedFlagValue,
  },
  {
    // `mysql -pX`: MySQL and MariaDB clients take a password only attached to `-p`. The client is a command
    // word (not a directory such as `/var/lib/mysql`, unless under a `bin/`), and the search stops at the end
    // of its command, an escaped newline included.
    kind: "credential",
    re: new RegExp(`(?:(?<![^\\s;|&(\`"'])|(?<=bin/)|(?<=\\\\[nt]))(?:mysql[a-z]{0,8}|mariadb(?:-?[a-z]{1,8})?)(?![\\w.-])[^\\n;|&\\\\]{0,200}?\\s-p${FLAG_VALUE}`, "g"),
    group: "v",
    check: mysqlPassword,
  },
  {
    // `sshpass -p X`, after any of sshpass's own options; a `-p` in the command it runs is not its.
    kind: "credential",
    re: new RegExp(`(?<![\\w-])sshpass(?:\\s+-[fdP][ \\t]*[^\\s-]\\S*|\\s+-[ehvV]){0,4}\\s+-p[ \\t]*${FLAG_VALUE}`, "g"),
    group: "v",
    check: flagValue,
  },
  {
    // `GITHUB_TOKEN=x`, `"api_key": "x"`, `?token=x`. Values that are variable references or masks stay.
    // Quotes may be escaped (JSON inside a JSON-encoded result), and a value ends at a backslash, so an
    // escaped and a plain copy of one value get the same placeholder.
    kind: "credential",
    re: new RegExp(
      `${CREDENTIAL_KEY}\\\\?["']?\\s*[=:]\\s*\\\\?["']?` +
        `(?![0-9]{1,5}(?![0-9A-Za-z]))(?<v>[^\\s"'⟦$*{[<%&,;\`\\\\][^\\s"'&,;<>\`\\\\]{7,})`,
      "gi",
    ),
    group: "v",
    check: keyValue,
  },
  {
    // `"password": "words, & symbols"`: in a JSON pair the whole quoted string is the value.
    kind: "credential",
    re: new RegExp(`${CREDENTIAL_KEY}\\\\?["']\\s*:\\s*\\\\?"(?<v>[^"\\\\\\n⟦$*{[<%][^"\\\\\\n]{7,199})\\\\?"`, "gi"),
    group: "v",
    check: keyValue,
  },
  {
    // An upper-case name with a credential word inside it: `SENTROOK_SECRET_MARKERS=x`. A number or a
    // path is not a value here (`TOKEN_LIMIT=4096`, `GITHUB_TOKEN_PATH=/home/…`).
    kind: "credential",
    re: new RegExp(
      `(?<![A-Za-z0-9_])[A-Z0-9_]{0,40}(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE)_[A-Z0-9_]{1,40}\\\\?["']?\\s*[=:]\\s*\\\\?["']?` +
        `(?![0-9]+(?![^\\s"'&,;<>\`\\\\]))(?<v>[^\\s"'⟦$*{<%&,;\`\\\\/~.][^\\s"'&,;<>\`\\\\]{7,})`,
      "g",
    ),
    group: "v",
    check: innerKeyValue,
  },
  { kind: "credential", re: proseStated(PROSE_CUES), group: "v", check: statedValue },
  { kind: "credential", re: proseBare(`${PROSE_CUES}|key`), group: "v", check: bareValue },
];

/**
 * Object keys whose whole value is a credential: any key that ends in a credential word (`password`,
 * `secretAccessKey`, `logintoken`). `pass`, `tok` and `credentials` count only as a whole word, so
 * `compass` and `passage` stay.
 */
const CREDENTIAL_FIELD =
  /^(?:.*[_-])?(?:pass|tok|credentials?)$|(?:token|password|passwd|passphrase|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer|private[_-]?key|client[_-]?secret)$/i;

function spansOf(text: string): Array<[number, number, string]> {
  const spans: Array<[number, number, string]> = [];
  for (const shape of SHAPES) {
    const re = shape.group ? new RegExp(shape.re.source, `${shape.re.flags.replace("d", "")}d`) : shape.re;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex += 1;
        continue;
      }
      if (shape.group) {
        const idx = m.indices?.groups?.[shape.group];
        if (idx && (!shape.check || shape.check(text.slice(idx[0], idx[1])))) spans.push([idx[0], idx[1], shape.kind]);
      } else {
        spans.push([m.index, m.index + m[0].length, shape.kind]);
      }
    }
  }
  spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const merged: Array<[number, number, string]> = [];
  for (const s of spans) {
    const last = merged[merged.length - 1];
    if (last && s[0] < last[1]) {
      last[1] = Math.max(last[1], s[1]);
      continue;
    }
    merged.push([...s]);
  }
  return merged;
}

export function createRedactor(level: RedactionLevel, salt: string): Redactor {
  const ref = (value: string) => createHmac("sha256", salt).update(value).digest("hex").slice(0, 4);
  // A private key is hashed without its line breaks, plain or escaped, so a key keeps its placeholder
  // however many times the text around it was JSON-encoded.
  const placeholder = (kind: string, value: string) =>
    `⟦secret:${kind}:${ref(kind === "private_key" ? value.replace(/\\+[rnt]|\s+/g, "") : value)}⟧`;

  const redactString = (text: string): string => {
    if (level === "off" || !text) return text;
    const spans = spansOf(text);
    if (!spans.length) return text;
    let out = "";
    let pos = 0;
    for (const [start, end, kind] of spans) {
      out += text.slice(pos, start) + placeholder(kind, text.slice(start, end));
      pos = end;
    }
    return out + text.slice(pos);
  };

  const walk = (value: unknown, depth: number): unknown => {
    if (typeof value === "string") return redactString(value);
    if (!value || typeof value !== "object" || depth > 32) return value;
    if (Array.isArray(value)) return value.map((v) => walk(v, depth + 1));
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      // A URL under a credential key (`forgotPassword`) goes through the text rules, which keep its host.
      if (level !== "off" && CREDENTIAL_FIELD.test(k) && typeof v === "string" && v && !v.startsWith("⟦") && keyValue(v)) {
        out[k] = placeholder("credential", v);
      } else {
        out[k] = walk(v, depth + 1);
      }
    }
    return out;
  };

  return {
    level,
    string: redactString,
    value: <T>(value: T): T => walk(value, 0) as T,
  };
}

export interface Capped {
  text: string;
  truncated: boolean;
  sizeBytes: number;
}

/** Cap text at `capBytes` (UTF-8), keeping two thirds head and one third tail. */
export function capHeadTail(text: string, capBytes: number): Capped {
  const sizeBytes = Buffer.byteLength(text, "utf8");
  if (sizeBytes <= capBytes) return { text, truncated: false, sizeBytes };
  const marker = `\n…[sentrook: ${sizeBytes - capBytes} bytes cut]…\n`;
  const budget = Math.max(0, capBytes - Buffer.byteLength(marker, "utf8"));
  const buf = Buffer.from(text, "utf8");
  const headBytes = Math.floor((budget * 2) / 3);
  const tailBytes = budget - headBytes;
  // toString on a cut multi-byte sequence yields U+FFFD; trim it rather than send a broken char.
  const head = buf.subarray(0, headBytes).toString("utf8").replace(/\uFFFD$/, "");
  const tail = buf.subarray(buf.length - tailBytes).toString("utf8").replace(/^\uFFFD/, "");
  return { text: head + marker + tail, truncated: true, sizeBytes };
}

/**
 * Cap an arguments object at about `capBytes` of JSON while keeping it an object: long string leaves
 * are cut head and tail to a share of the budget. Anything still over (very wide objects) collapses
 * to `{ _truncated: "<capped JSON>" }`.
 */
export function capArgs(value: unknown, capBytes: number): Record<string, unknown> {
  const obj = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : { value };
  const json = JSON.stringify(obj);
  if (Buffer.byteLength(json, "utf8") <= capBytes) return obj;
  let leaves = 0;
  const count = (v: unknown, d: number): void => {
    if (typeof v === "string") leaves += 1;
    else if (v && typeof v === "object" && d < 32) Object.values(v as object).forEach((x) => count(x, d + 1));
  };
  count(obj, 0);
  const leafCap = Math.max(200, Math.floor(capBytes / Math.max(1, leaves)));
  const cut = (v: unknown, d: number): unknown => {
    if (typeof v === "string") return capHeadTail(v, leafCap).text;
    if (Array.isArray(v)) return d < 32 ? v.map((x) => cut(x, d + 1)) : v;
    if (v && typeof v === "object" && d < 32) {
      return Object.fromEntries(Object.entries(v as object).map(([k, x]) => [k, cut(x, d + 1)]));
    }
    return v;
  };
  const shrunk = cut(obj, 0) as Record<string, unknown>;
  const shrunkJson = JSON.stringify(shrunk);
  if (Buffer.byteLength(shrunkJson, "utf8") <= capBytes * 1.25) return shrunk;
  return { _truncated: capHeadTail(shrunkJson, capBytes).text };
}
