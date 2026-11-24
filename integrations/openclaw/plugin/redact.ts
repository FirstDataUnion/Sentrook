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
/**
 * The last character of a value: sentence punctuation after a value is not part of it (`password: X.`,
 * `(token=X)`), so one secret gets one placeholder however the sentence around it goes on.
 */
const VALUE_END = `[^\\s"'&,;<>\`\\\\.:!?)\\]]`;
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
 * One part of a name in code, read as a word (`token_data`, `getSecret`, `JSON`, `oauth2`, `b64decode`): lower, camel,
 * Pascal or upper case, maybe after `_`, with digits at its end or one short run before more letters.
 */
const CODE_PART = String.raw`_?(?:[a-z]+(?:[0-9]{1,3}[a-z]{3,}|[0-9]*)(?:_[a-z]+[0-9]*)*|[a-z]+[0-9]*(?:[A-Z][a-z]+[0-9]*)+|[A-Z][a-z]+[0-9]*(?:[A-Z][a-z]+[0-9]*)*|[A-Z]+[0-9]*(?:_[A-Z]+[0-9]*)*)`;
/** A name, maybe dotted, called with no or one bare argument, or subscripted with a small number. */
const CODE_CHAIN = String.raw`${CODE_PART}(?:\.${CODE_PART}|\(\)|\([a-z_]{1,20}\)|\[[0-9]{1,4}\])*`;
/**
 * A dotted name whose every part reads as a word of up to 32 characters with no run of four digits (`config.token`,
 * `process.env.TOKEN`).
 */
const DOTTED_PART = String.raw`(?=[A-Za-z0-9_]{1,32}(?![A-Za-z0-9_]))(?![A-Za-z0-9_]{0,28}[0-9]{4})${CODE_PART}`;
const DOTTED_NAME = String.raw`${DOTTED_PART}(?:\.${DOTTED_PART})+`;
/**
 * Code that reads a secret from where it is kept, cut where its quoted argument starts: `token_data[` in
 * `access_token = token_data['access_token']`, `os.environ[`, `creds.get(`, `getpass(`, `resp.json()[`. A name, maybe
 * dotted, called or subscripted, that ends in an open bracket or parenthesis, or a call whose one argument is another
 * such read (`base64.b64decode(os.environ[`) or a dotted name (`b64decode(config.secret`). A random value that happens
 * to end in a bracket is still a value.
 */
const CODE_READ = new RegExp(String.raw`^(?:${CODE_CHAIN}(?:[\[(]|\((?:${CODE_CHAIN}[\[(]|${DOTTED_NAME}\)?)))$`);
/**
 * A call whose one argument is a bare lower-case name, cut before its closing parenthesis or a comma (`os.getenv(name`,
 * `load_token(path`, `getattr(settings`). It is code only when the name called reads as code (`isCodeRead`): dotted,
 * with `_` or a capital, or called or subscripted itself, or one of `CODE_READERS`. `hunter(abc)` and
 * `mysecret(pw_2024)` are values.
 */
const CODE_NAME_ARG_READ = new RegExp(String.raw`^(?:${CODE_CHAIN}\([a-z_][a-z0-9_]{0,29})$`);
const CODE_READERS = new Set("input getattr getenv getpass open read load get".split(" "));
/**
 * A dotted name called with a keyword before a quoted argument (`getpass.getpass(prompt=`) or subscripted with a
 * number of one or two digits (`sys.argv[1`, its `]` left out as punctuation). Only a dotted name counts
 * (`isCodeRead`): `qwerty[99]` and `monkey(prompt='x')` are values.
 */
const CODE_ARG_READ = new RegExp(String.raw`^(?:${CODE_CHAIN}(?:\[[0-9]{1,2}\]?|\([a-z_][a-z0-9_]{0,29}=))$`);
/**
 * A plain attribute read is code only from one of these receivers (`self.token`, `config.token`), or when it reads a
 * credential field (`resp.access_token`); `correct.horse.battery.staple` is a value.
 */
const CODE_RECEIVERS = new Set(
  "self cls this args opts options config cfg conf settings env process os creds credentials secrets params ctx app request".split(" "),
);
const DOTTED_READ = new RegExp(`^(?:${DOTTED_NAME})$`);
/**
 * Whether `v` is code that reads a secret from somewhere: called or subscripted and cut where its quoted argument
 * starts (`CODE_READ`), a dotted name with a simple argument (`CODE_ARG_READ`), a call on a bare name
 * (`CODE_NAME_ARG_READ`), or a plain attribute read from a known receiver or of a credential field (`config.token`).
 */
const isCodeRead = (v: string): boolean => {
  if (CODE_READ.test(v)) return true;
  if (v.includes(".") && CODE_ARG_READ.test(v)) return true;
  if (CODE_NAME_ARG_READ.test(v)) {
    const callee = v.slice(0, v.lastIndexOf("("));
    if (/[._A-Z(\[]/.test(callee) || CODE_READERS.has(callee)) return true;
  }
  if (!DOTTED_READ.test(v)) return false;
  const parts = v.split(".");
  return CODE_RECEIVERS.has(parts[0]) || CREDENTIAL_FIELD.test(parts[parts.length - 1]);
};

/**
 * Not a key's value: a URL (the URL rule takes any password inside it and the host stays) or the name of
 * an environment variable (`token: GITHUB_TOKEN`).
 */
const keyValue = (v: string) => !v.includes("://") && !/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v);
/**
 * An unquoted value after a key: also not code that reads the secret from somewhere (`token = creds.get('token')`,
 * cut where its quoted argument starts). A quoted value or one under an object key is whole, so it is never code cut
 * short.
 */
const unquotedKeyValue = (v: string) => keyValue(v) && !isCodeRead(v);
/**
 * An upper-case name with a credential word inside it names many things; only a long value counts, and not code that
 * reads the secret from somewhere (`MY_SECRET_TOKEN = config.token`), as after any other key.
 */
const innerKeyValue = (v: string) => v.length >= 12 && keyValue(v) && !isCodeRead(v);
/** The same name with a quoted value: a quoted value is whole, so one shaped like code is still a value. */
const innerQuotedValue = (v: string) => v.length >= 12 && keyValue(v);
/** After "password is" or "token:": six or more characters that are not words, a number or code that reads one. */
const statedValue = (v: string) =>
  v.length >= 6 && !isOrdinary(v) && !/^[0-9]+$/.test(v) && !NAMED_THING.test(v) && !isCodeRead(v);
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
/**
 * "the password changed, it's now X", "the token was rotated and it is now X": a second clause of the sentence
 * states the value. The words before it stay inside the sentence, as in "password is X".
 */
const proseRestated = (cues: string) =>
  new RegExp(
    `(?<![A-Za-z0-9_/.⟦-])(?:${cues})(?![A-Za-z0-9_])[^\\n:.;=\"'\`⟦]{0,40}?` +
      `(?:,|\\s+and)\\s+it(?:(?:['’]|\\\\{1,8}u2019)s|\\s+(?:is|was))(?:\\s+(?:now|still|currently|set\\s+to|changed\\s+to))?\\s+${PROSE_VALUE}`,
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
    // escaped and a plain copy of one value get the same placeholder. Trailing punctuation stays outside.
    kind: "credential",
    re: new RegExp(
      `${CREDENTIAL_KEY}\\\\?["']?\\s*[=:]\\s*\\\\?["']?` +
        `(?![0-9]{1,5}(?![0-9A-Za-z]))(?<v>[^\\s"'⟦$*{[<%&,;\`\\\\](?:[^\\s"'&,;<>\`\\\\]{6,}${VALUE_END}|[^\\s"'&,;<>\`\\\\]{5}${VALUE_END}(?=[.:!?)\\]])))`,
      "gi",
    ),
    group: "v",
    check: unquotedKeyValue,
  },
  {
    // `PASSWORD="x!"`: a quoted value is all of it up to its closing quote, trailing punctuation included,
    // as in a JSON pair or under an object key.
    kind: "credential",
    re: new RegExp(
      `${CREDENTIAL_KEY}\\\\?["']?\\s*[=:]\\s*\\\\?["']` +
        `(?![0-9]{1,5}(?![0-9A-Za-z]))(?<v>[^\\s"'⟦$*{[<%&,;\`\\\\][^\\s"'&,;<>\`\\\\]{7,})(?=\\\\?["'])`,
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
    // path is not a value here (`TOKEN_LIMIT=4096`, `GITHUB_TOKEN_PATH=/home/…`), and nor is unquoted
    // code that reads the secret from somewhere (`MY_SECRET_TOKEN = config.token`).
    kind: "credential",
    re: new RegExp(
      `(?<![A-Za-z0-9_])[A-Z0-9_]{0,40}(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE)_[A-Z0-9_]{1,40}\\\\?["']?\\s*[=:]\\s*` +
        `(?![0-9]+(?![^\\s"'&,;<>\`\\\\]))(?<v>[^\\s"'⟦$*{<%&,;\`\\\\/~.][^\\s"'&,;<>\`\\\\]{6,}${VALUE_END})`,
      "g",
    ),
    group: "v",
    check: innerKeyValue,
  },
  {
    // The same name with a quoted value (`GITHUB_TOKEN_VALUE="x"`): a quoted value is whole, so one
    // shaped like code is still a value.
    kind: "credential",
    re: new RegExp(
      `(?<![A-Za-z0-9_])[A-Z0-9_]{0,40}(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE)_[A-Z0-9_]{1,40}\\\\?["']?\\s*[=:]\\s*\\\\?["']` +
        `(?![0-9]+(?![^\\s"'&,;<>\`\\\\]))(?<v>[^\\s"'⟦$*{<%&,;\`\\\\/~.][^\\s"'&,;<>\`\\\\]{6,}${VALUE_END})`,
      "g",
    ),
    group: "v",
    check: innerQuotedValue,
  },
  { kind: "credential", re: proseStated(PROSE_CUES), group: "v", check: statedValue },
  { kind: "credential", re: proseRestated(PROSE_CUES), group: "v", check: statedValue },
  { kind: "credential", re: proseBare(`${PROSE_CUES}|key`), group: "v", check: bareValue },
];

/**
 * Object keys whose whole value is a credential: any key that ends in a credential word (`password`,
 * `secretAccessKey`, `logintoken`). `pass`, `tok` and `credentials` count only as a whole word, so
 * `compass` and `passage` stay.
 */
const CREDENTIAL_FIELD =
  /^(?:.*[_-])?(?:pass|tok|credentials?)$|(?:token|password|passwd|passphrase|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer|private[_-]?key|client[_-]?secret)$/i;

/**
 * Access codes, PINs and personal identifiers named by a cue word, and random values under a key or a header. A
 * short number is a secret only after a cue word ("the gate code is 861206", "collection PIN for order 441 is 6815",
 * `yard_code=090373`): with no cue it stays, and so do ordinary codes (postal, country, status, error, product and
 * business-record codes). A random value counts only under a key or a header (`value: <random>`,
 * `X-Desk: <random>`), never in prose ("what it says: X"), and never under a key that names an id, a hash, a version
 * or data. Kinds:
 * `code`, `pin`, `identifier` (a passport number) and `random`; a placeholder says `identifier` for an identifier
 * and `credential` for the others (`PLACEHOLDER_KIND`). The Hermes plugin and the scanner's second pass hold the
 * same rules.
 */
type CueKind = "code" | "pin" | "identifier" | "random";
const PLACEHOLDER_KIND: Record<CueKind, string> = { code: "credential", pin: "credential", random: "credential", identifier: "identifier" };

/** Where a cue word starts: not inside a word, or straight after an escaped newline or tab of a JSON-encoded text. */
const CUE_START = String.raw`(?:(?<![A-Za-z0-9_\\])|(?<=\\[nrt]))`;
/**
 * Words before "code" that make it an access or sign-in code: "gate code", "sign-in code", "backup codes". A code
 * with any other qualifier (postal, country, error, promo) is not a secret.
 */
const CODE_QUALIFIERS =
  "gate|door|alarm|access|entry|entrance|keypad|lock|lockbox|key[ -]?safe|safe|sign[ -]?in|" +
  "log[ -]?in|login|verification|verify|security|one[ -]time|backup|recovery|unlock|2fa|mfa";
const CODE_CUE = String.raw`${CUE_START}(?:(?:${CODE_QUALIFIERS})[ \t]+codes?|pass[ -]?codes?|otp)`;
/**
 * `PIN` in capitals (a lower-case "pin" is usually the verb), and in any case "pin code" / "pin number" or a pin
 * that belongs to someone or something ("my pin", "the card pin", "collection pin").
 */
const PIN_CAPS_CUE = String.raw`${CUE_START}PINs?`;
const PIN_WORDS_CUE = String.raw`${CUE_START}(?:pin[ \t]+(?:codes?|numbers?)|(?:my|your|his|her|their|our|the|card|collection|door|access|sim|bank|debit|atm)[ \t]+pin)`;
const PASSPORT_CUE = String.raw`${CUE_START}passport(?:[ \t]+(?:numbers?|no\.?|#))?`;
/**
 * "for order 441", "on the booking": a short phrase between the cue and the value. When one is present the value
 * must follow `is`, `was` or a colon, so a number inside the phrase is never taken as the value. "the gate code, it is
 * N" states it in a second clause.
 */
const CUE_CONNECTOR = String.raw`[ \t]+(?:for|on|of|to|from)[ \t]+[^\n.:;=]{1,40}?(?:[ \t]+(?:is|was)\b|[ \t]*:)[ \t]*`;
const CUE_SEPARATOR = String.raw`[ \t]*(?:(?:is|was)[ \t]*:?[ \t]*|[:=#-][ \t]*|,[ \t]*it(?:['’]s|[ \t]+(?:is|was))(?:[ \t]+now)?[ \t]*:?[ \t]*|)`;
/** A value ends at a character that does not continue it or a number ("6815." ends a sentence; "10:30" is not a code). */
const CUE_END = String.raw`(?![A-Za-z0-9_-]|[.:,/][0-9])`;
const cueRule = (flags: string, cue: string, value: string) =>
  new RegExp(String.raw`(?:${cue})(?:${CUE_CONNECTOR}|${CUE_SEPARATOR})\\{0,8}["'\x60]?${value}${CUE_END}`, `${flags}gd`);
/** A code: four to ten digits, or two groups of letters and digits with a digit in them (`4821-9930`). */
const codeValue = (v: string) => !v.includes("-") || /[0-9]/.test(v);
/** A passport number: capitals and digits, with a digit (`passport renewal` is words). */
const identifierValue = (v: string) => /[0-9]/.test(v) && !/[a-z]/.test(v);

/** Group `v` is replaced; a match counts only when its value passes the check. */
const CUES: Array<{ kind: CueKind; re: RegExp; check?: (v: string) => boolean }> = [
  { kind: "code", re: cueRule("i", CODE_CUE, "(?<v>[0-9]{4,10}|[A-Za-z0-9]{4,6}-[A-Za-z0-9]{4,6})"), check: codeValue },
  { kind: "pin", re: cueRule("", PIN_CAPS_CUE, "(?<v>[0-9]{4,10})") },
  { kind: "pin", re: cueRule("i", PIN_WORDS_CUE, "(?<v>[0-9]{4,10})") },
  { kind: "identifier", re: cueRule("i", PASSPORT_CUE, "(?<v>[A-Z0-9]{6,12})"), check: identifierValue },
  // The value first: "482193 is your verification code".
  {
    kind: "code",
    re: new RegExp(
      String.raw`(?:(?<![A-Za-z0-9_.\\-])|(?<=\\[nrt]))(?<v>[0-9]{4,10})[ \t]+is[ \t]+(?:your|the|my)[ \t]+(?:[A-Za-z0-9_-]{1,30}[ \t]+)?${CODE_CUE}`,
      "gid",
    ),
  },
];

/** Where a key starts: not inside a word, a dotted name or a path, or straight after an escaped newline or tab. */
const KEY_START = String.raw`(?:(?<![A-Za-z0-9_.\\-])|(?<=\\[nrt]))`;
/** `yard_code=090373`, `client_pin: 7021`, `gateCode: 4471`, `"passport_number": "PPCDHFZC6"`, `code=006960`. */
const CODE_KEY = new RegExp(
  String.raw`${KEY_START}(?<k>[A-Za-z][A-Za-z0-9_-]{0,40})\\{0,8}["']?[ \t]*(?<sep>[:=])[ \t]*\\{0,8}["']?(?<v>[A-Za-z0-9]{4,12})${CUE_END}`,
  "gd",
);
/** `value: <random>`, `"X-Desk": "<random>"`, `sig=<random>`: any key or header, a long value. */
const RANDOM_KEY = new RegExp(
  String.raw`${KEY_START}(?<k>[A-Za-z_][A-Za-z0-9_.-]{0,40})\\{0,8}["']?[ \t]*(?<sep>[:=])[ \t]*\\{0,8}["']?(?<v>[A-Za-z0-9+/_-]{12,256}={0,2})(?![A-Za-z0-9+/=_@-])`,
  "gd",
);
const RANDOM_VALUE = /^[A-Za-z0-9+/_-]{12,256}={0,2}$/;
/**
 * Key prefixes that make `*_code` an ordinary value: postal, country, status and error codes, product,
 * business-record and discount codes, language and currency codes.
 */
const ORDINARY_CODE_PREFIX = new Set(
  (
    "zip postal post country area status error err exit return ret response resp http product item " +
    "sku promo discount coupon voucher lang language locale currency color colour region iso tax vat " +
    "sort bank swift bic qr bar barcode hs naics sic reason event type class char key op short dial " +
    "phone airport iata icao station stop route flight course department dept cost gl account project " +
    "source src fiscal unit state county city branch store site plan tier mode format result customer " +
    "client vendor supplier merchant mcc lot batch location loc ticket run job tariff part model serial " +
    "invoice order shipment carrier service category group cpt icd diagnosis procedure exchange " +
    "market ticker isin cusip unspsc"
  ).split(" "),
);
/** Keys and headers whose values are identifiers, digests, names, state, data or patterns, not secrets. */
const NOT_SECRET_KEY =
  /(?:^|[_.-])(?:id|ids|uuid|guid|hash|sha\d*|md5|digest|checksum|crc|commit|rev|revision|etag|cid|ref|trace\w*|span\w*|request\w*|version|ver|build|sku|order|path|file|filename|url|uri|href|src|name|class|classname|type|title|label|tag|branch|slug|key_id|keyid|fingerprint|nonce|state|data|content|body|payload|blob|image|attachment|b64|base64|raw|integrity|list|si|in-reply-to|references|message-id|thread\w*|customer|payment_intent|charge|invoice|subscription|price|product|regex|pattern|glob)$/i;
/**
 * camelCase keys ending in an id or name word (`userId`, `fileHash`); case-sensitive, so `sid` and `PHPSESSID`
 * (session cookies) still count.
 */
const NOT_SECRET_CAMEL_KEY = /[a-z](?:Id|ID|Ids|Hash|Name|Url|Uri|Path|Version)$/;
/** A provider's object id (`cus_…`, `pi_…`) and subresource-integrity hashes (`sha384-…`). */
const PREFIXED_OBJECT_ID = /^(?:[a-z]{1,8}_|[Ss][Hh][Aa](?:1|256|384|512)-)/;

/** `yard_code` → [yard, code]; `gateCode` → [gate, code]; `alarmPIN` → [alarm, pin]. */
const keyWords = (key: string) =>
  key
    .split(/[_-]|(?<=[a-z0-9])(?=[A-Z])/)
    .filter((w) => w)
    .map((w) => w.toLowerCase());

/**
 * The kind of secret under a code, PIN or passport key, or null. A bare `code` key counts only as a form or query
 * field with six or more digits (`-d 'code=006960'`): a JSON or YAML `code:` is far more often a status or error
 * code, and a link's `?code=` an exchange the scanner needs to see.
 */
const keyKind = (key: string, value: string, sep: string, afterQuery: boolean): CueKind | null => {
  const words = keyWords(key);
  if (!words.length) return null;
  const last = words[words.length - 1];
  const passport =
    ["passport", "passportno", "passportnum", "passportnumber"].includes(last) ||
    (words.length > 1 && words[words.length - 2] === "passport" && ["no", "num", "number"].includes(last));
  if (passport) return value.length >= 6 && value.length <= 12 && identifierValue(value) ? "identifier" : null;
  if (!/^[0-9]{4,10}$/.test(value)) return null;
  if (["pin", "passcode", "otp"].includes(last)) return "pin";
  if (last !== "code") return null;
  if (words.length > 1) return ORDINARY_CODE_PREFIX.has(words[words.length - 2]) ? null : "code";
  return sep === "=" && value.length >= 6 && !afterQuery ? "code" : null;
};

const charClass = (ch: string) => (/[0-9]/.test(ch) ? 0 : /[A-Z]/.test(ch) ? 1 : /[a-z]/.test(ch) ? 2 : 3);

/**
 * A value a person did not type: twelve or more characters with upper case, lower case and a digit, not hex (a
 * hash, a commit id, a UUID), with frequent changes between character classes, which rules out camelCase words
 * (`PrimaryButton2`), and enough distinct characters.
 */
const looksRandom = (v: string): boolean => {
  const core = v.replace(/=+$/, "");
  if (core.length < 12 || "/-_".includes(core[0]) || PREFIXED_OBJECT_ID.test(core)) return false;
  if (/^[0-9A-Fa-f-]+$/.test(core)) return false;
  if (!(/[A-Z]/.test(core) && /[a-z]/.test(core) && /[0-9]/.test(core))) return false;
  let changes = 0;
  for (let i = 1; i < core.length; i++) if (charClass(core[i - 1]) !== charClass(core[i])) changes += 1;
  if (changes < 0.35 * (core.length - 1)) return false;
  const counts = new Map<string, number>();
  for (const c of core) counts.set(c, (counts.get(c) ?? 0) + 1);
  let entropy = 0;
  for (const n of counts.values()) entropy -= (n / core.length) * Math.log2(n / core.length);
  return entropy >= 3.0;
};

/**
 * A random value under a key or header that does not name an id, a hash, a version or data, outside a link's query
 * (`?si=…`, `&list=…` are share links and tracking parameters).
 */
const randomKey = (key: string, value: string, afterQuery: boolean) =>
  !NOT_SECRET_KEY.test(key) && !NOT_SECRET_CAMEL_KEY.test(key) && !afterQuery && looksRandom(value);

const afterQuery = (text: string, start: number) => start > 0 && "?&".includes(text[start - 1]);

/**
 * A `key: value` pair stands on its own: its key starts a line (indented or not), follows `{ , ; ( [` or a quote (JSON,
 * a dict, a quoted header) or a `-H` / `--header` flag. A word before a colon in a sentence ("what it says: X") is
 * prose, not a key.
 */
const startsEntry = (text: string, start: number): boolean => {
  let i = start;
  while (i > 0) {
    if (" \t".includes(text[i - 1])) i -= 1;
    else if (i > 1 && text.slice(i - 2, i) === "\\t") i -= 2;
    else break;
  }
  if (i === 0 || "\n\r{,;([\"'".includes(text[i - 1]) || ["\\n", "\\r"].includes(text.slice(Math.max(0, i - 2), i))) return true;
  const before = text.slice(Math.max(0, i - 8), i);
  return before.endsWith("-H") || before.endsWith("--header");
};

/** Every access code, PIN, identifier and random value the cue and key rules find, as (start, end, kind). */
function cueSpans(text: string): Array<[number, number, CueKind]> {
  const out: Array<[number, number, CueKind]> = [];
  const each = (re: RegExp, fn: (m: RegExpExecArray) => void) => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex += 1;
        continue;
      }
      fn(m);
    }
  };
  for (const cue of CUES) {
    each(cue.re, (m) => {
      const idx = m.indices?.groups?.v;
      if (idx && (!cue.check || cue.check(text.slice(idx[0], idx[1])))) out.push([idx[0], idx[1], cue.kind]);
    });
  }
  each(CODE_KEY, (m) => {
    const g = m.groups as Record<string, string>;
    const kind = keyKind(g.k, g.v, g.sep, afterQuery(text, m.index));
    const idx = m.indices?.groups?.v;
    if (kind && idx) out.push([idx[0], idx[1], kind]);
  });
  each(RANDOM_KEY, (m) => {
    const g = m.groups as Record<string, string>;
    if (g.sep === ":" && !startsEntry(text, m.index)) return;
    const idx = m.indices?.groups?.v;
    if (idx && randomKey(g.k, g.v, afterQuery(text, m.index))) out.push([idx[0], idx[1], "random"]);
  });
  return out;
}

/**
 * The kind of secret a parsed object's value is under its key, or null: a code, PIN or passport number under its key
 * (a number counts as its digits), or a random string under any key or header (`{"X-Desk": …}`).
 */
function objectKind(key: string, value: unknown): CueKind | null {
  if (typeof value !== "string" && !(typeof value === "number" && Number.isSafeInteger(value) && value >= 0)) return null;
  const text = String(value);
  if (/^[A-Za-z0-9]{4,12}$/.test(text)) {
    const kind = keyKind(key, text, ":", false);
    if (kind) return kind;
  }
  if (typeof value === "string" && RANDOM_VALUE.test(value) && randomKey(key, value, false)) return "random";
  return null;
}

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
  for (const [s, e, kind] of cueSpans(text)) spans.push([s, e, PLACEHOLDER_KIND[kind]]);
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
        const kind = level !== "off" ? objectKind(k, v) : null;
        out[k] = kind ? placeholder(PLACEHOLDER_KIND[kind], String(v)) : walk(v, depth + 1);
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
