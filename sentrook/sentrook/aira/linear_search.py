"""Listed patterns searched in linear time, with the same answer as the regex.

A pattern `<head><gap><tail>` with a greedy gap (`[^;&|\\n]*`: any words to the end of the simple
command), searched as a regex, retries the gap from every head and the tail at every position after it:
a long simple command with many heads (`rsync rsync …`, `uvx uvx …`) is quadratic, a chain of such gaps
(`systemctl … stop … openclaw`) cubic, and the remote-copy tail `\\S+@\\S+:` cubic in one long word
(`a@a@…`). For the patterns in `LINEAR` the search here reads the gap ranges of all the heads once,
left to right, and tries each later piece once at each position in them. It finds where the leftmost
match starts; `search` then lets the regex match from there, which is the match `rx.search` returns.
A chain of such gaps (`<piece>[^;&|\n]*<piece>…`) has its matches built here too, the regex's
longest gaps taken (`chain_spans`): the regex can take long to build one. For the patterns in
`FOUND_ONLY`, only `found` is linear: their callers ask for a yes or no.

Patterns of the form `<command>(?:<option>)*<end>` that preparation reads (the host of `ssh -o x
host`, the module of `python -m`, the program of `perl -e`, the file of `sed -i`) retry the run of
options from every head in it (`-scp -scp …`): `option_run_finditer` reads each position of the run
once, for the patterns in `OPTION_RUNS`, with the regex's own matches.

The lists keep the patterns: an entry here is keyed by the pattern's text, so a pattern changed in a
list (or an overlay) is searched as the regex it is. Every entry is checked against its regex.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

#: The gap of a command pattern: any characters but a separator of simple commands.
COMMAND_GAP = re.compile(r"[^;&|\n]*")


def gap_tail_first(
    text: str,
    head: re.Pattern[str],
    tail_at: Callable[[str, int], bool],
    gap: re.Pattern[str] = COMMAND_GAP,
    least: int = 0,
    lead: re.Pattern[str] | None = None,
    pos: int = 0,
    start_of: Callable[[str, re.Match[str], int], int] | None = None,
) -> int:
    """Where the leftmost `<head><lead><gap><tail>` in `text` at or after `pos` starts; -1 when there
    is none. For a head whose matches never overlap and end where they end (one end per start), an
    optional lead `L+` (`\\s+` after `uvx`) whose class takes in the gap's or runs before it, and a
    gap `C*` (or `C+`, `least=1`) of one character class. The positions the tail may start at are then
    one span from the head's end (plus `least`, or one for a lead) to where the gap ends after the
    lead's run, and the spans of later heads end no earlier. `tail_at(text, p)`: whether the tail
    matches at `p`; it is called once per position, in ascending order. The first position where it
    holds lies in the span of no head before the one being read, so that head starts the leftmost
    match (or `start_of(text, head, pos)` does, for a pattern with an optional part before its head
    that only moves where the match starts)."""
    tried = -1  # every position up to here has been tried
    end = -1  # where the last head's gap ends
    for m in head.finditer(text, pos):
        e = m.end()
        start = e + least
        if lead is not None:
            run = lead.match(text, e)
            if run is None:
                continue
            start, e = e + 1, run.end()
        if e > end:
            end = gap.match(text, e).end()  # type: ignore[union-attr]  (a `C*` always matches)
        for p in range(max(start, tried + 1), end + 1):
            if tail_at(text, p):
                return start_of(text, m, pos) if start_of is not None else m.start()
        tried = max(tried, end)
    return -1


#: A piece of a chain: its pattern, and how many characters its shortest match takes when it can
#: match more than one way (`>>?\s*`: one, `>`, or more), every length in between being a match too.
Piece = tuple[re.Pattern[str], int | None]


def chain_first(text: str, pieces: Sequence[Piece], pos: int = 0) -> int:
    """Where the leftmost `<piece>[^;&|\\n]*<piece>…[^;&|\\n]*<piece>` in `text` at or after `pos`
    starts; -1 when there is none. Read right to left: for each piece, the first position from each
    point where it matches and the rest of the chain can follow (the next piece starting before the
    end of the simple command its match ends in). A piece that can match more than one length (its
    shortest given) reaches from its shortest end to the end of the command its longest end is in.
    Each piece is tried once at each position."""
    for rx, _ in pieces:
        if rx.search(text, pos) is None:
            return -1
    n = len(text)
    sep = [n] * (n + 1)  # the first separator at or after each position
    for i in range(n - 1, -1, -1):
        sep[i] = i if text[i] in ";&|\n" else sep[i + 1]
    after: list[int] | None = None  # the first position from each point where the rest can start
    for k in range(len(pieces) - 1, -1, -1):
        rx, shortest = pieces[k]
        first = [n + 1] * (n + 2)
        for p in range(n, pos - 1, -1):
            m = rx.match(text, p)
            ok = m is not None
            if ok and after is not None:
                lo = p + shortest if shortest is not None else m.end()  # type: ignore[union-attr]
                ok = after[lo] <= sep[m.end()]  # type: ignore[union-attr]
            first[p] = p if ok else first[p + 1]
        after = first
    assert after is not None
    return after[pos] if after[pos] <= n else -1


def chain_spans(text: str, pieces: Sequence[Piece], pos: int = 0) -> Iterator[tuple[int, int]]:
    """The spans of `rx.finditer(text, pos)` for the chain `<piece>[^;&|\\n]*<piece>…`, in linear time.

    Each piece matches at most one way where it matches, or (its shortest given) every length from
    its shortest to its greedy longest, the longest preferred. The regex, from a start, takes each
    gap as long as it can be: of the ways to match from there it makes the one where the second
    piece starts last, then (from there) the third, and so on, and the last piece ends where that
    way's does. Read right to left, each position keeps where the match ends when a piece starts
    there (none when the rest cannot follow), and each gap the latest start of the next piece in it
    that has an end; each piece is tried once at each position. Starts are found left to right from
    where the last match ended, as `finditer` does."""
    for rx, _ in pieces:
        if rx.search(text, pos) is None:
            return
    n = len(text)
    is_sep = [c in ";&|\n" for c in text]
    gap_end: list[int] | None = None  # from each position, where a match ends: the gap read longest
    ends: list[int] = []
    for k in range(len(pieces) - 1, -1, -1):
        rx, shortest = pieces[k]
        ends = [-1] * (n + 1)  # where the match ends when this piece starts at each position
        for p in range(pos, n + 1):
            m = rx.match(text, p)
            if m is None:
                continue
            if gap_end is None:
                ends[p] = m.end()
                continue
            lo = p + shortest if shortest is not None else m.end()
            for e in range(m.end(), lo - 1, -1):
                if gap_end[e] >= 0:
                    ends[p] = gap_end[e]
                    break
        if k == 0:
            break
        gap_end = [-1] * (n + 2)
        for q in range(n, pos - 1, -1):
            later = gap_end[q + 1] if q < n and not is_sep[q] else -1
            gap_end[q] = later if later >= 0 else ends[q]
    p = pos
    while p <= n:
        while p <= n and ends[p] < 0:
            p += 1
        if p > n:
            return
        yield p, ends[p]
        p = ends[p] if ends[p] > p else p + 1


def regex_tail(pattern: str) -> Callable[[str, int], bool]:
    rx = _rx(pattern)
    return lambda text, p: rx.match(text, p) is not None


class RemoteCopyTail:
    """The remote-copy tail `\\S+@\\S+:|\\b[\\w.-]+\\.[a-z]{2,}:|\\brsync://|\\bsftp://` tried at
    ascending positions. `user@host:` holds, within one run of non-space characters, for a prefix of the
    run's positions (an `@` after the position, a `:` two after that, both in the run), and `host.tld:`
    likewise within a run of `[\\w.-]` among the positions at a word boundary (the run must end at the
    `:`): after it fails at a position, the rest of that run is not tried again."""

    #: `\S+@\S+:` at a position, without its backtracking: the first `@` after the first character,
    #: then the first `:` after the character after it.
    USER_HOST = re.compile(r"\S[^\s@]*@\S[^\s:]*:")
    HOST = re.compile(r"\b[\w.-]+\.[a-z]{2,}:", re.IGNORECASE)
    URL = re.compile(r"\b(?:rsync|sftp)://", re.IGNORECASE)
    WORD = re.compile(r"\S+")
    HOST_RUN = re.compile(r"\b[\w.-]+")

    def __init__(self) -> None:
        self.user_host_failed_until = -1
        self.host_failed_until = -1

    def __call__(self, text: str, p: int) -> bool:
        if p >= self.user_host_failed_until:
            if self.USER_HOST.match(text, p):
                return True
            word = self.WORD.match(text, p)
            if word:
                self.user_host_failed_until = word.end()
        if p >= self.host_failed_until:
            if self.HOST.match(text, p):
                return True
            run = self.HOST_RUN.match(text, p)
            if run:
                self.host_failed_until = run.end()
        return self.URL.match(text, p) is not None


class SudoTail:
    """A fetch-to-program tail `\\|\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?<program>\\b` tried at ascending
    positions. After `sudo`, the option words (`-\\S+\\s+`, each a whole word and the whitespace after
    it) lead from one to the next: the program is looked for along that chain once per position, the
    answer kept for every position on it. Tried as a regex, each `|` in a long word of options
    (`-curl|sudo -curl|sudo …`) re-read the options to the end of the text."""

    PIPE = re.compile(r"\|\s*")
    SUDO = re.compile(r"sudo\s+", re.IGNORECASE)
    OPTION = re.compile(r"-\S+\s+", re.IGNORECASE)

    def __init__(self, program: str) -> None:
        self.program = _rx(program)
        self.memo: dict[int, bool] = {}

    def __call__(self, text: str, p: int) -> bool:
        m = self.PIPE.match(text, p)
        if m is None:
            return False
        q = m.end()
        if self.program.match(text, q):
            return True
        sudo = self.SUDO.match(text, q)
        return sudo is not None and self._chain(text, sudo.end())

    def _chain(self, text: str, c: int) -> bool:
        walked: list[int] = []
        at: int | None = c
        while at is not None and at not in self.memo:
            walked.append(at)
            o = self.OPTION.match(text, at)
            at = o.end() if o is not None else None
        found = self.memo[at] if at is not None else False
        for q in reversed(walked):
            found = found or self.program.match(text, q) is not None
            self.memo[q] = found
        return self.memo[c]


_RX: dict[str, re.Pattern[str]] = {}


def _rx(pattern: str) -> re.Pattern[str]:
    """A piece of a listed pattern, compiled as the lists compile theirs (ignoring case)."""
    if pattern not in _RX:
        _RX[pattern] = re.compile(pattern, re.IGNORECASE)
    return _RX[pattern]


Search = Callable[[str, int], int]
#: The chains of `LINEAR` (pattern text -> the spans of its matches from a position): a chain's match
#: is built here, not by the regex, which can take long to build it.
CHAIN_SPANS: dict[str, Callable[[str, int], Iterator[tuple[int, int]]]] = {}


def _command(
    head: str,
    tail: str,
    *,
    lead: str = "",
    gap: str = r"[^;&|\n]*",
    prefix: tuple[str, str, Callable[[str, re.Match[str], int], int]] | None = None,
    tail_at: Callable[[], Callable[[str, int], bool]] | None = None,
) -> tuple[str, Search]:
    """`<head><lead><gap><tail>`: the pattern's text and its linear search. `lead` (`\\s+`, `\\S+`) is a
    run the head ends with; `gap` a class run, `*` (or `+`, needing one character). `prefix`: the
    pattern's text before the head (an optional part, and the head's own start), and where a match
    whose head is found starts. `tail_at`: a new test of the tail per search, for a tail the regex
    cannot try in constant time."""
    least = 1 if gap.endswith("+") else 0
    gap_rx = _rx(gap[:-1].rstrip("*+?") + "*" if gap.endswith(("+", "?")) else gap)
    lead_rx = _rx(lead) if lead else None
    before, head_start, start_of = prefix if prefix is not None else ("", "", None)
    return before + head + lead + gap + tail, lambda text, pos: gap_tail_first(
        text,
        _rx(head_start + head),
        tail_at() if tail_at is not None else regex_tail(tail),
        gap=gap_rx,
        least=least,
        lead=lead_rx,
        pos=pos,
        start_of=start_of,
    )


class _GapTails:
    """For one text and tail: from each position, the last place in the gap (`[^;&|\\n]*`) read from
    there where the tail matches (-1 for none). Kept for the last text read, so the matches of one
    text are built from one pass."""

    def __init__(self) -> None:
        self.key: tuple[str, str] | None = None
        self.last: list[int] = []

    def __call__(self, text: str, tail: re.Pattern[str]) -> list[int]:
        if self.key is None or self.key[1] != tail.pattern or self.key[0] is not text:
            n = len(text)
            last = [-1] * (n + 2)
            for q in range(n, -1, -1):
                later = last[q + 1] if q < n and text[q] not in ";&|\n" else -1
                last[q] = later if later >= 0 else (q if tail.match(text, q) else -1)
            self.key, self.last = (text, tail.pattern), last
        return self.last


_GAP_TAILS = _GapTails()


def _lead_gap_tail_end(text: str, start: int, head: re.Pattern[str], tail: re.Pattern[str]) -> int:
    """Where the match of `<head>\\S+[^;&|\\n]*<tail>` that starts at `start` ends (-1 for none), as
    the regex makes it: the word (`\\S+`) as long as a tail can follow it in the gap, then the gap as
    long as it can be. Asked of the regex, a long word whose tail is only found inside it (`-H
    x.rm.aaaa… b b …`) re-read the gap after each shorter word."""
    h = head.match(text, start)
    if h is None:
        return -1
    lead = h.end()
    word = lead
    while word < len(text) and not text[word].isspace():
        word += 1
    last = _GAP_TAILS(text, tail)
    for e in range(word, lead, -1):
        if last[e] >= 0:
            return tail.match(text, last[e]).end()  # type: ignore[union-attr]
    return -1


_HOST_PREFIX = re.compile(r"\bDOCKER_HOST=\S", re.IGNORECASE)
_SPACE_BEFORE = re.compile(r"\s+\Z")


def _docker_host_start(text: str, head: re.Match[str], pos: int) -> int:
    """`(?:DOCKER_HOST=\\S+\\s+)?docker…`, the head `docker…` found: the match starts at the first
    `DOCKER_HOST=` with a character after it in the word before the head's spaces, if there is one
    (from `pos` on), else at the head."""
    d = head.start()
    i = d
    while i > 0 and text[i - 1].isspace():
        i -= 1
    if i == d:
        return d
    j = i
    while j > 0 and not text[j - 1].isspace():
        j -= 1
    m = _HOST_PREFIX.search(text, max(j, pos), i)
    return m.start() if m is not None and m.end() <= i else d


def _chain(*pieces: str | tuple[str, int]) -> tuple[str, Search]:
    """`<piece>[^;&|\\n]*<piece>…`: the pattern's text and its linear search. A piece given as
    `(pattern, shortest)` can match more than one length."""
    parts = [(p, None) if isinstance(p, str) else p for p in pieces]
    text = r"[^;&|\n]*".join(p for p, _ in parts)
    assert re.compile(text).groups == 0, text  # a match is built from its span alone
    CHAIN_SPANS[text] = lambda t, pos: chain_spans(t, [(_rx(p), k) for p, k in parts], pos)
    return text, lambda t, pos: chain_first(t, [(_rx(p), k) for p, k in parts], pos)


_DOCKER_REMOVE = r"\b(?:rm|rmi|system\s+prune|volume\s+rm)\b"
_DOCKER_REMOTE, _DOCKER_REMOTE_SEARCH = _command(
    r"docker\s+(?:-H|--host)[\s=]",
    _DOCKER_REMOVE,
    lead=r"\S+",
    prefix=(r"\b(?:DOCKER_HOST=\S+\s+)?", r"\b", _docker_host_start),
)
_REMOTE_COPY = (
    r"\b(?:scp|rsync|sftp)\b[^;&|\n]*(?:\S+@\S+:|\b[\w.-]+\.[a-z]{2,}:|\brsync://|\bsftp://)"
)
_TO_SHELL = r"\|\s*(?:sudo\s+)?(?:ba|z|da|k|a|fi)?sh\b"
_FROM_URL = r"\s(?:https?://|git\+)"
_GATEWAY = r"\b(?:openclaw|hermes)"

#: Listed pattern (as written in its list, compiled ignoring case) -> where its leftmost match from a
#: position starts.
LINEAR: dict[str, Search] = dict(
    [
        # egress.yaml exec_markers
        (
            _REMOTE_COPY,
            lambda text, pos: gap_tail_first(
                text, _rx(r"\b(?:scp|rsync|sftp)\b"), RemoteCopyTail(), pos=pos
            ),
        ),
        _command(r"\baws\s+s3\s+(?:cp|sync|mv)\b", r"\ss3://"),
        _command(r"\bgsutil\s+(?:cp|rsync|mv)\b", r"\sgs://"),
        _command(r"\brclone\s+(?:copy|sync|move)\b", r"\s\w+:"),
        # guardrail.yaml: config_set_patterns (the dotted key is one run of `[A-Za-z0-9_.-]`) and
        # process_kill_patterns
        _command(
            r"approvals?\.",
            r"""\s+["']?(?:auto|always|true|yes|allow|approve|never_ask)""",
            gap=r"[A-Za-z0-9_.-]+",
        ),
        _command(r"\b(?:pkill|killall)\b", _GATEWAY),
        _chain(r"\bsystemctl\b", r"\b(?:stop|disable|mask|kill)\b", _GATEWAY),
        _chain(r"\blaunchctl\b", r"\b(?:unload|bootout|stop|kill|disable)\b", _GATEWAY),
        _command(r"\bdocker\s+(?:stop|kill|rm)\b", _GATEWAY),
        # guardrail.yaml content_write_marker_patterns: a file opened for writing in inline code
        _command(r"open\s*\(", r"""["'][wax]\+?["']""", gap=r"[^)]*"),
        # privilege.yaml setuid_patterns
        _command(r"\bchmod\b", r"\s(?:[ugoa]*\+[rwxX]*s[rwxX]*|[2467][0-7]{3})\b"),
        _chain(r"\bchown\b", r"\broot\b", r"\bchmod\b", r"\+s"),
        # installers.yaml
        _command(r"base64\s+(?:-d|--decode|-D)\b", _TO_SHELL),
        _command(r"\bxxd\s+-r\b", _TO_SHELL),
        _command(
            r"\b(?:curl|wget)\b",
            r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|a|fi)?sh\b",
            tail_at=lambda: SudoTail(r"(?:ba|z|da|k|a|fi)?sh\b"),
        ),
        _command(
            r"\b(?:curl|wget)\b",
            r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:python[23]?|node|perl|ruby|deno|bun)\b",
            tail_at=lambda: SudoTail(r"(?:python[23]?|node|perl|ruby|deno|bun)\b"),
        ),
        _command(r"\bpip3?\s+install\b", _FROM_URL),
        _command(
            r"\bnpm\s+(?:install|i|add)\b",
            r"\s(?:https?://|github:|git\+|git://|bitbucket:|gitlab:)",
        ),
        _command(
            r"\b(?:pnpm|yarn|bun)\s+(?:add|install)\b", r"\s(?:https?://|github:|git\+|git://)"
        ),
        _command(r"\bpipx\s+(?:run|install)\b", _FROM_URL),
        _command(r"\buv\s+(?:run|tool\s+(?:run|install)|pip\s+install)\b", _FROM_URL),
        _command(r"\buvx", _FROM_URL, lead=r"\s+"),
        _command(r"\bnpx", r"\s(?:https?://|github:)", lead=r"\s+"),
        _command(r"\bcargo\s+install\b", r"\s--git\b"),
        _command(
            r"(?:^|[=&])command=",
            r"(?:\b(?:ba|z)?sh\b|\bpython|\bnode\b|\bperl\b)",
            gap=r"[^&]*",
        ),
        _chain(
            r"\b(?:echo|printf)\b",
            r"(?:registry|index-url)\s*=\s*https?://",
            (r">>?\s*", 1),
            r"(?:\.npmrc|pip\.conf|\.pypirc)",
        ),
        # extent.yaml bulk_patterns and destructive.yaml verbs
        _command(r"\bfind\b", r"\s-(?:exec|execdir|ok|okdir|delete)\b"),
        _command(r"\bfind\b", r"\s-delete\b"),
        _command(r"\bfind\b", r"\s-exec\s+(?:rm|shred|unlink|truncate)\b"),
        _command(r"\bxargs\b", r"\b(?:rm|shred|unlink)\b"),
        _command(r"\bgit\s+clean\b", r"\s-[A-Za-z]*[fdx]"),
        _command(r"\bdd\b", r"\bof=((?:~|\$HOME|\.{1,2})?/\S+)"),
        # remote_destructive.yaml cli
        _command(r"\bgcloud", r"\bdelete\b", lead=r"\s+", gap=r"[\w\s.-]*?"),
        _command(r"\baz", r"\bdelete\b", lead=r"\s+", gap=r"[\w\s-]*?"),
        _command(
            r"\bgit\s+push\b",
            r"(?:\s--force\b|\s-f\b|\s--force-with-lease\b|\s--delete\b|\s-d\b|\s:[^\s:]+)",
        ),
        _command(r"\bgit\s+push\b", r"\s--mirror\b"),
        (_DOCKER_REMOTE, _DOCKER_REMOTE_SEARCH),
        _command(
            r"\bDOCKER_HOST=",
            r"\s+docker\s+(?:rm|rmi|system\s+prune|volume\s+rm)\b",
            gap=r"\S+",
        ),
        _command(
            r"\bkubectl\s+(?:create|apply|replace|patch|edit)\b",
            r"\b(?:clusterrolebindings?|rolebindings?|clusterroles?|rbac)\b",
        ),
    ]
)

#: Of `LINEAR`, patterns whose match is built here from the start found, as the regex builds it (they
#: have no groups): pattern -> where the match from a start ends.
MATCH_END: dict[str, Callable[[str, int], int]] = {
    _DOCKER_REMOTE: lambda text, start: _lead_gap_tail_end(
        text,
        start,
        _rx(r"\b(?:DOCKER_HOST=\S+\s+)?docker\s+(?:-H|--host)[\s=]"),
        _rx(_DOCKER_REMOVE),
    )
}

#: Of `LINEAR`, the patterns whose match is not built from the start found (`search` asks the regex):
#: the remote-copy marker, whose callers only ask whether it is there.
FOUND_ONLY: frozenset[str] = frozenset({_REMOTE_COPY})

#: A match with a given span: a chain has no groups, so its match is its span.
_SPAN = re.compile(r".*", re.S)


_FLAGS = re.compile("", re.IGNORECASE).flags


def _linear(rx: re.Pattern[str]) -> Search | None:
    # The linear pieces are compiled case-insensitive and nothing else, so any other flag set
    # (multiline, ASCII, verbose) is searched as the plain regex.
    return LINEAR.get(rx.pattern) if rx.flags == _FLAGS else None


def found(rx: re.Pattern[str], text: str) -> bool:
    """`rx.search(text) is not None`, in linear time for the patterns in `LINEAR`."""
    linear = _linear(rx)
    return linear(text, 0) >= 0 if linear is not None else rx.search(text) is not None


def search(rx: re.Pattern[str], text: str, pos: int = 0) -> re.Match[str] | None:
    """`rx.search(text, pos)`: for the patterns in `LINEAR` the leftmost start is found in linear time
    and the regex matches from there (none found, nothing to match)."""
    linear = _linear(rx)
    if linear is not None and rx.pattern in CHAIN_SPANS:
        span = next(CHAIN_SPANS[rx.pattern](text, pos), None)
        return None if span is None else _SPAN.match(text, *span)
    if linear is None or rx.pattern in FOUND_ONLY:
        if linear is not None and linear(text, pos) < 0:
            return None
        return rx.search(text, pos)
    start = linear(text, pos)
    if start < 0:
        return None
    if rx.pattern in MATCH_END:
        end = MATCH_END[rx.pattern](text, start)
        if end >= 0:
            return _SPAN.match(text, start, end)
    return rx.match(text, start) or rx.search(text, pos)


@dataclass(frozen=True)
class OptionRun:
    """One branch `<head>(?:<option>)*<end>` of a pattern (`*?` when `lazy`), read where:
    - the head matches at most one way, ending in a whitespace run that the option and the end cannot
      start with (so the run is taken whole);
    - an option matches at most one way that lets anything follow: a word, then the whole whitespace run
      after it (a shorter word or run leaves whitespace, or a non-space, where none can be);
    - the end is the last piece of the pattern. With `truncate`, it holds no `$`, `\\b` or lookahead
      at its end, so the pattern matched up to where the end's match ends gives that same match.
    `end_at`, when given, decides whether the end matches at a position (for an end with a `.*`, whose
    regex reads to the end of the text each time) and is built once per text."""

    head: str
    option: str | None
    end: str
    lazy: bool = False
    truncate: bool = True
    end_at: Callable[[str, int], Callable[[int], bool]] | None = None


def option_run_finditer(rx: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """`rx.finditer(text)` for a pattern in `OPTION_RUNS`, in linear time; any other pattern is
    searched as the regex it is.

    The regex, at each head, takes every option word after it (`-x -x …`) and tries the end after
    each count, the most first (`*`) or the fewest (`*?`); at a later head in the same run it tries the
    same positions again, which is quadratic in the run. The positions after a head form a chain (each
    option word leads to the one after it), shared by every head in the run: here each position is
    read once, with the answer for the chain from it (the last, or first, position on it where the end
    matches) kept. A head whose chain has such a position starts a match, and the regex then builds
    it from that head, bounded by where the end's match ends; the regex reads no further than that
    match then."""
    branches = OPTION_RUNS.get((rx.pattern, rx.flags))
    if branches is None:
        yield from rx.finditer(text)
        return
    compiled = [_option_run_compiled(b, rx.flags) for b in branches]
    starts = sorted(
        (m.start(), i) for i, (find, *_rest) in enumerate(compiled) for m in find.finditer(text)
    )
    memo: list[dict[int, int]] = [{} for _ in branches]
    end_at: list[Callable[[int], bool] | None] = [None] * len(branches)
    pos = 0
    for h, i in starts:
        if h < pos:
            continue
        branch = branches[i]
        _find, head, option, end = compiled[i]
        q0 = head.match(text, h)
        if q0 is None:
            continue
        if end_at[i] is None:
            end_at[i] = (
                branch.end_at(text, rx.flags)  # type: ignore[call-arg]
                if branch.end_at is not None
                else (lambda q, end=end: end.match(text, q) is not None)
            )
        at = _option_run_best(text, q0.end(), option, end_at[i], branch.lazy, memo[i])  # type: ignore[arg-type]
        if at < 0:
            continue
        m = None
        if branch.truncate:
            e = end.match(text, at)
            assert e is not None
            m = rx.match(text, h, e.end())
            if m is not None and m.end() != e.end():
                m = None
        if m is None:
            m = rx.match(text, h)
        if m is None:  # not reached: the chain says the regex matches here
            yield from _finditer_from(rx, text, pos)
            return
        yield m
        pos = m.end() if m.end() > m.start() else m.end() + 1


def _finditer_from(rx: re.Pattern[str], text: str, pos: int) -> Iterator[re.Match[str]]:
    while pos <= len(text):
        m = rx.search(text, pos)
        if m is None:
            return
        yield m
        pos = m.end() if m.end() > m.start() else m.end() + 1


def _option_run_best(
    text: str,
    q: int,
    option: re.Pattern[str] | None,
    end_at: Callable[[int], bool],
    lazy: bool,
    memo: dict[int, int],
) -> int:
    """The position on the chain from `q` where the regex's end match is made: the last one where
    the end matches (the first, `lazy`); -1 for none. Fills `memo` for every position walked."""
    chain: list[int] = []
    p: int | None = q
    while p is not None and p not in memo:
        chain.append(p)
        o = option.match(text, p) if option is not None else None
        p = o.end() if o is not None else None
    after = memo[p] if p is not None else -1
    for p in reversed(chain):
        if lazy:
            after = p if end_at(p) else after
        elif after < 0:
            after = p if end_at(p) else -1
        memo[p] = after
    return memo[q]


_OPTION_RUN_RX: dict[tuple[OptionRun, int], tuple] = {}


def _option_run_compiled(
    b: OptionRun, flags: int
) -> tuple[re.Pattern[str], re.Pattern[str], re.Pattern[str] | None, re.Pattern[str]]:
    """The branch's head finder (every position its head matches at, overlapping ones too), head,
    option and end, compiled with the pattern's flags."""
    key = (b, flags)
    if key not in _OPTION_RUN_RX:
        _OPTION_RUN_RX[key] = (
            re.compile(f"(?=(?:{b.head}))", flags),
            re.compile(b.head, flags),
            re.compile(b.option, flags) if b.option is not None else None,
            re.compile(b.end, flags),
        )
    return _OPTION_RUN_RX[key]


def option_run_pattern(prefix: str, branches: Sequence[OptionRun], suffix: str = "") -> str:
    """The pattern text the branches spell: `prefix(?:b1|b2|…)suffix`, or the one branch bare when
    there is one and no prefix or suffix. Each branch reads `head(?:option)*end` (`*?` when lazy), its
    head and end taken without the prefix and suffix they were given."""
    parts = []
    for b in branches:
        head = b.head[len(prefix) :] if prefix and b.head.startswith(prefix) else b.head
        end = b.end[: len(b.end) - len(suffix)] if suffix else b.end
        run = f"(?:{b.option})*{'?' if b.lazy else ''}" if b.option is not None else ""
        parts.append(head + run + end)
    if len(parts) == 1 and not prefix and not suffix:
        return parts[0]
    return prefix + "(?:" + "|".join(parts) + ")" + suffix


def _sed_end_at(text: str, flags: int) -> Callable[[int], bool]:
    """`(?:-i\\S*|--in-place\\S*)\\s.*\\s(\\S+)\\s*(?:$|[;&])` at a position: the option word and a
    space, then (`.*` taking any run) the last place in the text where `\\s(\\S+)\\s*(?:$|[;&])`
    matches, if it is no earlier. That place is found once."""
    word = re.compile(r"(?:-i\S*|--in-place\S*)\s", flags)
    m = re.compile(r".*(\s)(\S+)\s*(?:$|[;&])", flags | re.S).match(text)
    last = m.start(1) if m is not None else -1

    def at(q: int) -> bool:
        w = word.match(text, q)
        return w is not None and last >= w.end()

    return at


_PY_HEAD = r"\bpython[\d.]*\s+"
_LONG_OPTION = r"-\S+\s+"

#: Patterns of the form `<head>(?:<option>)*<end>` (and alternations of them), by pattern text and
#: flags -> their branches. `option_run_finditer` reads them in linear time; the tests check each
#: against its regex.
OPTION_RUNS: dict[tuple[str, int], tuple[OptionRun, ...]] = {
    (
        option_run_pattern("", bs, sfx) if pre is None else option_run_pattern(pre, bs, sfx),
        flags,
    ): bs
    for pre, bs, sfx, flags in [
        # entities: hosts given to ssh-like commands and to netcat-like commands
        (
            None,
            (
                OptionRun(
                    r"(?:ssh|scp|rsync|sftp)\s+",
                    _LONG_OPTION,
                    r"(?:[\w.-]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
                ),
            ),
            "",
            re.UNICODE,
        ),
        (
            None,
            (
                OptionRun(
                    r"\b(?:nc|ncat|netcat|telnet)\s+",
                    r"-\w+\s+",
                    r"([A-Za-z0-9.-]+\.[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})",
                ),
            ),
            "",
            re.UNICODE,
        ),
        # entities: the module `python -m` runs, and where an inline program's text starts
        (
            None,
            (OptionRun(_PY_HEAD, r"-[A-Za-z]+\s+", r"-m\s*([\w.]+)", lazy=True),),
            "",
            re.UNICODE,
        ),
        (
            r"\b",
            (
                OptionRun(_PY_HEAD, r"-[A-Za-z]+\s+", r"-[A-Za-z]*c[\s=]+", lazy=True),
                OptionRun(
                    r"\b(?:node|nodejs|bun)\s+",
                    _LONG_OPTION,
                    r"(?:-e|--eval|-p|--print)[\s=]+",
                    lazy=True,
                ),
                OptionRun(r"\b(?:perl|ruby)\s+", _LONG_OPTION, r"-[A-Za-z]*[eE][\s=]+", lazy=True),
                OptionRun(r"\bphp\s+", _LONG_OPTION, r"-r[\s=]+", lazy=True),
                OptionRun(r"\bdeno\s+eval", None, r"[\s=]+"),
            ),
            r"[\s=]+",
            re.UNICODE,
        ),
        # written_selfmod: a shell running what a fetch prints through a substitution, an inline
        # program that may fetch and run, and wget's combined short flags ending in `O` (without the
        # group around the options its substitution reads)
        (
            None,
            (
                OptionRun(
                    r"(?:\b(?:ba|z|k|da|fi)?sh|\beval|\bsource|(?:^|[\s;&|(])\.)\s+",
                    r"-\w+\s+",
                    r"[\"']?(?:\$\(|`|<\()\s*(?:\S+/)?(?:curl|wget|fetch)\b",
                    truncate=False,
                ),
            ),
            "",
            re.UNICODE,
        ),
        (
            None,
            (
                OptionRun(
                    r"\b(?:python[23]?|node|deno|bun|perl|ruby|php)\s+",
                    r"-\w+\s+",
                    r"(?:-c|-e|-E|-r|--eval)\b",
                    truncate=False,
                ),
            ),
            "",
            re.UNICODE | re.IGNORECASE,
        ),
        (
            None,
            (
                OptionRun(
                    r"\bwget\s+", r"-\S+\s+", r"-([A-Za-z]+)O(?=\s)", lazy=True, truncate=False
                ),
            ),
            "",
            re.UNICODE,
        ),
        # written_selfmod: the file an in-place sed edits
        (
            None,
            (
                OptionRun(
                    r"\bsed\s+",
                    r"-\w+\s+",
                    r"(?:-i\S*|--in-place\S*)\s.*\s(\S+)\s*(?:$|[;&])",
                    truncate=False,
                    end_at=_sed_end_at,
                ),
            ),
            "",
            re.UNICODE | re.S,
        ),
    ]
}


def finditer(rx: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """`rx.finditer(text)`, each next match found as `search` finds one (for a chain, its matches'
    spans read in one pass; for a pattern in `FOUND_ONLY`, the regex's own matches once one is known
    to exist)."""
    linear = _linear(rx)
    if linear is not None and rx.pattern in CHAIN_SPANS:
        for span in CHAIN_SPANS[rx.pattern](text, 0):
            yield _SPAN.match(text, *span)  # type: ignore[misc]
        return
    if linear is None or rx.pattern in FOUND_ONLY:
        if linear is None or linear(text, 0) >= 0:
            yield from rx.finditer(text)
        return
    pos = 0
    while pos <= len(text):
        m = search(rx, text, pos)
        if m is None:
            return
        yield m
        pos = m.end() if m.end() > m.start() else m.end() + 1
