"""Listed patterns searched in linear time, with the same answer as the regex.

A pattern `<head><gap><tail>` with a greedy gap (`[^;&|\\n]*`: any words to the end of the simple
command), searched as a regex, retries the gap from every head and the tail at every position after it:
a long simple command with many heads (`rsync rsync …`, `uvx uvx …`) is quadratic, a chain of such gaps
(`systemctl … stop … openclaw`) cubic, and the remote-copy tail `\\S+@\\S+:` cubic in one long word
(`a@a@…`). For the patterns in `LINEAR` the search here reads the gap ranges of all the heads once,
left to right, and tries each later piece once at each position in them. It finds where the leftmost
match starts; `search` then lets the regex match from there, which is the match `rx.search` returns.
For the patterns in `FOUND_ONLY`, whose match itself can still take the regex long to build, only
`found` is linear: their callers ask for a yes or no.

The lists keep the patterns: an entry here is keyed by the pattern's text, so a pattern changed in a
list (or an overlay) is searched as the regex it is. Every entry is checked against its regex.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence

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


_RX: dict[str, re.Pattern[str]] = {}


def _rx(pattern: str) -> re.Pattern[str]:
    """A piece of a listed pattern, compiled as the lists compile theirs (ignoring case)."""
    if pattern not in _RX:
        _RX[pattern] = re.compile(pattern, re.IGNORECASE)
    return _RX[pattern]


Search = Callable[[str, int], int]
_CHAINS: set[str] = set()


def _command(
    head: str,
    tail: str,
    *,
    lead: str = "",
    gap: str = r"[^;&|\n]*",
    prefix: tuple[str, str, Callable[[str, re.Match[str], int], int]] | None = None,
) -> tuple[str, Search]:
    """`<head><lead><gap><tail>`: the pattern's text and its linear search. `lead` (`\\s+`, `\\S+`) is a
    run the head ends with; `gap` a class run, `*` (or `+`, needing one character). `prefix`: the
    pattern's text before the head (an optional part, and the head's own start), and where a match
    whose head is found starts."""
    least = 1 if gap.endswith("+") else 0
    gap_rx = _rx(gap[:-1].rstrip("*+?") + "*" if gap.endswith(("+", "?")) else gap)
    lead_rx = _rx(lead) if lead else None
    before, head_start, start_of = prefix if prefix is not None else ("", "", None)
    return before + head + lead + gap + tail, lambda text, pos: gap_tail_first(
        text,
        _rx(head_start + head),
        regex_tail(tail),
        gap=gap_rx,
        least=least,
        lead=lead_rx,
        pos=pos,
        start_of=start_of,
    )


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
    _CHAINS.add(text)
    return text, lambda t, pos: chain_first(t, [(_rx(p), k) for p, k in parts], pos)


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
        # privilege.yaml setuid_patterns
        _command(r"\bchmod\b", r"\s(?:[ugoa]*\+[rwxX]*s[rwxX]*|[2467][0-7]{3})\b"),
        _chain(r"\bchown\b", r"\broot\b", r"\bchmod\b", r"\+s"),
        # installers.yaml
        _command(r"base64\s+(?:-d|--decode|-D)\b", _TO_SHELL),
        _command(r"\bxxd\s+-r\b", _TO_SHELL),
        _command(r"\b(?:curl|wget)\b", r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|a|fi)?sh\b"),
        _command(
            r"\b(?:curl|wget)\b",
            r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:python[23]?|node|perl|ruby|deno|bun)\b",
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
        _command(
            r"docker\s+(?:-H|--host)[\s=]",
            r"\b(?:rm|rmi|system\s+prune|volume\s+rm)\b",
            lead=r"\S+",
            prefix=(r"\b(?:DOCKER_HOST=\S+\s+)?", r"\b", _docker_host_start),
        ),
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

#: Of `LINEAR`, the patterns whose match is not built from the start found (`search` asks the regex):
#: a chain, whose match can take the regex long to build, and the remote-copy marker.
FOUND_ONLY: frozenset[str] = frozenset({_REMOTE_COPY, *_CHAINS})


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
    if linear is None or rx.pattern in FOUND_ONLY:
        if linear is not None and linear(text, pos) < 0:
            return None
        return rx.search(text, pos)
    start = linear(text, pos)
    if start < 0:
        return None
    return rx.match(text, start) or rx.search(text, pos)


def finditer(rx: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """`rx.finditer(text)`, each next match found as `search` finds one (for a pattern in
    `FOUND_ONLY`, the regex's own matches once one is known to exist)."""
    linear = _linear(rx)
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
