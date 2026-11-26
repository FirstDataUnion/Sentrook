"""What Python source run by a code tool (Hermes `execute_code`) can reach on the network.

A URL or a quoted shell command inside a string literal (`"curl -X POST https://api.x.io/v1"`) is text the
code holds. It names a destination only when the code reaches a network sink that could act on it: an
HTTP library, a socket, a subprocess or shell, a host web tool, or anything this reading does not follow
(a module outside the known-local list, a dynamic import, `exec`/`eval`, an attribute walk through
dunders or stack frames, a name the code never binds). Code with no such sink only mentions the hosts it
writes. Writing a file counts as a sink unless the file is plainly data (`.json`, `.txt`, …): a quoted
command written into `~/.bashrc` or a `.pth` file runs later.

When the code's only sinks are HTTP calls this module follows (`requests`, `httpx`, `urllib.request`) and
every request call is aimed at a URL whose host the code writes, the hosts of those URLs are its targets: a
URL inside the body or any other data is a mention. The host is written when the whole URL is, or when the
written start of it reaches past the host (the `/` after it, or a `?` or `#`) whatever follows:
`'https://api.x.io/v1/' + path`, an f-string, `.format` or `%` with such a start, or `urljoin` of such a
base with a written relative path. The URL may come directly, through a name set only to such URLs (read
from the scope Python reads it from), through a `Request` built from one, or through a parameter of a
function the program defines and calls only by its name, every call passing such a URL. A target the code
computes (`requests.post(T["u"])`, a loop variable, an argument some call computes, a start that stops at
the host: `'https://api.x.io' + rest` may go on as `.evil.net`) is not followed, and then every host the
code writes stays a possible destination. So is a function an earlier program left in the interpreter, a
request function taken from anything but the client module itself (`s.post(u)`), and any program that makes
types of its own (a `class`, `type(name, bases, ns)`, a dunder method), whose objects may answer `+`, `%` or
a method call with any URL.
"""

from __future__ import annotations

import ast
import builtins
import importlib
import inspect
import re
import urllib
import urllib.parse
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urljoin, urlsplit

__all__ = [
    "CodeReach",
    "KernelEffects",
    "kernel_effects",
    "kernel_reads",
    "plain_mentions",
    "python_reach",
]


@dataclass(frozen=True)
class CodeReach:
    #: The code reaches a network sink, or something this reading does not follow.
    network: bool
    #: The hosts every request call is aimed at, when each target is a URL written in the code; None
    #: when the code reaches no network or a target is not followed.
    targets: frozenset[str] | None = None


_LOCAL = CodeReach(network=False)
_UNFOLLOWED = CodeReach(network=True)

#: Modules that act only on local data. A dotted name is local only as written here.
_LOCAL_MODULES = frozenset(
    {
        "__future__",
        "abc",
        "argparse",
        "array",
        "ast",
        "base64",
        "binascii",
        "bisect",
        "bz2",
        "calendar",
        "cmath",
        "codecs",
        "collections",
        "collections.abc",
        "configparser",
        "copy",
        "csv",
        "dataclasses",
        "datetime",
        "decimal",
        "difflib",
        "enum",
        "fnmatch",
        "fractions",
        "functools",
        "glob",
        "gzip",
        "hashlib",
        "heapq",
        "hmac",
        "html",
        "html.parser",
        "itertools",
        "json",
        "keyword",
        "locale",
        "lzma",
        "math",
        "numbers",
        "operator",
        "os.path",
        "pathlib",
        "pprint",
        "random",
        "re",
        "secrets",
        "shlex",
        "statistics",
        "struct",
        "tarfile",
        "textwrap",
        "time",
        "tomllib",
        "unicodedata",
        "urllib.parse",
        "uuid",
        "warnings",
        "xml.etree",
        "xml.etree.ElementTree",
        "zipfile",
        "zlib",
    }
)

#: Modules local only through these attributes (and names imported from them): anything else
#: (`os.system`, `os.popen`, `sys.modules`, the Hermes `terminal` or web tools) is not followed.
_RESTRICTED: dict[str, frozenset[str]] = {
    "os": frozenset(
        {
            "path",
            "environ",
            "getenv",
            "listdir",
            "scandir",
            "walk",
            "getcwd",
            "sep",
            "linesep",
            "pathsep",
            "curdir",
            "pardir",
            "devnull",
            "name",
            "makedirs",
            "mkdir",
            "remove",
            "unlink",
            "rmdir",
            "stat",
            "lstat",
            "fspath",
            "fsencode",
            "fsdecode",
            "access",
            "R_OK",
            "W_OK",
            "X_OK",
            "F_OK",
            "cpu_count",
            "getpid",
            "urandom",
            "get_terminal_size",
        }
    ),
    "sys": frozenset(
        {
            "argv",
            "exit",
            "stdout",
            "stderr",
            "stdin",
            "version",
            "version_info",
            "maxsize",
            "platform",
            "getsizeof",
            "setrecursionlimit",
            "getrecursionlimit",
        }
    ),
    "urllib": frozenset({"parse"}),
    "contextlib": frozenset({"contextmanager", "suppress", "nullcontext", "closing"}),
    "io": frozenset({"StringIO", "BytesIO"}),
    "tempfile": frozenset({"gettempdir", "mkdtemp", "TemporaryDirectory"}),
    # `string.Formatter().get_field` and `typing.get_type_hints` reach attributes and code by name.
    "string": frozenset(
        {
            "ascii_letters",
            "ascii_lowercase",
            "ascii_uppercase",
            "digits",
            "hexdigits",
            "octdigits",
            "punctuation",
            "printable",
            "whitespace",
            "capwords",
            "Template",
        }
    ),
    "typing": frozenset(
        {
            "TYPE_CHECKING",
            "Any",
            "Callable",
            "Counter",
            "DefaultDict",
            "Dict",
            "FrozenSet",
            "Generator",
            "Iterable",
            "Iterator",
            "List",
            "Literal",
            "Mapping",
            "NamedTuple",
            "Optional",
            "Sequence",
            "Set",
            "Tuple",
            "Type",
            "TypedDict",
            "Union",
            "cast",
        }
    ),
    "xml": frozenset({"etree"}),
    # The Hermes code tool's own module: its file tools stay local; `terminal`, `web_search` and
    # `web_extract` reach a shell or the network.
    "hermes_tools": frozenset({"read_file", "write_file", "search_files", "patch"}),
}

#: HTTP clients whose request calls this module follows, and the package that binds each one when it
#: is imported without an alias (`import urllib.request` binds `urllib`).
_HTTP_MODULES = frozenset({"requests", "httpx", "urllib.request"})

#: Builtins that run or reach code this reading cannot see.
_OPAQUE_BUILTINS = frozenset(
    {
        "__import__",
        "exec",
        "eval",
        "compile",
        "globals",
        "locals",
        "vars",
        "__builtins__",
        "breakpoint",
        "help",  # imports any module by name
    }
)
#: Dunder names a program may read: anything else (`__loader__`, `__spec__`, `__build_class__`) reaches
#: the import machinery.
_SAFE_DUNDER_NAMES = frozenset({"__name__", "__file__", "__doc__"})
#: Attribute prefixes and names that reach stack frames, and through them every module and builtin
#: (`gen.gi_frame.f_builtins["__import__"]`).
_FRAME_PREFIXES = ("f_", "gi_", "cr_", "ag_", "tb_", "co_")
_FRAME_ATTRS = frozenset({"walk_stack", "walk_tb", "stack", "currentframe"})
#: Attributes that move, link or unpack files: a data file renamed to `~/.bashrc` runs later.
_FILE_MOVES = frozenset(
    {
        "symlink_to",
        "hardlink_to",
        "link_to",
        "extractall",
        "extract",
        "copyfile",
        "copytree",
        "move",
    }
)
#: File classes that take a path and a mode like `open` (`zipfile.ZipFile(p, "w")`).
_FILE_CLASSES = frozenset({"FileIO", "ZipFile", "TarFile", "GzipFile", "BZ2File", "LZMAFile"})
#: Calls that create or open a file where this reading cannot check the path.
_FILE_FACTORIES = frozenset(
    {"NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile", "mkstemp", "FileType"}
)
#: The one dot-directory a program may write data files in: the code tool's own scratch space.
_SCRATCH_DOT_DIR = re.compile(r"/\.hermes/cache/")
#: Data files a tool reads settings or commands from (`package.json` scripts, editor tasks, MCP and hook
#: settings, pip requirements) or an agent reads as instructions: never written by "local" code. A name is
#: denied when it is one of these, or contains one of the words.
_DENIED_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "composer.json",
        "deno.json",
        "deno.jsonc",
        "tasks.json",
        "launch.json",
        "claude.md",
        "agents.md",
        "skill.md",
        "gemini.md",
        "memory.md",
        "soul.md",
        "user.md",
        "tools.md",
        "heartbeat.md",
        "cmakelists.txt",
        "lefthook.json",
        "nodemon.json",
        "project.json",
        "kernel.json",
        "keybindings.json",
    }
)
_DENIED_WORDS = (
    "settings",
    "config",
    "mcp",
    "hooks",
    "requirements",
    "constraints",
    # agent instruction files and their variants (`CLAUDE.local.md`, `AGENTS.override.md`)
    "claude",
    "agents",
    "gemini",
    "hermes",
    "skill",
)
#: Calls that write a file at their path argument.
_WRITE_CALLS = frozenset({"write_text", "write_bytes", "write_file", "patch"})
#: Names that open or write a file: followed only where the program calls them directly, so the path and mode
#: are seen (`o = open; o(p, "a")`, `partial(open, mode="a")`, `wt = Path(p).write_text` are not followed).
_WRITERS = frozenset({"open"}) | _FILE_CLASSES | _FILE_FACTORIES | _WRITE_CALLS
#: Extensions of files a write may create: data, never read as code or configuration.
_DATA_EXTENSIONS = (".json", ".jsonl", ".txt", ".md", ".csv", ".tsv")
#: Dunder attributes that do not lead out of the object (`super().__init__()`); any other one can walk to
#: modules and builtins the code never imports (`().__class__.__base__.__subclasses__()`).
_SAFE_DUNDERS = frozenset(
    {
        "__init__",
        "__name__",
        "__qualname__",
        "__doc__",
        "__len__",
        "__repr__",
        "__str__",
        "__eq__",
        "__hash__",
        "__lt__",
        "__iter__",
        "__next__",
        "__enter__",
        "__exit__",
        "__contains__",
        "__getitem__",
        "__setitem__",
        "__post_init__",
    }
)
#: Calls that name an attribute by a string: followed only for a plain, non-dunder constant.
_ATTR_BY_NAME = frozenset({"getattr", "setattr", "delattr"})
_ATTR_CALLERS = frozenset({"attrgetter", "methodcaller"})
_BUILTINS = frozenset(dir(builtins))
#: The modules `os.path` is, by platform.
_PATH_MODULES = frozenset({"posixpath", "ntpath", "genericpath"})
#: How many attributes past an imported name are checked against the real objects.
_CHAIN_DEPTH = 6
#: How many values one expression may resolve to before its target counts as not followed.
_MAX_VALUES = 64

#: Call names (attribute or plain) that make an HTTP request with the followed clients.
_REQUEST_CALLS = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
        "stream",
        "send",
        "urlopen",
        "urlretrieve",
        "Request",
        "build_request",
    }
)
#: With a followed client, calls and keywords that set where requests go other than by their URL.
_UNFOLLOWED_CALLS = frozenset(
    {
        "build_opener",
        "install_opener",
        "OpenerDirector",
        "ProxyHandler",
        "URLopener",
        "FancyURLopener",
        "set_proxy",
        "mount",
    }
)
#: Names that make a type or an object with methods of the program's choosing.
_TYPE_FACTORIES = frozenset({"SimpleNamespace", "new_class", "make_dataclass", "prepare_class"})
#: Modules whose functional APIs make types (`enum.Enum("E", {...})`, `abc.ABCMeta(...)`).
_TYPE_MODULES = frozenset({"enum", "abc", "types", "typing", "copyreg"})
#: Request keywords that let code change the request as it is sent.
_RETARGET_KEYWORDS = frozenset({"auth", "hooks", "event_hooks"})
#: Calls that set one header by a name this reading would have to follow.
_HEADER_SETTERS = frozenset({"add_header", "add_unredirected_header", "putheader"})
#: What a program may take from a client module (`requests.post`, `urllib.request.Request`,
#: `urllib.parse.urljoin`): its request functions, its error and URL helpers. Anything else reached through
#: the module (`urllib.request.os`, `requests.utils`) is not followed.
_CLIENT_ATTRS = frozenset(
    {
        "Request",
        "urlopen",
        "urlretrieve",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
        "stream",
        "Session",
        "session",
        "Client",
        "AsyncClient",
        "Timeout",
        "HTTPError",
        "URLError",
        "HTTPStatusError",
        "RequestError",
        "RequestException",
        "ConnectionError",
        "TimeoutException",
        "codes",
        "urljoin",
        "urlencode",
        "quote",
        "quote_plus",
        "unquote",
        "unquote_plus",
        "urlparse",
        "urlsplit",
        "urlunparse",
        "urlunsplit",
        "parse_qs",
        "parse_qsl",
        *_UNFOLLOWED_CALLS,
    }
)
_UNFOLLOWED_KEYWORDS = frozenset({"base_url", "proxies", "proxy", "mounts", "transport"})

_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_SCHEMES = ("http://", "https://", "ws://", "wss://")


def _host(text: str, exact: bool) -> str | None:
    """The host of a URL written as `text` (all of it when `exact`, else a prefix of it): None unless the
    scheme is a web one and the host is fully written (followed by `/`, `?` or `#`, or the end of an exact
    value), so `https://api.x.io{path}` is not read as `api.x.io`."""
    if not text.lower().startswith(_SCHEMES):
        return None
    scheme, rest = text.split("://", 1)
    end = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=-1)
    if end < 0 and not exact:
        return None
    authority = rest if end < 0 else rest[:end]
    if not authority or any(c in authority for c in "{}$%\\ \t\n"):
        return None
    try:
        host = urlsplit(f"{scheme}://{authority}").hostname
    except ValueError:
        return None
    host = (host or "").strip(".").lower()
    return host or None


def _call_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _url_arg(call: ast.Call) -> ast.expr | None:
    """A request call's URL argument: `url=`, else the first positional one, or the second after a method
    (`requests.request("POST", url)`; a `.request(…)` always takes the method first)."""
    for kw in call.keywords:
        if kw.arg == "url":
            return kw.value
    args = call.args
    if not args or any(isinstance(a, ast.Starred) for a in args):
        return None
    if _call_name(call.func) == "request":
        return args[1] if len(args) > 1 else None
    first = args[0]
    if (
        isinstance(first, ast.Constant)
        and isinstance(first.value, str)
        and first.value.upper() in _METHODS
    ):
        return args[1] if len(args) > 1 else None
    return first


def _argument(call: ast.Call, args: ast.arguments, param: ast.arg) -> ast.expr | None:
    """What `call` passes for `param`: the argument in its place, by keyword, or the parameter's default.
    None when the call unpacks arguments (`*a`, `**kw`) or `param` collects them."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(
        k.arg is None for k in call.keywords
    ):
        return None
    positional = [*args.posonlyargs, *args.args]
    at = next((i for i, a in enumerate(positional) if a is param), None)
    if at is not None:
        if at < len(call.args):
            return call.args[at]
        if at >= len(args.posonlyargs):
            for k in call.keywords:
                if k.arg == param.arg:
                    return k.value
        first = len(positional) - len(args.defaults)
        return args.defaults[at - first] if at >= first else None
    at = next((i for i, a in enumerate(args.kwonlyargs) if a is param), None)
    if at is None:
        return None
    for k in call.keywords:
        if k.arg == param.arg:
            return k.value
    return args.kw_defaults[at]


def _allowed_path(start: str | None, end: str | None) -> bool:
    """A write target whose known start (`start`), known end (`end`) or whole path (both, the same) passes:
    no dot-directory or dotfile, other than the code tool's scratch space, and no denied name. `end` alone may
    begin inside a name."""
    text = start if start is not None else end or ""
    text = _SCRATCH_DOT_DIR.sub("/scratch/", text)
    parts = text.split("/")
    if end is not None and start is None and not text.startswith("/"):
        name_known = len(parts) > 1
        parts = parts[1:]  # the first part may be the tail of a name the program computes
    else:
        name_known = True
    if any(p.startswith(".") and p not in (".", "..") for p in parts):
        return False
    if start is not None and text.startswith("/etc/"):
        return False  # system configuration
    if start is not None and end is None:
        return True  # a start alone: the name is checked from the end
    name = (parts[-1] if parts else "").lower()
    tail = (end or "").rsplit("/", 1)[-1].lower()
    if not name_known:
        # `D + k + "_rows.json"`: the name ends with the tail; it must not be able to end as a denied one
        if tail.startswith(".") or any(d.endswith(tail) for d in _DENIED_NAMES):
            return False
        return not any(w in tail for w in _DENIED_WORDS)
    if name in _DENIED_NAMES or any(w in name for w in _DENIED_WORDS):
        return False
    return True


def _hosts_of(values: list[tuple[str, bool]] | None) -> set[str] | None:
    """The hosts of request URLs with these values, or None when one of them is not known."""
    if not values:
        return None
    hosts: set[str] = set()
    for text, exact in values:
        h = _host(text, exact)
        if h is None:
            return None
        hosts.add(h)
    return hosts


def _plain_keys(values: list[tuple[str, bool]] | None) -> bool:
    return values is not None and all(
        exact and "://" not in t and not t.lower().startswith(_SCHEMES) for t, exact in values
    )


def _harmless_opaque(node: ast.Name, parents: dict[ast.AST, ast.AST]) -> str | None:
    """The few forms of an opaque builtin that change nothing: `__import__("re")` of a local module (returns
    `import:re`), `"k" in globals()` (`read`), and `exec(open("/dev/null").read())` (`noop`). None for any
    other use: `globals().get(k)` hands back any global, the interpreter's builtins included."""
    call = parents.get(node)
    if not (isinstance(call, ast.Call) and call.func is node):
        return None
    if node.id == "__import__":
        if len(call.args) == 1 and not call.keywords:
            arg = call.args[0]
            if (
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and arg.value in _LOCAL_MODULES
                and "." not in arg.value  # `__import__("os.path")` returns `os`
                and arg.value not in _RESTRICTED
                and arg.value != "__future__"
            ):
                return "import:" + arg.value
        return None
    if node.id == "globals" and not call.args:
        parent = parents.get(call)
        if (
            isinstance(parent, ast.Compare)
            and call in parent.comparators
            and all(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops)
        ):
            return "read"
        return None
    if node.id == "exec" and len(call.args) == 1 and not call.keywords:
        read = call.args[0]
        if (
            isinstance(read, ast.Call)
            and not read.args
            and isinstance(read.func, ast.Attribute)
            and read.func.attr == "read"
            and isinstance(read.func.value, ast.Call)
            and isinstance(read.func.value.func, ast.Name)
            and read.func.value.func.id == "open"
            and len(read.func.value.args) == 1
            and isinstance(read.func.value.args[0], ast.Constant)
            and read.func.value.args[0].value == "/dev/null"
        ):
            return "noop"
    return None


def _parse(source: str) -> ast.Module:
    """Parse the program without the interpreter's warnings about its text (`"\\."` escapes are common)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(source)


class _Unfollowed(Exception):
    pass


_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
#: A name as read in one scope: the function (or lambda) that owns it, None for the module, or "*" for a name
#: read unscoped (`_Reader.declared`).
_Key = tuple[object, str]
#: A binding: the value assigned, a parameter (`ast.arg`), a `def`, or None for anything else.
_Bound = ast.expr | ast.arg | ast.FunctionDef | ast.AsyncFunctionDef | None


def _scopes(tree: ast.Module) -> dict[ast.AST, ast.AST | None]:
    """The function or lambda whose local names each node's names are, None for the module. A def's
    decorators, defaults and annotations belong to the scope it is written in, its parameters and body to the
    function. A comprehension counts as the scope around it: a name bound there is one more value the outer
    name may hold, never one fewer. A class body would hide the name around it, so a program with a class is
    not followed at all (`_Reader._makes_types`)."""
    out: dict[ast.AST, ast.AST | None] = {}
    stack: list[tuple[ast.AST, ast.AST | None]] = [(tree, None)]
    while stack:
        node, scope = stack.pop()
        out[node] = scope
        if not isinstance(node, _FUNCS):
            stack.extend((c, scope) for c in ast.iter_child_nodes(node))
            continue
        a = node.args
        out[a] = node
        outer: list[ast.AST] = [*a.defaults, *(d for d in a.kw_defaults if d is not None)]
        if not isinstance(node, ast.Lambda):
            outer += [*node.decorator_list, *getattr(node, "type_params", [])]
            if node.returns is not None:
                outer.append(node.returns)
        for arg in (*a.posonlyargs, *a.args, a.vararg, *a.kwonlyargs, a.kwarg):
            if arg is not None:
                out[arg] = node
                if arg.annotation is not None:
                    outer.append(arg.annotation)
        stack.extend((n, scope) for n in outer)
        body = node.body if isinstance(node.body, list) else [node.body]
        stack.extend((n, node) for n in body)
    return out


def _dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _host_header(value: object) -> bool:
    """A `Host` header name (or the same in bytes), which sends the request to another site on the address."""
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    return isinstance(value, str) and value.strip().lower().rstrip(":") == "host"


def _relative(text: str) -> bool:
    """A reference `urljoin` resolves against the base's host: no scheme, no `//` authority, nothing a parser
    strips or reads as a separator (spaces, controls, backslashes)."""
    return (
        not text.startswith("//")
        and ":" not in text
        and all(33 <= ord(c) < 127 and c != "\\" for c in text)
    )


def _check_module(obj: object) -> None:
    if inspect.ismodule(obj) and not (
        obj.__name__ in _LOCAL_MODULES
        or obj.__name__ in _PATH_MODULES
        or obj.__name__ in _RESTRICTED
    ):
        raise _Unfollowed


def _allowed_attrs(obj: object) -> frozenset[str] | None:
    """The attributes allowed through `obj` when it is a restricted module (however it was reached), else
    None."""
    if inspect.ismodule(obj):
        return _RESTRICTED.get(obj.__name__)
    return None


class _Reader:
    def __init__(self, tree: ast.Module, *, tolerant: bool = False) -> None:
        #: Reading what a program leaves in the interpreter (`kernel_effects`): the web-read tools and the
        #: followed HTTP clients are allowed, and so are names an earlier program bound.
        self.tolerant = tolerant
        self.tree = tree
        self.parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
        #: Every value a plain name is bound to; None marks a binding that is not a simple assignment.
        self.bindings: dict[str, list[ast.expr | None]] = {}
        #: The function (or lambda) each node's names belong to, None for the module (`_scopes`).
        self.scope_of = _scopes(tree)
        #: The same bindings by the scope that owns them; a parameter binds its `ast.arg` and a `def` its node.
        self.scoped: dict[tuple[ast.AST | None, str], list[_Bound]] = {}
        #: Names some scope declares `global` or `nonlocal`, or bound where no scope was given: read unscoped.
        self.declared: set[str] = set()
        #: `import top.sub` statements per `top`: each binds the same package, so they count as one binding.
        self.package_imports: dict[str, int] = {}
        #: Every read of each plain name, gathered when a parameter is resolved from the calls.
        self._loads: dict[str, list[ast.Name]] | None = None
        #: Names bound to a restricted module, with the attributes allowed through them.
        self.restricted: dict[str, set[str]] = {}
        #: Names bound to a followed client module, and functions imported from one (alias → name).
        self.http_modules: set[str] = set()
        self.http_funcs: dict[str, str] = {}
        #: Names bound by an import of a local or restricted module, with the object each names.
        self.objects: dict[str, object] = {}
        self.http = False
        #: The program imports from `xml` (an `ElementTree` writes a file at a path).
        self.xml = False
        #: A function that sets where requests go was imported under another name.
        self.targets_off = False
        #: What each name (in the scope that owns it) resolves to, once worked out, so many calls on one name
        #: stay linear.
        self._name_values: dict[_Key, list[tuple[str, bool]] | None] = {}
        self._name_hosts: dict[_Key, set[str] | None] = {}
        self._name_keys: dict[_Key, bool] = {}
        self._name_own: dict[_Key, bool] = {}

    # ------------------------------------------------------------------ imports and sinks

    def _bind(self, name: str, value: ast.expr | None = None, site: ast.AST | None = None) -> None:
        """Record a binding of `name` at `site` (the node that binds it); with no site, the name is read
        unscoped wherever it is read."""
        self.bindings.setdefault(name, []).append(value)
        if site is None:
            self.declared.add(name)
            return
        bound: _Bound = value
        if isinstance(site, (ast.arg, ast.FunctionDef, ast.AsyncFunctionDef)):
            bound = site
        self.scoped.setdefault((self.scope_of.get(site), name), []).append(bound)

    def _import(self, node: ast.Import) -> None:
        for a in node.names:
            top = a.name.split(".")[0]
            bound = a.asname or top
            module = a.name if a.asname else top
            self._bind(bound, site=node)
            if a.asname is None and "." in a.name:
                self.package_imports[top] = self.package_imports.get(top, 0) + 1
            if a.name in _HTTP_MODULES:
                self.http = True
                self.http_modules.add(bound)
                if module in _RESTRICTED:  # `import urllib.request` binds `urllib`
                    self.restricted.setdefault(bound, set(_RESTRICTED[module])).add(
                        a.name.split(".", 1)[1]
                    )
                continue
            if a.name not in _LOCAL_MODULES and a.name not in _RESTRICTED:
                raise _Unfollowed
            if module in _RESTRICTED:
                self.restricted.setdefault(bound, set()).update(_RESTRICTED[module])
            elif module not in _LOCAL_MODULES:
                raise _Unfollowed
            self._object(bound, module, None)

    def _import_from(self, node: ast.ImportFrom) -> None:
        if node.level:
            raise _Unfollowed  # a relative import: a local module this reading cannot see
        module = node.module or ""
        names = [a.name for a in node.names]
        for a in node.names:
            self._bind(a.asname or a.name, site=node)
            if a.name in _ATTR_CALLERS or a.name in _ATTR_BY_NAME or a.name in _OPAQUE_BUILTINS:
                raise _Unfollowed  # `from operator import attrgetter as ag`
            if a.name in _WRITERS and a.asname and a.asname != a.name:
                raise _Unfollowed  # `from hermes_tools import write_file as w`: the call is not seen as a write
        if "*" in names and module not in _LOCAL_MODULES:
            raise _Unfollowed
        if module in _HTTP_MODULES or (module == "urllib" and "request" in names):
            self.http = True
            for a in node.names:
                if module == "urllib" and a.name == "parse":
                    continue
                if module == "urllib" and a.name != "request":
                    raise _Unfollowed
                bound = a.asname or a.name
                if a.name in _UNFOLLOWED_CALLS:
                    self.targets_off = True  # `from urllib.request import ProxyHandler as P`
                if module == "urllib":
                    self.http_modules.add(bound)
                elif a.name in _REQUEST_CALLS:
                    self.http_funcs[bound] = a.name
            return
        if module in _RESTRICTED:
            allowed = _RESTRICTED[module]
            if self.tolerant and module == "hermes_tools":
                allowed = allowed | _WEB_READ_TOOLS
            if any(n not in allowed for n in names):
                raise _Unfollowed
        elif module not in _LOCAL_MODULES:
            raise _Unfollowed
        for a in node.names:
            if a.name != "*":
                self._object(a.asname or a.name, module, a.name)

    def _object(self, bound: str, module: str, name: str | None) -> None:
        """Record what `bound` names (a module, or `name` from it), checking it is no module outside the
        local list (`from shutil import os`)."""
        try:
            obj: object = importlib.import_module(module)
        except ImportError:
            return  # not installed here (`hermes_tools`): its names are checked by `_RESTRICTED`
        if name is not None:
            if name.startswith("_"):
                raise _Unfollowed
            if not hasattr(obj, name):
                return
            obj = getattr(obj, name)
            _check_module(obj)
        self.objects[bound] = obj

    def _store(self, name: ast.Name) -> None:
        parent = self.parents.get(name)
        if isinstance(parent, ast.Assign) and any(t is name for t in parent.targets):
            self._bind(name.id, parent.value, name)
        elif isinstance(parent, ast.AnnAssign) and parent.target is name and parent.value:
            self._bind(name.id, parent.value, name)
        else:
            # a loop, `with`, unpacking, `+=` or walrus: not followed
            self._bind(name.id, site=name)

    def scan(self) -> None:
        """Collect bindings and imports; raise `_Unfollowed` at anything this reading does not follow."""
        globals_keys: set[str] = set()
        imported: list[tuple[ast.Call, str]] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                self.xml = self.xml or any(a.name.split(".")[0] == "xml" for a in node.names)
                self._import(node)
            elif isinstance(node, ast.ImportFrom):
                self.xml = self.xml or (node.module or "").split(".")[0] == "xml"
                self._import_from(node)
            elif isinstance(node, ast.Name):
                harmless = _harmless_opaque(node, self.parents)
                if node.id == "globals" and (key := self._globals_key(node)) is not None:
                    globals_keys.add(key)
                elif harmless is not None:
                    if harmless.startswith("import:"):
                        imported.append((self.parents[node], harmless[7:]))  # type: ignore[arg-type]
                elif node.id in _OPAQUE_BUILTINS:
                    raise _Unfollowed
                elif node.id.startswith("__") and node.id not in _SAFE_DUNDER_NAMES:
                    raise _Unfollowed
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    self._store(node)
            elif isinstance(node, ast.Attribute):
                if (
                    node.attr.startswith("__")
                    and node.attr.endswith("__")
                    and node.attr not in _SAFE_DUNDERS
                ):
                    raise _Unfollowed
                if node.attr.startswith(_FRAME_PREFIXES) or node.attr in _FRAME_ATTRS:
                    raise _Unfollowed
                if node.attr in _ATTR_CALLERS or node.attr in _FILE_MOVES:
                    raise _Unfollowed
            elif isinstance(node, ast.arg):
                self._bind(node.arg, site=node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._bind(node.name, site=node)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for n in node.names:
                    self._bind(n)  # read unscoped: another scope's assignments reach it
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self._bind(node.name, site=node)
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                self._bind(node.name, site=node)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                self._bind(node.rest, site=node)
        for key in globals_keys:
            # `globals()["R"] = R` binds a plain name; one that names a module, a client function or a
            # builtin could swap what a call reaches.
            if (
                key in self.objects
                or key in self.restricted
                or key in self.http_modules
                or key in self.http_funcs
                or key in _BUILTINS
            ):
                raise _Unfollowed
            self._bind(key, site=self.tree)  # a global: the module's scope
        for call, module in imported:
            self._dynamic_import(call, module)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                self._check_call(node)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self._check_name(node)
            elif isinstance(node, ast.Attribute):
                self._check_attribute(node)

    def _globals_key(self, node: ast.Name) -> str | None:
        """The key of `globals()["name"]` when `node` is that `globals` and the key is a plain name."""
        call = self.parents.get(node)
        if not (isinstance(call, ast.Call) and call.func is node and not call.args):
            return None
        sub = self.parents.get(call)
        if not (
            isinstance(sub, ast.Subscript) and sub.value is call and isinstance(sub.ctx, ast.Store)
        ):
            return None  # `globals()["run"]` read back is whatever an earlier program left
        key = sub.slice
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            return None
        if not key.value.isidentifier() or key.value.startswith("_"):
            return None
        return key.value

    def _check_call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name in _ATTR_CALLERS:
            raise _Unfollowed
        if isinstance(node.func, ast.Name) and name in _ATTR_BY_NAME:
            attr = node.args[1] if len(node.args) > 1 else None
            if not (isinstance(attr, ast.Constant) and isinstance(attr.value, str)):
                raise _Unfollowed
            if attr.value.startswith("_") or attr.value in _REQUEST_CALLS or attr.value in _WRITERS:
                raise _Unfollowed
            obj = node.args[0]
            if isinstance(obj, ast.Name) and (obj.id in self.restricted or obj.id in self.objects):
                raise _Unfollowed  # `getattr(glob, "os")`
        if name == "write" and node.args and self.xml:
            raise _Unfollowed  # `ElementTree.write(path)` writes a file at its argument
        self._check_write(node, name)

    def _check_write(self, node: ast.Call, name: str | None) -> None:
        """A call that writes a file is followed only when the file is plainly data (`_DATA_EXTENSIONS`)."""
        path: ast.expr | None = None
        if name in _FILE_FACTORIES:
            raise _Unfollowed  # `NamedTemporaryFile(suffix=".pth", …)`, `argparse.FileType("a")`
        if name == "open" or name in _FILE_CLASSES:
            if any(isinstance(a, ast.Starred) for a in node.args) or any(
                k.arg is None for k in node.keywords
            ):
                raise _Unfollowed  # `open(*args)`, `open(p, **kw)`: the mode is not seen
            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            module_open = (
                receiver is None
                or name in _FILE_CLASSES
                or (
                    isinstance(receiver, ast.Name)
                    and inspect.ismodule(self.objects.get(receiver.id))
                )
            )
            mode_at = 1 if module_open else 0
            mode: ast.expr | None = next((k.value for k in node.keywords if k.arg == "mode"), None)
            if mode is None and len(node.args) > mode_at:
                mode = node.args[mode_at]
            if mode is None:
                return  # a read
            if (
                isinstance(mode, ast.Constant)
                and isinstance(mode.value, str)
                and not set(mode.value) & set("wax+")
            ):
                return
            if module_open:
                path = node.args[0] if node.args else None
            else:
                path = receiver
        elif name in ("rename", "replace") and len(node.args) == 1 and not node.keywords:
            raise _Unfollowed  # `Path.rename(target)`; `str.replace` takes two
        elif name in _WRITE_CALLS:
            if isinstance(node.func, ast.Attribute):
                path = node.func.value
            else:
                kw = next((k.value for k in node.keywords if k.arg == "path"), None)
                path = kw if kw is not None else (node.args[0] if node.args else None)
        else:
            return
        if self.tolerant and path is not None and self._outside_import_path(path):
            return  # nothing written under /tmp or the tool's scratch space is imported later
        if path is None or not self._data_path(path, frozenset()):
            raise _Unfollowed
        if self.tolerant:
            return  # a data file changes nothing later programs reach in the interpreter
        if not self._write_allowed(path):
            raise _Unfollowed  # a dot-directory, or a data file a tool reads settings or commands from

    def _write_allowed(self, path: ast.expr) -> bool:
        """A data file outside dot-directories whose name is not on the deny list (`_DENIED_NAMES`). Parts of
        the path the program computes are unknown: the known start and end must pass, a name the program
        completes must not be able to end as a denied one, and no string anywhere in the path (a middle
        `join` argument, a `/` operand) may name a dot-directory."""
        if not self._no_dot_parts(path, frozenset()):
            return False
        exact = self._values(path, frozenset())
        if exact is not None and all(e for _, e in exact):
            return all(_allowed_path(t, t) for t, _ in exact)
        prefixes = self._path_prefixes(path, frozenset())
        suffixes = self._path_suffixes(path, frozenset())
        if not suffixes:
            return False
        return all(_allowed_path(p, None) for p in prefixes or [""]) and all(
            _allowed_path(None, t) for t in suffixes
        )

    def _no_dot_parts(self, expr: ast.expr, seen: frozenset[str]) -> bool:
        """No string in `expr` (or in what the names in it are set to) has a part starting with a dot, other
        than `.`, `..` and the code tool's scratch space."""
        self._parents_of_path = {
            child: node for node in ast.walk(expr) for child in ast.iter_child_nodes(node)
        }
        for node in ast.walk(expr):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = _SCRATCH_DOT_DIR.sub("/scratch/", node.value)
                parts = text.split("/")
                last = parts[-1]
                parent = self._parents_of_path.get(node)
                appended = (
                    isinstance(parent, ast.BinOp)
                    and isinstance(parent.op, ast.Add)
                    and parent.right is node
                ) or isinstance(parent, ast.JoinedStr)
                if appended and len(parts) == 1 and re.fullmatch(r"\.[A-Za-z0-9]{1,8}", last):
                    continue  # an extension added to a computed name (`k + ".json"`): the name rules judge it
                if any(p.startswith(".") and p not in (".", "..") for p in parts):
                    return False
            elif isinstance(node, ast.Name) and node.id not in seen:
                for b in self.bindings.get(node.id) or []:
                    if b is not None and not self._no_dot_parts(b, seen | {node.id}):
                        return False
        return True

    def _path_suffixes(self, expr: ast.expr, seen: frozenset[str]) -> list[str] | None:
        """The known end of each value the path `expr` can take."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value]
        if isinstance(expr, ast.JoinedStr):
            last = expr.values[-1] if expr.values else None
            if isinstance(last, ast.Constant) and isinstance(last.value, str):
                return [last.value]
            return None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            right = self._path_suffixes(expr.right, seen)
            if right is None:
                return None
            return ["/" + r for r in right] if isinstance(expr.op, ast.Div) else right
        if isinstance(expr, ast.Call):
            fn = _call_name(expr.func)
            if (
                fn in ("Path", "PurePath", "join", "expanduser", "abspath", "normpath")
                and expr.args
            ):
                last = self._path_suffixes(expr.args[-1], seen)
                if last is None or fn != "join" or len(expr.args) < 2:
                    return last
                return ["/" + t for t in last]
            return None
        if isinstance(expr, ast.Name) and expr.id not in seen:
            binds = self.bindings.get(expr.id) or []
            out: list[str] = []
            for b in binds:
                got = None if b is None else self._path_suffixes(b, seen | {expr.id})
                if got is None:
                    return None
                out.extend(got)
            return out or None
        return None

    def _path_prefixes(self, expr: ast.expr, seen: frozenset[str]) -> list[str] | None:
        """The known start of each value the path `expr` can take."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value]
        if isinstance(expr, ast.JoinedStr):
            first = expr.values[0] if expr.values else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return [first.value]
            return None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            left = self._path_prefixes(expr.left, seen)
            if left is None:
                return None
            sep = "/" if isinstance(expr.op, ast.Div) else ""
            return [p + sep for p in left]
        if isinstance(expr, ast.Call):
            fn = _call_name(expr.func)
            if (
                fn in ("Path", "PurePath", "join", "expanduser", "abspath", "normpath")
                and expr.args
            ):
                first = self._path_prefixes(expr.args[0], seen)
                if first is None or fn != "join" or len(expr.args) < 2:
                    return first
                return [p.rstrip("/") + "/" for p in first]
            return None
        if isinstance(expr, ast.Name) and expr.id not in seen:
            binds = self.bindings.get(expr.id) or []
            out: list[str] = []
            for b in binds:
                got = None if b is None else self._path_prefixes(b, seen | {expr.id})
                if got is None:
                    return None
                out.extend(got)
            return out or None
        return None

    def _outside_import_path(self, path: ast.expr) -> bool:
        """The path's known start is under /tmp or the code tool's scratch space, with no `..` and no `%`
        or `{` before the first computed part."""
        prefixes = self._path_prefixes(path, frozenset())
        if not prefixes:
            return False
        return all(
            re.match(
                r"\A(?:/tmp/|/var/tmp/|(?:~|/home/[^/]+|/root|/Users/[^/]+)/\.hermes/cache/)", p
            )
            and ".." not in p
            and "%" not in p
            and "{" not in p
            for p in prefixes
        )

    def _data_path(self, expr: ast.expr, seen: frozenset[str]) -> bool:
        """`expr` is a path that ends in a data extension, however the rest of it is computed."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value.lower().endswith(_DATA_EXTENSIONS)
        if isinstance(expr, ast.JoinedStr):
            last = expr.values[-1] if expr.values else None
            return last is not None and self._data_path(last, seen)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            return self._data_path(expr.right, seen)
        if (
            isinstance(expr, ast.BinOp)
            and isinstance(expr.op, ast.Mod)
            and isinstance(expr.left, ast.Constant)
            and isinstance(expr.left.value, str)
        ):
            # `"p%d.txt" % n`: the text after the last conversion is written as is
            tail = re.split(r"%[-#0 +]*\d*(?:\.\d+)?[a-zA-Z%]", expr.left.value)[-1]
            return tail.lower().endswith(_DATA_EXTENSIONS)
        if isinstance(expr, ast.Call):
            fn = _call_name(expr.func)
            if (
                fn in ("Path", "PurePath", "join", "expanduser", "abspath", "normpath")
                and expr.args
            ):
                return self._data_path(expr.args[-1], seen)
            return False
        if isinstance(expr, ast.Name) and expr.id not in seen:
            binds = self.bindings.get(expr.id) or []
            return bool(binds) and all(
                b is not None and self._data_path(b, seen | {expr.id}) for b in binds
            )
        return False

    def _check_name(self, node: ast.Name) -> None:
        parent = self.parents.get(node)
        if node.id in _WRITERS and not (isinstance(parent, ast.Call) and parent.func is node):
            raise _Unfollowed  # a writer passed around or bound to another name: its writes are not seen
        if node.id not in self.bindings and node.id not in _BUILTINS and not self.tolerant:
            # A name the program never binds: a function the host provides (a tool, called or passed
            # around), or one this reading cannot see.
            raise _Unfollowed
        if node.id in _ATTR_BY_NAME | _ATTR_CALLERS and not (
            isinstance(parent, ast.Call) and parent.func is node
        ):
            raise _Unfollowed  # `reduce(getattr, …)`
        if node.id in self.objects and node.id not in self.http_modules:
            # a client package (`import urllib.request, urllib.parse`): what is taken from it is checked
            # where requests are read (`_known_client_attr`)
            self._check_chain(node)
        if node.id in self.restricted:
            # A restricted module is local only through its allowed attributes; the module used as a
            # value (`f(os)`, `m = os`) is not followed.
            if not (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and parent.attr in self.restricted[node.id]
            ):
                raise _Unfollowed
        if node.id in self.http_modules and not (
            isinstance(parent, ast.Attribute) and parent.value is node
        ):
            raise _Unfollowed
        if node.id in self.http_funcs and not (
            isinstance(parent, ast.Call) and parent.func is node
        ):
            raise _Unfollowed  # `send = post; send(url)`: the call is not seen as a request

    def _dynamic_import(self, call: ast.Call, module: str) -> None:
        """`__import__("re")` of a local module: its attributes are checked like an import's, and a name it is
        bound to (`(re := __import__("re"))`) holds the module."""
        obj = importlib.import_module(module)
        parent = self.parents.get(call)
        if isinstance(parent, ast.Attribute) and parent.value is call:
            self._check_chain(call, obj)
        elif isinstance(parent, ast.NamedExpr) and parent.value is call:
            self.objects[parent.target.id] = obj
        elif (
            isinstance(parent, ast.Assign)
            and parent.value is call
            and len(parent.targets) == 1
            and isinstance(parent.targets[0], ast.Name)
        ):
            self.objects[parent.targets[0].id] = obj
        else:
            raise _Unfollowed

    def _check_chain(self, node: ast.expr, start: object | None = None) -> None:
        """Walk the attributes taken from an imported module or name, on the real objects: none may be
        private or a module outside the local list (`shutil.os.system`, `os.path.os`, `tempfile._os`)."""
        obj = start if start is not None else self.objects[node.id]  # type: ignore[attr-defined]
        child: ast.AST = node
        for _ in range(_CHAIN_DEPTH):
            parent = self.parents.get(child)
            allowed = _allowed_attrs(obj)
            if not (isinstance(parent, ast.Attribute) and parent.value is child):
                if inspect.ismodule(obj):
                    raise _Unfollowed  # a module used as a value (`g = glob`, `f(glob)`): its attributes are not followed
                return
            if parent.attr.startswith("_"):
                raise _Unfollowed
            if allowed is not None and parent.attr not in allowed:
                if child is node and isinstance(node, ast.Name) and node.id in self.restricted:
                    allowed = self.restricted[node.id]  # `import urllib.request` adds `request`
                if parent.attr not in allowed:
                    raise _Unfollowed
            if not hasattr(obj, parent.attr):
                return
            obj = getattr(obj, parent.attr)
            _check_module(obj)
            child = parent

    def _check_attribute(self, node: ast.Attribute) -> None:
        if node.attr in _WRITERS and isinstance(node.ctx, ast.Load):
            parent = self.parents.get(node)
            if not (isinstance(parent, ast.Call) and parent.func is node):
                raise _Unfollowed  # `wt = Path(p).write_text`, `partial(gzip.open, …)`
        if not self.http or node.attr not in _REQUEST_CALLS:
            return
        if (
            node.attr == "request"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.http_modules
        ):
            return  # `urllib.request`: the module, not a call
        parent = self.parents.get(node)
        if not (isinstance(parent, ast.Call) and parent.func is node):
            raise _Unfollowed  # `partial(requests.post, …)`, `f = s.post`

    # ------------------------------------------------------------------ request targets

    def targets(self) -> frozenset[str] | None:
        if self._makes_types():
            return None
        hosts: set[str] = set()
        seen = False
        for node in ast.walk(self.tree):
            if isinstance(node, ast.keyword) and node.arg in _UNFOLLOWED_KEYWORDS:
                return None
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                return None
            if isinstance(node, ast.keyword) and node.arg is None:
                return None  # `requests.post(url, **kw)`: `kw` may carry `proxies`
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and isinstance(node.value, ast.Attribute)
            ):
                return None  # `s.proxies["https"] = …`
            if isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Name) and node.func.id in ("setattr", "delattr"))
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("update", "setdefault")
                    and isinstance(node.func.value, ast.Attribute)
                )
            ):
                return None  # `setattr(req, "full_url", …)`, `s.proxies.update(…)`
            if self.targets_off:
                return None  # `req.full_url = …`, `s.proxies = …`: the request changes after it is built
            if (isinstance(node, ast.Attribute) and node.attr in _UNFOLLOWED_CALLS) or (
                isinstance(node, ast.Name) and node.id in _UNFOLLOWED_CALLS
            ):
                return None
            if self._environ_changed(node):
                return None  # `os.environ["HTTPS_PROXY"] = …` sends every request elsewhere
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            if isinstance(node.func, ast.Name):
                if self._own_function(node.func):
                    continue  # the program's own `def post(p, body)`: its requests are read inside it
                name = self.http_funcs.get(name or "", name)
            if name in _UNFOLLOWED_CALLS:
                return None
            if name not in _REQUEST_CALLS:
                continue
            url = _url_arg(node)
            if url is None:
                if name == "get" and not node.args and not node.keywords:
                    continue  # `queue.get()`: no argument, no request
                return None
            # `s.post(u)`, `K().Request(u)`: only the client module's own function is read as a request to `u`
            client = not isinstance(node.func, ast.Attribute) or self._module_receiver(node.func)
            found = self._request_hosts(url, frozenset()) if client else None
            if found is None:
                if name == "get" and self._plain_key(url):
                    continue  # `data.get("key")`, `os.environ.get(KEY)`: a lookup, not a request
                return None
            hosts |= found
            seen = True
        return frozenset(hosts) if seen else None

    def _makes_types(self) -> bool:
        """The program does something this reading does not model where a request goes, and its targets are
        not followed:

        - it makes a type of its own (a `class`, a dunder method, `type` used other than to look at a value,
          the `enum`, `abc`, `types` or `typing` modules, a namespace or class factory): its objects may
          answer `+`, `%`, a name lookup or a method call with any URL;
        - it calls `__init__` or `__new__`, or takes a private or dunder attribute (`r.__init__(other)`
          re-aims a built request);
        - it takes from a client module anything but its known request functions and types
          (`urllib.request.os.system`);
        - it passes `auth=` or a hook (which may change the request as it is sent), or sets a `Host` header
          (the request then reaches another site on the same address)."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                return True
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _dunder(node.name):
                return True
            if isinstance(node, ast.Name) and node.id == "type" and isinstance(node.ctx, ast.Load):
                if not self._type_looked_at(node):
                    return True  # `type(n, b, ns)`, `t = type`, `type(x)(…)`
            if (isinstance(node, ast.Name) and node.id in _TYPE_FACTORIES) or (
                isinstance(node, ast.Attribute) and node.attr in _TYPE_FACTORIES
            ):
                return True
            if isinstance(node, ast.Import) and any(
                a.name.split(".")[0] in _TYPE_MODULES for a in node.names
            ):
                return True
            if (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").split(".")[0] in _TYPE_MODULES
            ):
                return True
            if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
                return True
            if isinstance(node, ast.keyword) and node.arg in _RETARGET_KEYWORDS:
                return True
            if isinstance(node, ast.Constant) and _host_header(node.value):
                return True
            if isinstance(node, ast.Call) and _call_name(node.func) in _HEADER_SETTERS:
                return True  # `r.add_header(k, v)`: headers only from a literal `headers=`
            if isinstance(node, ast.Name) and node.id in self.http_modules:
                if not self._known_client_attr(node):
                    return True
        return False

    def _type_looked_at(self, node: ast.Name) -> bool:
        """`type(x)` compared, passed on, or its `__name__` read: never called, bound or given more
        arguments."""
        call = self.parents.get(node)
        if not (
            isinstance(call, ast.Call)
            and call.func is node
            and len(call.args) == 1
            and not call.keywords
        ):
            return False
        use = self.parents.get(call)
        if isinstance(use, ast.Compare) or isinstance(use, ast.FormattedValue):
            return True
        if isinstance(use, ast.Call) and call in use.args:
            return True
        return isinstance(use, ast.Attribute) and use.attr == "__name__"

    def _known_client_attr(self, node: ast.Name) -> bool:
        """`node` names a client module and the attributes taken from it are its known request functions
        and types (`urllib.request.urlopen`, `requests.post`), not a way into anything else."""
        parent = self.parents.get(node)
        if not isinstance(parent, ast.Attribute):
            return True  # the module used as a value: `_check_name` refuses it
        allowed = _CLIENT_ATTRS
        attr: ast.AST = parent
        if parent.attr in ("request", "parse", "error"):
            nxt = self.parents.get(parent)
            if not isinstance(nxt, ast.Attribute) or nxt.value is not parent:
                return parent.attr in ("request", "parse", "error")
            attr = nxt
        return getattr(attr, "attr", None) in allowed

    def _module_receiver(self, func: ast.Attribute) -> bool:
        """`func` is taken from a followed client module itself (`requests.post`, `urllib.request.Request`,
        `ur.urlopen`), the module's name bound once, by its import."""
        recv = func.value
        if isinstance(recv, ast.Attribute) and recv.attr == "request":
            recv = recv.value  # `urllib.request.X`
        if not isinstance(recv, ast.Name) or recv.id in self.declared:
            return False
        return recv.id in self.http_modules and self._bound_once(recv.id)

    def _bound_once(self, name: str) -> bool:
        """`name` is bound once, counting repeated `import name.sub` statements as one."""
        count = len(self.bindings.get(name) or [])
        return count - max(self.package_imports.get(name, 0) - 1, 0) == 1

    def _environ_changed(self, node: ast.AST) -> bool:
        """`node` is the environment, used other than to read one value (`os.environ.get(k)`,
        `os.environ[k]`)."""
        if not (
            (isinstance(node, ast.Attribute) and node.attr == "environ")
            or (isinstance(node, ast.Name) and node.id == "environ")
        ):
            return False
        parent = self.parents.get(node)
        if isinstance(parent, ast.Subscript) and parent.value is node:
            return not isinstance(parent.ctx, ast.Load)
        if isinstance(parent, ast.Attribute) and parent.value is node and parent.attr == "get":
            call = self.parents.get(parent)
            return not (isinstance(call, ast.Call) and call.func is parent)
        return True

    def _plain_key(self, expr: ast.expr) -> bool:
        """`expr` is only ever plain strings that are no URL (a dict or environment key)."""
        if isinstance(expr, ast.Name):
            key, _ = self._scope_binds(expr)
            if key not in self._name_keys:
                self._name_keys[key] = _plain_keys(self._values(expr, frozenset()))
            return self._name_keys[key]
        return _plain_keys(self._values(expr, frozenset()))

    def _scope_binds(self, name: ast.Name) -> tuple[_Key, Sequence[_Bound]]:
        """The bindings `name` reads, from the innermost scope that binds it as Python does (a function's
        locals, then each enclosing function's, then the module's). A name some scope declares `global` or
        `nonlocal` reads every binding anywhere."""
        if name.id in self.declared:
            return ("*", name.id), self.bindings.get(name.id) or []
        scope = self.scope_of.get(name)
        while scope is not None:
            if (scope, name.id) in self.scoped:
                return (scope, name.id), self.scoped[(scope, name.id)]
            scope = self.scope_of.get(scope)
        return (None, name.id), self.scoped.get((None, name.id), [])

    def _own_function(self, name: ast.Name) -> bool:
        """`name` is only ever a plain function this program defines with `def` in the module or in a
        function, never a method."""
        key, binds = self._scope_binds(name)
        if key not in self._name_own:
            self._name_own[key] = bool(binds) and all(
                isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)) and not self._in_class(b)
                for b in binds
            )
        return self._name_own[key]

    def _in_class(self, node: ast.AST) -> bool:
        """`node` is written in a class body (directly or under an `if`, `try`, …), not in a function."""
        parent = self.parents.get(node)
        while parent is not None and not isinstance(parent, (*_FUNCS, ast.Module)):
            if isinstance(parent, ast.ClassDef):
                return True
            parent = self.parents.get(parent)
        return False

    def _request_hosts(self, expr: ast.expr, seen: frozenset[object]) -> set[str] | None:
        """The hosts a request URL argument (or a `Request` it names) is aimed at, or None."""
        name = _call_name(expr.func) if isinstance(expr, ast.Call) else None
        if isinstance(expr, ast.Call) and name in ("Request", "build_request"):
            # The client's own: a `Request` the program defines or binds (`def Request(u)`, a method of that
            # name, `Request = …`) or one taken from anything but the client module may return any URL.
            if name in self.declared or len(self.bindings.get(name) or []) != (
                1 if name in self.http_funcs else 0
            ):
                return None
            if isinstance(expr.func, ast.Attribute) and not self._module_receiver(expr.func):
                return None
            inner = _url_arg(expr)
            return None if inner is None else self._request_hosts(inner, seen)
        if isinstance(expr, ast.Name):
            key, binds = self._scope_binds(expr)
            if key in seen:
                return None
            if key not in self._name_hosts:
                if binds and all(isinstance(b, ast.Call) for b in binds):
                    hosts = self._bound_hosts(key, binds, seen)
                else:
                    hosts = _hosts_of(self._values(expr, seen))
                self._name_hosts[key] = hosts
            return self._name_hosts[key]
        return _hosts_of(self._values(expr, seen))

    def _bound_hosts(
        self, key: _Key, binds: Sequence[_Bound], seen: frozenset[object]
    ) -> set[str] | None:
        out: set[str] = set()
        for b in binds:
            assert isinstance(b, ast.Call)
            got = self._request_hosts(b, seen | {key})
            if got is None:
                return None
            out |= got
        return out

    def _bound_values(
        self, key: _Key, binds: Sequence[_Bound], seen: frozenset[object]
    ) -> list[tuple[str, bool]] | None:
        out: list[tuple[str, bool]] = []
        for b in binds:
            if b is None or isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return None
            if isinstance(b, ast.arg):
                got = self._param_values(b, seen | {key})
            else:
                got = self._values(b, seen | {key})
            if got is None:
                return None
            out.extend(got)
            if len(out) > _MAX_VALUES:
                return None  # too many to follow: every host stays a possible destination
        return out

    def _param_values(
        self, param: ast.arg, seen: frozenset[object]
    ) -> list[tuple[str, bool]] | None:
        """The values a parameter takes: what every call of its function passes (or its default), when the
        function is a plain `def` this program calls only by its name, each call with arguments in plain
        view. Anything else (a method, a decorated or lambda function, a function passed around or called
        with `*args`/`**kw`, a `*args` parameter) is not followed."""
        func = self.scope_of.get(param)
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) or func.decorator_list:
            return None
        if self._in_class(func) or func.name in self.declared:
            return None
        if len(self.bindings.get(func.name) or []) != 1:
            return None  # the name is bound to something else too, somewhere
        if self._loads is None:
            self._loads = {}
            for n in ast.walk(self.tree):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                    self._loads.setdefault(n.id, []).append(n)
        reads = self._loads.get(func.name) or []
        if not reads:
            return None
        out: list[tuple[str, bool]] = []
        for read in reads:
            call = self.parents.get(read)
            if not (isinstance(call, ast.Call) and call.func is read):
                return None  # `map(send, urls)`, `f = send`: calls this reading does not see
            arg = _argument(call, func.args, param)
            got = None if arg is None else self._values(arg, seen)
            if got is None:
                return None
            out.extend(got)
            if len(out) > _MAX_VALUES:
                return None
        return out

    def _is_urljoin(self, func: ast.expr) -> bool:
        """`func` is `urllib.parse.urljoin`, imported by name or reached through the module."""
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name) or root.id in self.declared:
            return False
        if not self._bound_once(root.id):
            return False
        if isinstance(func, ast.Name):
            return self.objects.get(func.id) is urllib.parse.urljoin
        if not (isinstance(func, ast.Attribute) and func.attr == "urljoin"):
            return False
        if func.value is root:
            return self.objects.get(root.id) is urllib.parse  # `import urllib.parse as up`
        mod = func.value
        if not (isinstance(mod, ast.Attribute) and mod.value is root and mod.attr == "parse"):
            return False
        return self.objects.get(root.id) is urllib or (
            root.id in self.http_modules and "parse" in self.restricted.get(root.id, ())
        )

    def _joined(self, call: ast.Call, seen: frozenset[object]) -> list[tuple[str, bool]] | None:
        """`urljoin(base, "rel")` with a written relative reference: the base's host is the result's."""
        if len(call.args) != 2 or call.keywords:
            return None
        rel = call.args[1]
        if not (isinstance(rel, ast.Constant) and isinstance(rel.value, str)):
            return None
        if not _relative(rel.value):
            return None
        base = self._values(call.args[0], seen)
        if base is None:
            return None
        out: list[tuple[str, bool]] = []
        for text, exact in base:
            if _host(text, exact) is None:
                return None
            out.append((urljoin(text, rel.value), True) if exact else (text, False))
        return out

    def _values(self, expr: ast.expr, seen: frozenset[object]) -> list[tuple[str, bool]] | None:
        """The string values `expr` can take, each as (text, exact): `exact` False means only a prefix of
        the value is known. None when nothing is known."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [(expr.value, True)]
        if isinstance(expr, ast.Name):
            key, binds = self._scope_binds(expr)
            if not binds or key in seen:
                return None
            # A name that depends on itself (`u = u + "/x"`) resolves to None however it is reached.
            if key not in self._name_values:
                self._name_values[key] = self._bound_values(key, binds, seen)
            return self._name_values[key]
        if isinstance(expr, ast.JoinedStr):
            text = ""
            for part in expr.values:
                if not (isinstance(part, ast.Constant) and isinstance(part.value, str)):
                    return [(text, False)]
                text += part.value
            return [(text, True)]
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = self._values(expr.left, seen)
            if left is None:
                return None
            right = self._values(expr.right, seen)
            out = []
            for text, exact in left:
                if not exact or right is None:
                    out.append((text, False))
                else:
                    out.extend((text + r, e) for r, e in right)
                if len(out) > _MAX_VALUES:
                    return None
            return out
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "format"
        ):
            base = self._values(expr.func.value, seen)
            if base is None:
                return None
            return [(t.split("{", 1)[0], False) for t, _ in base]
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
            base = self._values(expr.left, seen)  # `"https://h/v1/%s" % p`
            if base is None:
                return None
            return [(t.split("%", 1)[0], False) for t, _ in base]
        if isinstance(expr, ast.Call) and self._is_urljoin(expr.func):
            return self._joined(expr, seen)
        return None


# ------------------------------------------------------------------ names read before they are bound

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _target_names(target: ast.AST) -> set[str]:
    """Names an assignment target binds (`a, b = …`), not those read in it (`globals()["k"] = …`)."""
    return {
        n.id
        for n in ast.walk(target)
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
    }


def _stmt_binds(stmt: ast.stmt) -> set[str]:
    """Names a simple statement binds once it has run."""
    if isinstance(stmt, (ast.Import, ast.ImportFrom)):
        return {(a.asname or a.name).split(".")[0] for a in stmt.names if a.name != "*"}
    if isinstance(stmt, ast.Assign):
        return set().union(*(_target_names(t) for t in stmt.targets))
    if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        return _target_names(stmt.target) if getattr(stmt, "value", None) is not None else set()
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {stmt.name}
    return set()


def _local_names(scope: ast.AST) -> set[str]:
    """Names a function binds in its own scope (Python makes each one local for the whole body), less
    those it declares `global` or `nonlocal`."""
    names: set[str] = set()
    declared: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        a = scope.args
        for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]:
            if arg is not None:
                names.add(arg.arg)
    body = scope.body if isinstance(scope.body, list) else [scope.body]
    stack: list[ast.AST] = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            declared.update(node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names |= _stmt_binds(node)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        if isinstance(node, _SCOPES):
            if not isinstance(node, ast.Lambda):
                names.add(node.name)
            # a nested scope's defaults, decorators and bases run here; its body does not
            stack.extend(getattr(node, "decorator_list", []))
            if isinstance(node, ast.ClassDef):
                stack.extend(node.bases)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return names - declared


def _may_run_code(stmt: ast.stmt) -> bool:
    """`stmt` may call a function defined above it: anything but an import, a plain `def` or an
    assignment of values that call nothing."""
    if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass)):
        return False
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
        return any(
            isinstance(n, (ast.Call, ast.Subscript, ast.Attribute, ast.BinOp, ast.Compare))
            for n in ast.walk(stmt.value)
        )
    return True


class _Flow:
    """Every global name the program reads is bound by the program before the read (or is a builtin it
    never rebinds). A code tool may keep one interpreter for a whole conversation, so a name read first
    and bound later (`terminal(cmd)` before `def terminal`) is whatever an earlier call left there."""

    def __init__(self, tree: ast.Module) -> None:
        self.stored = {
            n.id
            for n in ast.walk(tree)
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
        } | {name for n in ast.walk(tree) if isinstance(n, ast.stmt) for name in _stmt_binds(n)}
        self.deferred: list[tuple[ast.AST, frozenset[str]]] = []
        #: Builtins (and safe dunder names) the program reads without binding them: the interpreter's.
        self.builtin_reads: set[str] = set()
        #: The names bound where a class body starts, while checking it: its methods and comprehensions
        #: do not see the names the class body binds.
        self.class_outer: frozenset[str] | None = None

    def run(self, tree: ast.Module) -> None:
        self.block(tree.body, set(), frozenset())
        while self.deferred:
            scope, enclosing = self.deferred.pop()
            local = enclosing | _local_names(scope)
            body = scope.body if isinstance(scope.body, list) else [scope.body]
            for node in body:
                if isinstance(node, ast.stmt):
                    self.block([node], set(local), frozenset(local))
                else:
                    self.expr(node, set(local), frozenset(local))

    def ok(self, name: str, bound: set[str], enclosing: frozenset[str]) -> bool:
        if name in bound or name in enclosing:
            return True
        if (name in _BUILTINS or name in _SAFE_DUNDER_NAMES) and name not in self.stored:
            self.builtin_reads.add(name)
            return True
        return False

    def expr(self, node: ast.AST, bound: set[str], enclosing: frozenset[str]) -> None:
        stack = [node]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if not self.ok(n.id, bound, enclosing):
                    raise _Unfollowed
            elif isinstance(n, ast.Lambda):
                stack.extend([*n.args.defaults, *(d for d in n.args.kw_defaults if d)])
                self.deferred.append((n, enclosing | self._scope_bound(bound)))
                continue
            elif isinstance(n, _COMPREHENSIONS):
                inner = set(self._scope_bound(bound))
                for gen in n.generators:
                    self.expr(gen.iter, inner, enclosing)
                    inner |= _target_names(gen.target)
                    for cond in gen.ifs:
                        self.expr(cond, inner, enclosing)
                parts = [n.key, n.value] if isinstance(n, ast.DictComp) else [n.elt]
                for part in parts:
                    self.expr(part, inner, enclosing)
                continue
            elif isinstance(n, ast.NamedExpr):
                stack.append(n.value)  # its target counts as bound nowhere: the branch may not run
                continue
            stack.extend(ast.iter_child_nodes(n))

    def _scope_bound(self, bound: set[str]) -> frozenset[str]:
        """What a nested scope created here sees of the names bound so far: in a class body, not the
        class's own names."""
        return self.class_outer if self.class_outer is not None else frozenset(bound)

    def block(self, stmts: list[ast.stmt], bound: set[str], enclosing: frozenset[str]) -> set[str]:
        """Check `stmts` in order; return the names definitely bound after them. A function's body is
        checked against the names bound when the block next runs code (it cannot be called sooner), not
        those bound by the end of the module (`g()` before `terminal = print`)."""
        pending: list[ast.AST] = []

        def settle() -> None:
            for scope in pending:
                self.deferred.append((scope, enclosing | self._scope_bound(bound)))
            pending.clear()

        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = stmt.args
                for d in [*stmt.decorator_list, *a.defaults, *(d for d in a.kw_defaults if d)]:
                    self.expr(d, bound, enclosing)
                if stmt.decorator_list:
                    settle()
                bound.add(stmt.name)  # bound before the body can run, so it may call itself
                pending.append(stmt)
                if stmt.decorator_list:
                    settle()  # a decorator may call the function now
                continue
            if _may_run_code(stmt):
                settle()
            if isinstance(stmt, ast.ClassDef):
                for d in [*stmt.decorator_list, *stmt.bases, *(k.value for k in stmt.keywords)]:
                    self.expr(d, bound, enclosing)
                outer, self.class_outer = self.class_outer, self._scope_bound(bound)
                try:
                    self.block(stmt.body, set(bound), enclosing)
                finally:
                    self.class_outer = outer
                bound.add(stmt.name)
            elif isinstance(stmt, ast.If):
                self.expr(stmt.test, bound, enclosing)
                if isinstance(stmt.test, ast.NamedExpr):
                    bound.add(
                        stmt.test.target.id
                    )  # `if (m := …):` always binds before either branch
                then = self.block(stmt.body, set(bound), enclosing)
                other = self.block(stmt.orelse, set(bound), enclosing)
                bound |= then & other
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                self.expr(stmt.iter, bound, enclosing)
                self.block(stmt.body, bound | _target_names(stmt.target), enclosing)
                self.block(stmt.orelse, set(bound), enclosing)
            elif isinstance(stmt, ast.While):
                self.expr(stmt.test, bound, enclosing)
                self.block(stmt.body, set(bound), enclosing)
                self.block(stmt.orelse, set(bound), enclosing)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self.expr(item.context_expr, bound, enclosing)
                    if item.optional_vars is not None:
                        bound |= _target_names(item.optional_vars)
                # a context manager may swallow an exception, so what the body binds is not definite
                self.block(stmt.body, set(bound), enclosing)
            elif isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
                done = self.block(stmt.body + stmt.orelse, set(bound), enclosing)
                for h in stmt.handlers:
                    if h.type is not None:
                        self.expr(h.type, bound, enclosing)
                    names = {h.name} if h.name else set()
                    done &= self.block(h.body, bound | names, enclosing) - names
                bound |= done
                bound |= self.block(stmt.finalbody, set(bound), enclosing)
            elif isinstance(stmt, ast.Match):
                self.expr(stmt.subject, bound, enclosing)
                for case in stmt.cases:
                    names = {
                        n.name
                        for n in ast.walk(case.pattern)
                        if isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name
                    }
                    if case.guard is not None:
                        self.expr(case.guard, bound | names, enclosing)
                    self.block(case.body, bound | names, enclosing)
            elif isinstance(stmt, ast.Delete):
                self.expr(stmt, bound, enclosing)
                for t in stmt.targets:
                    bound -= _target_names(t)
            else:
                if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                    if not self.ok(stmt.target.id, bound, enclosing):
                        raise _Unfollowed  # `x += …` reads x first
                self.expr(stmt, bound, enclosing)
                bound |= _stmt_binds(stmt)
        settle()
        return bound


@lru_cache(maxsize=256)
def python_reach(source: str) -> CodeReach | None:
    """What `source` (Python) can reach; None when it does not parse, so callers keep reading it as text."""
    try:
        tree = _parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    reader = _Reader(tree)
    try:
        _Flow(tree).run(tree)
        reader.scan()
        if not reader.http:
            return _LOCAL
        return CodeReach(network=True, targets=reader.targets())
    except (_Unfollowed, RecursionError):
        return _UNFOLLOWED


# ------------------------------------------------------------------ a plain program's mentions

#: Modules a plain program may import: files, JSON, text, time and `urllib`.
_PLAIN_IMPORTS = frozenset(
    {
        "os",
        "os.path",
        "json",
        "re",
        "time",
        "datetime",
        "pathlib",
        "sys",
        "urllib",
        "urllib.request",
        "urllib.parse",
        "urllib.error",
    }
)
_PLAIN_URLLIB = frozenset({"request", "parse", "error"})
#: Keywords a plain program's request calls may pass.
_PLAIN_REQUEST_KEYWORDS = frozenset(
    {"url", "data", "json", "headers", "params", "timeout", "method"}
)
#: Names a plain program never reads: each reaches objects, attributes or code by a computed name.
_PLAIN_BANNED = frozenset(
    {
        "getattr",
        "setattr",
        "delattr",
        "hasattr",
        "exec",
        "eval",
        "compile",
        "globals",
        "locals",
        "vars",
        "__import__",
        "type",
        "super",
        "object",
        "breakpoint",
        "memoryview",
    }
)
#: Calls that put values into one string or URL: `"…{}".format(x)`, `sep.join(xs)`, `s.replace(a, b)`,
#: `urljoin(base, ref)`, `re.sub(p, repl, s)`.
_JOIN_CALLS = frozenset(
    {
        "format",
        "format_map",
        "join",
        "replace",
        "urljoin",
        "urlunsplit",
        "urlunparse",
        "sub",
        "subn",
        "expand",
    }
)
#: How many mentioned hosts one check takes.
_MAX_MENTIONS = 64


@lru_cache(maxsize=256)
def plain_mentions(source: str, hosts: frozenset[str]) -> bool:
    """`source` is a plain program and each of `hosts` it names stays text: it may count as only mentioned.

    Plain: every request target is known (`python_reach`), imports come only from `_PLAIN_IMPORTS`, and the
    program has no `lambda`, `class`, `global`, dunder name or attribute (other than `__name__ ==
    "__main__"`), private attribute, `getattr`-like or `type`-like builtin, header set by name, `Host`
    header, and passes its request calls only `_PLAIN_REQUEST_KEYWORDS`.

    Text: a string holding one of `hosts`, and every value that string flows into (by assignment, a call's
    argument, a return, a container it is added to), is never put into a string together with anything not
    written in the code (`+`, `%`, an f-string, `.format`, `.join`, `.replace`): a link built with the key
    (`"https://h/c?k=" + key`) is not text. The credential the program reads (an env file, the environment)
    is only ever put into a string with written text that holds no URL. A request's reply carries neither:
    it is what the server sent back. Names are followed by name, whatever their scope, which only adds flows."""
    if not hosts or len(hosts) > _MAX_MENTIONS:
        return False
    reach = python_reach(source)
    if reach is None or not reach.network or not reach.targets:
        return False
    try:
        tree = _parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    reader = _Reader(tree)
    try:
        reader.scan()
        return _Plain(reader, hosts).ok()
    except (_Unfollowed, RecursionError):
        return False


class _Plain:
    def __init__(self, reader: _Reader, hosts: frozenset[str]) -> None:
        self.r = reader
        self.tree = reader.tree
        self.parents = reader.parents
        self.hosts = tuple(sorted(h.lower() for h in hosts))
        self.defs: dict[str, list[ast.FunctionDef]] = {}
        for n in ast.walk(self.tree):
            if isinstance(n, ast.FunctionDef):
                self.defs.setdefault(n.name, []).append(n)
        #: Names bound by an import: a call on them (`json.dumps(x)`) does not change them.
        self.modules = {
            (a.asname or a.name).split(".")[0]
            for n in ast.walk(self.tree)
            if isinstance(n, (ast.Import, ast.ImportFrom))
            for a in n.names
        }

    def ok(self) -> bool:
        if not self._plain():
            return False
        flows = self._flows()
        mentions = self._tainted(flows, self._names_host)
        secret = self._tainted(flows, self._names_secret)
        if mentions & secret:
            return False  # one value holds both a mentioned host and the credential
        if not self._apart(mentions, secret):
            return False
        return self._joins_ok(self._tainted(flows, self._open_mention), secret)

    # ---------------------------------------------------------------- the shape

    def _plain(self) -> bool:
        for node in ast.walk(self.tree):
            if isinstance(
                node,
                (
                    ast.Lambda,
                    ast.ClassDef,
                    ast.AsyncFunctionDef,
                    ast.Global,
                    ast.Nonlocal,
                    ast.Await,
                ),
            ):
                return False
            if isinstance(node, ast.Import):
                if any(a.name not in _PLAIN_IMPORTS for a in node.names):
                    return False
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level or module not in _PLAIN_IMPORTS:
                    return False
                names = {a.name for a in node.names}
                if "*" in names or (module == "urllib" and not names <= _PLAIN_URLLIB):
                    return False
            elif isinstance(node, ast.Name):
                if node.id in _PLAIN_BANNED:
                    return False
                if _dunder(node.id) and not self._main_check(node):
                    return False
            elif isinstance(node, ast.Attribute):
                if node.attr.startswith("_"):
                    return False
            elif isinstance(node, ast.FunctionDef):
                if _dunder(node.name) or node.decorator_list:
                    return False
            elif isinstance(node, ast.Constant):
                if _host_header(node.value):
                    return False
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in _HEADER_SETTERS:
                    return False
                if name in _REQUEST_CALLS and any(
                    k.arg not in _PLAIN_REQUEST_KEYWORDS for k in node.keywords
                ):
                    return False
        return True

    def _main_check(self, node: ast.Name) -> bool:
        """`if __name__ == "__main__":`"""
        cmp = self.parents.get(node)
        return (
            node.id == "__name__"
            and isinstance(cmp, ast.Compare)
            and cmp.left is node
            and len(cmp.comparators) == 1
            and isinstance(cmp.comparators[0], ast.Constant)
            and cmp.comparators[0].value == "__main__"
        )

    # ---------------------------------------------------------------- where values go

    def _sending(self, node: ast.AST) -> bool:
        """A request call, whose result is the reply, or a request built for one (`Request(u, data=…)`), whose
        parts are sent and read back only as computed values."""
        if not isinstance(node, ast.Call):
            return False
        name = _call_name(node.func)
        if name not in _REQUEST_CALLS:
            return False
        if isinstance(node.func, ast.Attribute):
            return self.r._module_receiver(node.func)
        return node.func.id in self.r.http_funcs  # type: ignore[union-attr]

    def _parts(self, expr: ast.AST) -> list[ast.AST]:
        """The nodes of `expr`, less the inside of the request calls in it."""
        out: list[ast.AST] = []
        stack = [expr]
        while stack:
            n = stack.pop()
            out.append(n)
            if self._sending(n):
                continue
            stack.extend(ast.iter_child_nodes(n))
        return out

    def _flows(self) -> list[tuple[list[ast.AST], set[str]]]:
        """(value nodes, names they flow into) for every way a value reaches a name."""
        flows: list[tuple[list[ast.AST], set[str]]] = []

        def add(values: list[ast.AST], targets: set[str]) -> None:
            if targets:
                flows.append(([p for v in values for p in self._parts(v)], targets))

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                add([node.value], set().union(*(_stored(t) for t in node.targets)))
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                add([node.value], _stored(node.target))
            elif isinstance(node, ast.AugAssign):
                add([node.value, node.target], _stored(node.target))
            elif isinstance(node, (ast.For, ast.comprehension)):
                add([node.iter], _stored(node.target))
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                add([node.context_expr], _stored(node.optional_vars))
            elif isinstance(node, ast.NamedExpr):
                add([node.value], {node.target.id})
            elif (
                isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) and node.value is not None
            ):
                func = self.r.scope_of.get(node)
                if isinstance(func, ast.FunctionDef):
                    add([node.value], {func.name})
            elif isinstance(node, ast.FunctionDef):
                a = node.args
                params = [*a.posonlyargs, *a.args]
                for arg, default in zip(
                    params[len(params) - len(a.defaults) :], a.defaults, strict=True
                ):
                    add([default], {arg.arg})
                for arg, default in zip(a.kwonlyargs, a.kw_defaults, strict=True):
                    if default is not None:
                        add([default], {arg.arg})
            elif isinstance(node, ast.Call):
                values: list[ast.AST] = [*node.args, *(k.value for k in node.keywords)]
                func = node.func
                if isinstance(func, ast.Attribute):
                    root = _root_name(func)
                    if root is not None and root not in self.modules:
                        add(values, {root})  # `parts.append(link)`, `d.update(x)`
                elif isinstance(func, ast.Name) and func.id in self.defs:
                    for d in self.defs[func.id]:
                        for target, value in _passed(node, d):
                            add([value], {target})
        return flows

    def _tainted(self, flows, seeded) -> set[str]:
        """The names a value `seeded` marks reaches, through `flows`."""
        by_source: dict[str, list[int]] = {}
        tainted: set[str] = set()
        work: list[str] = []
        for i, (parts, targets) in enumerate(flows):
            if any(seeded(p) for p in parts):
                for t in targets - tainted:
                    tainted.add(t)
                    work.append(t)
            for p in parts:
                if isinstance(p, ast.Name) and isinstance(p.ctx, ast.Load):
                    by_source.setdefault(p.id, []).append(i)
        while work:
            name = work.pop()
            for i in by_source.get(name, ()):
                for t in flows[i][1] - tainted:
                    tainted.add(t)
                    work.append(t)
        return tainted

    def _names_host(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Constant) or not isinstance(node.value, (str, bytes)):
            return False
        text = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
        text = text.lower()
        return any(h in text for h in self.hosts)

    def _open_mention(self, node: ast.AST) -> bool:
        """A string naming a mentioned host other than as a whole URL written in it: a value put before it
        could add a scheme and userinfo, or one put after it extend the URL (`"https://h/c?k=" + key`)."""
        if not self._names_host(node):
            return False
        value = node.value  # type: ignore[attr-defined]
        text = (value.decode("latin-1") if isinstance(value, bytes) else value).lower()
        last_end = max((i for i, ch in enumerate(text) if ch in _URL_END), default=-1)
        for host in self.hosts:
            start = text.find(host)
            while start >= 0:
                if not _closed_url(text, start, len(host), last_end):
                    return True
                start = text.find(host, start + len(host))
        return False

    def _names_secret(self, node: ast.AST) -> bool:
        """The program reads its credential here: an env file it opens (`open(".../.env")`,
        `Path(".../.env").read_text()`), or the environment."""
        if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv"):
            return True
        if isinstance(node, ast.Name) and node.id in ("environ", "getenv"):
            return True
        if isinstance(node, ast.Call) and _call_name(node.func) in _FILE_READS:
            # the file named in the call or in what it is called on
            within: list[ast.AST] = [*node.args, *(k.value for k in node.keywords)]
            if isinstance(node.func, ast.Attribute):
                within.append(node.func.value)
            return any(
                isinstance(n, ast.Constant) and isinstance(n.value, str) and ".env" in n.value
                for w in within
                for n in ast.walk(w)
            )
        return False

    # ---------------------------------------------------------------- strings put together

    def _apart(self, mentions: set[str], secret: set[str]) -> bool:
        """No expression holds both a mentioned host and the credential, other than a request (or the
        request built for one) taking them as different arguments (`data=` the body, `headers=` the key)."""
        groups: list[ast.AST] = [
            c
            for stmt in ast.walk(self.tree)
            if isinstance(stmt, ast.stmt)
            for c in _expr_children(stmt)
        ]
        while groups:
            group = groups.pop()
            host = key = False
            stack = [group]
            while stack:
                n = stack.pop()
                if self._sending(n):
                    groups.extend(_call_values(n))  # type: ignore[arg-type]
                    continue
                if isinstance(n, ast.stmt):
                    continue  # a nested statement is a group of its own
                load = isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                host = host or self._names_host(n) or (load and n.id in mentions)  # type: ignore[attr-defined]
                key = key or self._names_secret(n) or (load and n.id in secret)  # type: ignore[attr-defined]
                if host and key:
                    return False
                stack.extend(ast.iter_child_nodes(n))
        return True

    def _joins_ok(self, mentions: set[str], secret: set[str]) -> bool:
        """No string is built from a mentioned host and a computed value, and the credential is put into a
        string only with written text that holds no URL."""
        facts = self._facts(mentions, secret)
        for node in ast.walk(self.tree):
            parts = self._join_parts(node)
            if parts is None:
                continue
            host = key = computed = other = url = False
            for part in parts:
                h, k, c, o, u = facts[part]
                host, key, computed, other, url = (
                    host or h,
                    key or k,
                    computed or c,
                    other or o,
                    url or u,
                )
            if host and computed:
                return False  # `"https://h/c?k=" + key`, `f"see {link}"`
            if key and (host or url or other):
                return False  # the credential put into a URL, or with another computed value
        return True

    def _facts(self, mentions: set[str], secret: set[str]) -> dict[ast.AST, tuple[bool, ...]]:
        """For every node, in one pass from the leaves up: (holds a mentioned host not written as a whole URL
        (`_open_mention`), holds the credential, holds
        a computed value, holds a computed value other than the credential or a builtin, holds a URL
        written in the code). A request call's result is a computed value with nothing of what it was
        given."""
        facts: dict[ast.AST, tuple[bool, ...]] = {}
        stack: list[tuple[ast.AST, bool]] = [(self.tree, False)]
        while stack:
            node, done = stack.pop()
            children = list(ast.iter_child_nodes(node))
            if not done:
                stack.append((node, True))
                stack.extend((c, False) for c in children)
                continue
            if self._sending(node):
                facts[node] = (False, False, True, True, False)
                continue
            h = self._open_mention(node)
            k = self._names_secret(node)
            c = o = u = False
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                u = _url_like(node.value)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                h = h or node.id in mentions
                k = k or node.id in secret
                c = True
                o = node.id not in secret and not (
                    node.id in _BUILTINS and node.id not in self.r.bindings
                )
            elif isinstance(node, (ast.Call, ast.Attribute, ast.Subscript)):
                c = True
            for child in children:
                ch, ck, cc, co, cu = facts[child]
                h, k, c, o, u = h or ch, k or ck, c or cc, o or co, u or cu
            facts[node] = (h, k, c, o, u)
        return facts

    def _join_parts(self, node: ast.AST) -> list[ast.AST] | None:
        """The values `node` puts into one string, or None when it is no such operation."""
        if isinstance(node, ast.BinOp):
            return [node.left, node.right]
        if isinstance(node, ast.AugAssign):
            return [node.target, node.value]
        if isinstance(node, ast.JoinedStr):
            return list(node.values)
        if isinstance(node, ast.Call) and _call_name(node.func) in _JOIN_CALLS:
            values = [*node.args, *(k.value for k in node.keywords)]
            if isinstance(node.func, ast.Attribute):
                values.append(node.func.value)
            return values
        return None


def _expr_children(stmt: ast.stmt) -> list[ast.AST]:
    """The expressions a statement holds directly (its nested statements are groups of their own)."""
    return [c for c in ast.iter_child_nodes(stmt) if not isinstance(c, ast.stmt)]


def _call_values(call: ast.Call) -> list[ast.AST]:
    """What a call is given: each argument a group of its own, and the object a method is called on."""
    out: list[ast.AST] = [*call.args, *(k.value for k in call.keywords)]
    if isinstance(call.func, ast.Attribute):
        out.append(call.func.value)
    return out


#: Calls that read a file's text.
_FILE_READS = frozenset({"open", "read_text", "read_bytes"})
#: Characters that end a URL written in text (markdown, HTML, quotes, whitespace).
_URL_END = frozenset(" \t\r\n)]>\"'<|`}")


def _closed_url(text: str, start: int, length: int, last_end: int) -> bool:
    """The host at `text[start:start + length]` is written as a whole URL inside `text`: right after a
    `scheme://`, and the URL ends inside the text (a space, a bracket, a quote; `last_end` is where the
    last such character is) rather than at its end."""
    if start < 4 or not text.startswith("://", start - 3):
        return False
    c = text[start - 4]
    if not (c.isalnum() or c in "+.-"):
        return False
    return last_end >= start + length


def _url_like(value: str | bytes) -> bool:
    text = value.decode("latin-1") if isinstance(value, bytes) else value
    return "://" in text or text.lstrip().startswith("//") or "%3a%2f%2f" in text.lower()


def _stored(target: ast.AST) -> set[str]:
    """The names an assignment target changes: a name, or the name a subscript or attribute is taken from."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_stored(t) for t in target.elts)) if target.elts else set()
    if isinstance(target, ast.Starred):
        return _stored(target.value)
    root = _root_name(target)
    return {root} if root is not None else set()


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _passed(call: ast.Call, func: ast.FunctionDef) -> list[tuple[str, ast.expr]]:
    """(parameter, value) for what `call` passes `func`; every parameter for every value when the call
    unpacks arguments."""
    a = func.args
    every = [p.arg for p in (*a.posonlyargs, *a.args, a.vararg, *a.kwonlyargs, a.kwarg) if p]
    values = [*call.args, *(k.value for k in call.keywords)]
    if any(isinstance(v, ast.Starred) for v in call.args) or any(
        k.arg is None for k in call.keywords
    ):
        return [(p, v) for p in every for v in values]
    out: list[tuple[str, ast.expr]] = []
    params = [p for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
    for p in params:
        value = _argument(call, a, p)
        if value is not None:
            out.append((p.arg, value))
    for i, v in enumerate(call.args):
        if i >= len(a.posonlyargs) + len(a.args):
            out.extend((p, v) for p in every)  # more than the named parameters take
    named = {p.arg for p in params}
    for k in call.keywords:
        if k.arg not in named:
            out.extend((p, k.value) for p in every)
    return out


# ------------------------------------------------------------------ what a program leaves in the interpreter

#: Reads and writes that change the interpreter in ways that cannot be listed.
_KERNEL_OPAQUE_NAMES = _OPAQUE_BUILTINS | _ATTR_BY_NAME | _ATTR_CALLERS
_KERNEL_OPAQUE_ATTRS = frozenset({"modules", "f_globals", "f_builtins", "f_locals", "f_back"})
_KERNEL_OPAQUE_MODULES = frozenset({"builtins", "importlib", "ctypes", "gc", "inspect", "types"})


@dataclass(frozen=True)
class KernelEffects:
    #: What the program leaves for later programs: `n:<builtin>` rebound to something that reaches a
    #: network sink, `m:<module>` whose attributes it patched.
    names: frozenset[str]
    #: It changed the interpreter in a way that cannot be listed (`exec`, `setattr`, `sys.modules`).
    unknown: bool


_NO_EFFECTS = KernelEffects(frozenset(), False)
_UNKNOWN_EFFECTS = KernelEffects(frozenset(), True)


@lru_cache(maxsize=256)
def kernel_reads(source: str) -> frozenset[str] | None:
    """What a program takes from the interpreter without binding it itself: `n:<builtin>` for each builtin it
    reads, `m:<module>` for each module it imports (a module is shared by every program). Every other global it
    reads it must bind first (`_Flow`). None when the program does not parse or reads a global it never binds."""
    try:
        tree = _parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    flow = _Flow(tree)
    try:
        flow.run(tree)
    except (_Unfollowed, RecursionError):
        return None
    out = {"n:" + n for n in flow.builtin_reads}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update("m:" + a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            out.add("m:" + node.module.split(".")[0])
    return frozenset(out)


#: Hermes tools that only fetch: a program that uses them may stay in the session's interpreter without
#: changing what later programs reach.
_WEB_READ_TOOLS = frozenset({"web_extract", "web_search"})
#: Dunder methods a class may define without code running when nobody calls it (`__del__` runs when a later
#: program rebinds the name that holds the object).
_PLAIN_DUNDER_METHODS = frozenset(
    {
        "__init__",
        "__repr__",
        "__str__",
        "__eq__",
        "__hash__",
        "__lt__",
        "__len__",
        "__iter__",
        "__next__",
        "__contains__",
        "__getitem__",
        "__post_init__",
    }
)


def _runs_unasked(tree: ast.Module) -> bool:
    """Code that can run later with no call from a later program: a finalizer or other hook method, a
    generator or coroutine holding a `finally` or `with` (it runs when the object is collected), or an
    `async` function."""
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            return True
        if isinstance(node, ast.FunctionDef):
            if node.name.startswith("__") and node.name not in _PLAIN_DUNDER_METHODS:
                return True
            body = [n for stmt in node.body for n in ast.walk(stmt)]
            if any(isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)) for n in body) and any(
                isinstance(n, (ast.Try, ast.With, ast.AsyncWith)) for n in body
            ):
                return True
    return False


def _clean_effects(tree: ast.Module) -> bool:
    """The program does nothing to the interpreter that a listing of rebound builtins could miss: it passes the
    local reading (`_Reader`) but for its use of the web-read tools, the followed HTTP clients and names an
    earlier program bound, and nothing of it runs unasked later (`_runs_unasked`). A thread, a subprocess, the
    terminal tool, an import hook, a redirected stdout or a module's private state all fail it."""
    if _runs_unasked(tree):
        return False
    try:
        _Reader(tree, tolerant=True).scan()
    except (_Unfollowed, RecursionError):
        return False
    return True


#: Calls through a module that register something every later program goes through (`codecs.register`,
#: `copyreg.pickle`, `sys.settrace`).
_REGISTERING = re.compile(r"\A(?:register|install|settrace|setprofile|addaudithook|pickle\Z)")


@lru_cache(maxsize=256)
def kernel_effects(source: str) -> KernelEffects:
    """What `source` leaves in a code tool's interpreter for later programs.

    A later program is read as local only when every global it reads, other than a builtin, is one it binds
    first (`_Flow`), so what matters is what it may read without binding: builtins and modules. Every builtin
    this program rebinds in the interpreter's globals (at module level, or through `global` in a function), in
    any form and to anything (`print = terminal`, `print = open`, `for print in …`, an import under that name),
    is tracked. Changing a module, or anything taken from one, by setting an attribute or registering a hook,
    makes the set unknown, as do `exec`, `setattr`, `sys.modules`, frames, a module handed around where a
    patch may follow it, and a program the scanner cannot parse (it may still run on a newer Python)."""
    try:
        tree = _parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _UNKNOWN_EFFECTS
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    global_names = {
        n for node in ast.walk(tree) if isinstance(node, ast.Global) for n in node.names
    }

    def module_scope(node: ast.AST, walrus: bool = False) -> bool:
        """`node` binds in the module's namespace: no function, lambda or class around it (a walrus target
        in a comprehension binds outside the comprehension)."""
        p = parents.get(node)
        while p is not None and not isinstance(p, ast.Module):
            if isinstance(p, _SCOPES):
                return False
            if isinstance(p, _COMPREHENSIONS) and not walrus:
                return False
            p = parents.get(p)
        return True

    def global_binding(name: str, node: ast.AST, walrus: bool = False) -> bool:
        return module_scope(node, walrus) or name in global_names

    def chain_root(node: ast.expr) -> ast.expr:
        while isinstance(node, ast.Attribute):
            node = node.value
        return node

    names: set[str] = set()
    module_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _KERNEL_OPAQUE_NAMES:
            if node.id == "globals" and (key := _plain_globals_key(node, parents)) is not None:
                names.add(key)
                continue
            harmless = _harmless_opaque(node, parents)
            if harmless is None:
                return _UNKNOWN_EFFECTS
            if harmless.startswith("import:"):
                holder = parents.get(parents[node])
                if isinstance(holder, ast.NamedExpr):
                    module_names.add(holder.target.id)
                elif isinstance(holder, ast.Assign):
                    for t in holder.targets:
                        module_names |= _target_names(t)
            continue
        if isinstance(node, ast.Attribute) and (
            node.attr in _KERNEL_OPAQUE_ATTRS
            or (
                node.attr.startswith("__")
                and node.attr.endswith("__")
                and node.attr not in _SAFE_DUNDERS
            )
        ):
            return _UNKNOWN_EFFECTS
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "type"
            and len(node.args) == 1
        ):
            return (
                _UNKNOWN_EFFECTS  # `type(obj).attr = …` patches a class shared with later programs
            )
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.level:
                continue
            for a in node.names:
                full = a.name if isinstance(node, ast.Import) else node.module or ""
                if full.split(".")[0] in _KERNEL_OPAQUE_MODULES or (
                    isinstance(node, ast.ImportFrom) and full == "sys" and a.name == "modules"
                ):
                    return _UNKNOWN_EFFECTS
                if a.name == "*":
                    return _UNKNOWN_EFFECTS  # binds names this reading does not list
                bound = a.asname or a.name.split(".")[0]
                module_names.add(bound)
                if global_binding(bound, node):
                    names.add(bound)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            walrus = isinstance(parents.get(node), ast.NamedExpr)
            if global_binding(node.id, node, walrus):
                names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if global_binding(node.name, node):
                names.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            if global_binding(node.name, node):
                names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            if global_binding(node.rest, node):
                names.add(node.rest)
        elif isinstance(node, ast.Assign):
            root = chain_root(node.value)
            if isinstance(root, ast.Name) and root.id in module_names:
                for t in node.targets:
                    module_names |= _target_names(t)  # `E = json.JSONEncoder`
    # Patching a module, or something taken from one, and registering a hook through one.
    handed_around = False
    loose_store = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = chain_root(node.value)
            if not isinstance(root, ast.Name) or root.id in module_names:
                return _UNKNOWN_EFFECTS
            loose_store = True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            root = chain_root(node.func.value)
            if (
                isinstance(root, ast.Name)
                and root.id in module_names
                and _REGISTERING.match(node.func.attr)
            ):
                return _UNKNOWN_EFFECTS
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in module_names
        ):
            top: ast.AST = node
            while isinstance(parents.get(top), ast.Attribute) and parents[top].value is top:  # type: ignore[attr-defined]
                top = parents[top]
            holder = parents.get(top)
            if isinstance(holder, ast.Call) and holder.func is top:
                continue
            if isinstance(holder, ast.Assign) and holder.value is top:
                continue  # an alias, followed above
            if isinstance(holder, ast.ExceptHandler):
                continue
            handed_around = True  # `[json.JSONEncoder]`, `f(json)`: a patch may follow it anywhere
    if handed_around and loose_store:
        return _UNKNOWN_EFFECTS
    if not _clean_effects(tree):
        return _UNKNOWN_EFFECTS
    kernelish = _BUILTINS | _SAFE_DUNDER_NAMES
    return KernelEffects(frozenset("n:" + n for n in names if n in kernelish), False)


def _plain_globals_key(node: ast.Name, parents: dict[ast.AST, ast.AST]) -> str | None:
    """The key of `globals()["name"]` when `node` is that `globals` and the key is a plain name."""
    call = parents.get(node)
    if not (isinstance(call, ast.Call) and call.func is node and not call.args):
        return None
    sub = parents.get(call)
    if not (
        isinstance(sub, ast.Subscript) and sub.value is call and isinstance(sub.ctx, ast.Store)
    ):
        return None  # `globals()["run"]` read back is whatever an earlier program left
    key = sub.slice
    if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
        return None
    if not key.value.isidentifier() or key.value.startswith("_"):
        return None
    return key.value
