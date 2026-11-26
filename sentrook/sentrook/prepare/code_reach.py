"""What Python source run by a code tool (Hermes `execute_code`) can reach on the network.

A URL or a quoted shell command inside a string literal (`"curl -X POST https://api.x.io/v1"`) is text the
code holds. It names a destination only when the code reaches a network sink that could act on it: an
HTTP library, a socket, a subprocess or shell, a host web tool, or anything this reading does not follow
(a module outside the known-local list, a dynamic import, `exec`/`eval`, an attribute walk through
dunders or stack frames, a name the code never binds). Code with no such sink only mentions the hosts it
writes. Writing a file counts as a sink unless the file is plainly data (`.json`, `.txt`, …): a quoted
command written into `~/.bashrc` or a `.pth` file runs later. A data file's name may come from a loop over
a literal collection of constants or from what each call passes to a helper the program defines (a program
with a class is not followed: its methods run without being named); a `shutil` file copy or move is followed
only with both paths written out in full, and folder copies and removals are not followed.

When the code's only sinks are HTTP calls this module follows (`requests`, `httpx`, `urllib.request`) and
every request call is aimed at a URL written in the code (directly, through a name set only to such URLs,
or through a `Request` built from one), the hosts of those URLs are its targets: a URL inside the body or
any other data is a mention. A target the code computes (`requests.post(T["u"])`, a loop variable, a
function argument) is not followed, and then every host the code writes stays a possible destination.
"""

from __future__ import annotations

import ast
import builtins
import importlib
import inspect
import pathlib
import posixpath
import re
import unicodedata
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import TypeVar
from urllib.parse import urlsplit

__all__ = ["CodeReach", "KernelEffects", "kernel_effects", "kernel_reads", "python_reach"]


@dataclass(frozen=True)
class CodeReach:
    #: The code reaches a network sink, or something this reading does not follow.
    network: bool
    #: The hosts every request call is aimed at, when each target is a URL written in the code; None
    #: when the code reaches no network or a target is not followed.
    targets: frozenset[str] | None = None


_T = TypeVar("_T")

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
    # File copies and moves, followed only as direct calls whose paths are written out in full and pass the
    # write rules (`_Reader._check_shutil`); `copytree`, `rmtree`, `which`, `chown`, `unpack_archive` and the
    # rest are not followed.
    "shutil": frozenset({"copy", "copy2", "copyfile", "move"}),
}

#: The `shutil` calls `_Reader._check_shutil` follows, with the parameters each takes by position.
_SHUTIL_OPS: dict[str, tuple[str, ...]] = {
    "copy": ("src", "dst"),
    "copy2": ("src", "dst"),
    "copyfile": ("src", "dst"),
    "move": ("src", "dst"),
}
#: The keywords those calls may take besides their parameters. Not `copy_function`, which hands the paths to
#: code this reading does not see.
_SHUTIL_KEYWORDS = frozenset({"follow_symlinks"})
#: Modules followed only where the program imports them itself: reached through another module
#: (`zipfile.shutil`), their calls are not seen as the calls they are.
_DIRECT_ONLY = frozenset({"shutil"})

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
#: Attributes that move, link or unpack files: a data file renamed to `~/.bashrc` runs later. A `shutil` call
#: of these names is followed as `_Reader._check_shutil` checks it.
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
        "copy_into",
        "move_into",
    }
)
#: File classes that take a path and a mode like `open` (`zipfile.ZipFile(p, "w")`).
_FILE_CLASSES = frozenset({"FileIO", "ZipFile", "TarFile", "GzipFile", "BZ2File", "LZMAFile"})
#: Calls that create or open a file where this reading cannot check the path.
_FILE_FACTORIES = frozenset(
    {"NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile", "mkstemp", "FileType"}
)
#: The dot-directories a program may write data files in: the code tool's own scratch space, and the folder
#: Hermes keeps files shared in chat in. Not the rest of `~/.hermes` (skills, memories, plugins, config, env). A
#: write in one of them is followed only when its whole path is written out in full (`_Reader._exact_paths`), with
#: no `..`: a computed part (`os.pardir`, `.parent`, `dirname`, `chr(46) * 2`) could climb back out.
_DATA_DOT_DIRS = re.compile(r"/\.hermes/(?:cache|attachments)/")


def _mask_data_dirs(text: str) -> str:
    """`text` with the dot-directories data files may go in (`_DATA_DOT_DIRS`) written as a plain folder, unless
    it climbs back out with `..`."""
    if ".." in text.split("/"):
        return text
    return _DATA_DOT_DIRS.sub("/scratch/", text)


#: The calls `_Reader._exact_paths` follows: they join or expand paths written out in full.
_EXACT_PATH_CALLS = (
    posixpath.join,
    posixpath.expanduser,
    pathlib.Path,
    pathlib.PurePath,
    pathlib.PurePosixPath,
)
#: Names that build a class or an object with attributes set by name: a class's methods run without their
#: names being read (`K(p)` runs `__init__`, `k == x` runs `__eq__`), so what their parameters take is not seen.
_CLASS_MAKERS = frozenset({"SimpleNamespace", "new_class", "make_dataclass"})


#: Builtins that read a collection without changing it: a literal collection passed to them keeps its values.
_READ_ONLY_BUILTINS = frozenset(
    {
        "len",
        "sorted",
        "list",
        "tuple",
        "set",
        "frozenset",
        "dict",
        "print",
        "str",
        "repr",
        "enumerate",
        "zip",
        "any",
        "all",
        "sum",
        "min",
        "max",
        "iter",
        "reversed",
    }
)
#: Methods that read a literal collection without changing it.
_READ_ONLY_METHODS = frozenset({"items", "keys", "values", "get", "copy", "count", "index"})
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
        "jobs.json",  # scheduled jobs (`~/.hermes/cron/jobs.json`)
        "openclaw.json",
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
    "openclaw",
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


def _squash(text: str) -> str:
    """`text` with empty and `.` parts dropped (`//etc/./x` is `/etc/x`), as the file system reads it, and
    `/private/etc` and `/private/var` (where macOS keeps `/etc` and `/var`) written as `/etc` and `/var`."""
    parts = [p for p in text.split("/") if p not in ("", ".")]
    out = ("/" if text.startswith("/") else "") + "/".join(parts)
    if text.endswith("/") and parts:
        out += "/"
    if out.startswith(("/private/etc/", "/private/var/")) or out in (
        "/private/etc",
        "/private/var",
    ):
        out = out[len("/private") :]
    return out


def _as_pathlib(text: str) -> str:
    """A path as `pathlib` holds it: no trailing `/`, no empty or `.` parts (`Path("a//./b/")` is `a/b`)."""
    lead = (
        "//"
        if text.startswith("//") and not text.startswith("///")
        else text[:1]
        if text[:1] == "/"
        else ""
    )
    rest = "/".join(p for p in text.split("/") if p not in ("", "."))
    return (lead + rest) or "."


def _fold(name: str) -> str:
    """A name as a case-insensitive file system may match it (`AGENTſ.md` opens `AGENTS.md`)."""
    return unicodedata.normalize("NFKC", name).casefold()


def _allowed_path(start: str | None, end: str | None) -> bool:
    """A write target whose known start (`start`), known end (`end`) or whole path (both, the same) passes:
    no dot-directory or dotfile, other than the folders data files may go in (`_DATA_DOT_DIRS`), nothing under
    `/etc`, and no denied name. `end` alone may begin inside a name."""
    text = start if start is not None else end or ""
    text = _mask_data_dirs(_squash(text) if start is not None else text)
    parts = text.split("/")
    if end is not None and start is None and not text.startswith("/"):
        name_known = len(parts) > 1
        parts = parts[1:]  # the first part may be the tail of a name the program computes
    else:
        name_known = True
    if any(p.startswith(".") and p not in (".", "..") for p in parts):
        return False
    if start is not None and (text.startswith("/etc/") or text == "/etc"):
        return False  # system configuration
    if start is not None and end is None:
        return True  # a start alone: the name is checked from the end
    name = _fold(parts[-1] if parts else "")
    tail = _fold((end or "").rsplit("/", 1)[-1])
    if not name_known:
        # `D + k + "_rows.json"`: the name ends with the tail; it must not be able to end as a denied one
        if tail.startswith(".") or any(d.endswith(tail) for d in _DENIED_NAMES):
            return False
        return not any(w in tail for w in _DENIED_WORDS)
    if name in _DENIED_NAMES or any(w in name for w in _DENIED_WORDS):
        return False
    return True


def _plain_data_file(path: str) -> bool:
    """A path written out in full that names a data file (`_DATA_EXTENSIONS`) and climbs nowhere (`..`)."""
    return _fold(path).endswith(_DATA_EXTENSIONS) and ".." not in path.split("/")


#: Where a `shutil` copy or move may put a file: the user's home or `/tmp`.
_COPY_ROOTS = re.compile(r"(?:~|/home/[^/]+|/Users/[^/]+|/root)/|/tmp/")
#: Folders a copied file may not land in anywhere: programs are run or imported from them.
_COPY_REFUSED_FOLDERS = frozenset({"bin", "sbin", "site-packages", "dist-packages", "node_modules"})


def _copy_destination(path: str) -> bool:
    """A `shutil` destination written out in full: under the user's home or `/tmp` (not `/usr`, `/opt`,
    `/Library`, `/System`, `/private`, `/etc` or `/var`), with no `..` and no folder programs are run or imported
    from (`_COPY_REFUSED_FOLDERS`)."""
    text = _squash(path)
    parts = text.split("/")
    if ".." in parts or not _COPY_ROOTS.match(text):
        return False
    return not any(_fold(p) in _COPY_REFUSED_FOLDERS for p in parts)


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


@dataclass(frozen=True)
class _Pending:
    """A path binding worked out once every binding of the program is known: a loop target (an `ast.Name`) or
    a function parameter (an `ast.arg`)."""

    node: ast.AST


def _check_module(obj: object) -> None:
    if inspect.ismodule(obj) and not (
        obj.__name__ in _LOCAL_MODULES
        or obj.__name__ in _PATH_MODULES
        or obj.__name__ in _RESTRICTED
    ):
        raise _Unfollowed


def _loop_of(
    name: ast.Name, parents: dict[ast.AST, ast.AST]
) -> tuple[ast.expr, int | None, int] | None:
    """When `name` is the target of a `for` loop or a comprehension, alone or as one of a flat tuple of names
    (`for k, v in …`): the loop's iterable, the name's place in the tuple (None alone), and the tuple's size."""
    parent = parents.get(name)
    target: ast.expr = name
    index: int | None = None
    size = 0
    if isinstance(parent, (ast.Tuple, ast.List)):
        if not all(isinstance(e, ast.Name) for e in parent.elts):
            return None
        index = next(i for i, e in enumerate(parent.elts) if e is name)
        size = len(parent.elts)
        target = parent
        parent = parents.get(parent)
    if isinstance(parent, (ast.For, ast.AsyncFor, ast.comprehension)) and parent.target is target:
        return parent.iter, index, size
    return None


def _items_of(coll: ast.Dict | ast.List | ast.Tuple | ast.Set) -> list[ast.expr | None]:
    """A literal collection's items: a dict's keys and values."""
    if isinstance(coll, ast.Dict):
        return [*coll.keys, *coll.values]
    return list(coll.elts)


def _frozen(item: ast.expr | None) -> bool:
    """An item no later statement can change: a constant, or a tuple of constants."""
    if isinstance(item, ast.Constant):
        return True
    return isinstance(item, ast.Tuple) and all(isinstance(e, ast.Constant) for e in item.elts)


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
        #: The same for the paths a program writes, where a loop over a literal collection binds its target to
        #: each value, and a function's parameter is bound to what each call passes (`_resolve_path_bindings`).
        #: Request targets do not use these: a URL drawn from a loop or an argument stays not followed.
        self.path_bindings: dict[str, list[ast.expr | _Pending | None]] = {}
        #: Every place each name is read.
        self.loads: dict[str, list[ast.Name]] = {}
        #: Names bound to the `shutil` module, and to a `shutil` function `_check_shutil` follows (alias → name).
        self.shutil_modules: set[str] = set()
        self.shutil_funcs: dict[str, str] = {}
        #: What the path reading worked out for each name (`_per_name`), and the names it is working on.
        self._path_memo: dict[tuple[str, str], object] = {}
        self._path_busy: set[tuple[str, str]] = set()
        #: Names this reading tracks (loop targets, parameters) whose values it could not work out, and names
        #: past `_MAX_VALUES`: a path may not start with one (`_misplaced`).
        self.path_unknown: set[str] = set()
        self._collections: dict[str, ast.Dict | ast.List | ast.Tuple | ast.Set | None] = {}
        self._collection_values: dict[
            tuple[ast.AST, str, int | None, int], list[ast.expr] | None
        ] = {}
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
        #: What each name resolves to, once worked out, so many calls on one name stay linear.
        self._name_values: dict[str, list[tuple[str, bool]] | None] = {}
        self._name_hosts: dict[str, set[str] | None] = {}
        self._name_keys: dict[str, bool] = {}

    # ------------------------------------------------------------------ imports and sinks

    def _bind(
        self, name: str, value: ast.expr | None = None, path: ast.expr | _Pending | None = None
    ) -> None:
        """Record a binding of `name`; `path` is what the path reading binds instead of `value`, worked out
        once every binding is known (`_Pending`)."""
        self.bindings.setdefault(name, []).append(value)
        self.path_bindings.setdefault(name, []).append(path if path is not None else value)

    def _import(self, node: ast.Import) -> None:
        for a in node.names:
            top = a.name.split(".")[0]
            bound = a.asname or top
            module = a.name if a.asname else top
            self._bind(bound)
            if module in _DIRECT_ONLY:
                self.shutil_modules.add(bound)
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
            self._bind(a.asname or a.name)
            if (
                a.name in _ATTR_CALLERS
                or a.name in _ATTR_BY_NAME
                or a.name in _OPAQUE_BUILTINS
                or a.name in _CLASS_MAKERS
            ):
                raise _Unfollowed  # `from operator import attrgetter as ag`
            if a.name in _WRITERS and a.asname and a.asname != a.name:
                raise _Unfollowed  # `from hermes_tools import write_file as w`: the call is not seen as a write
            if module in _DIRECT_ONLY and a.name in _SHUTIL_OPS:
                if a.asname and a.asname != a.name:
                    raise _Unfollowed  # `from shutil import copy as c`
                self.shutil_funcs[a.name] = a.name
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
            if inspect.ismodule(obj) and obj.__name__ in _DIRECT_ONLY:
                raise _Unfollowed  # `from zipfile import shutil`
        self.objects[bound] = obj

    def _store(self, name: ast.Name) -> None:
        parent = self.parents.get(name)
        if isinstance(parent, ast.Assign) and any(t is name for t in parent.targets):
            self._bind(name.id, parent.value)
        elif isinstance(parent, ast.AnnAssign) and parent.target is name and parent.value:
            self._bind(name.id, parent.value)
        elif isinstance(name.ctx, ast.Store) and _loop_of(name, self.parents) is not None:
            self._bind(name.id, None, _Pending(name))  # a path drawn from a loop: `_loop_values`
        else:
            self._bind(name.id)  # a loop, `with`, unpacking, `+=` or walrus: not followed

    # ------------------------------------------------------------------ path bindings of loops and parameters

    def _resolve_path_bindings(self) -> None:
        """Work out the path bindings left pending by the scan (`_Pending`), now that every binding and every
        read of every name is known. One that cannot be worked out is None: not followed."""
        fn_values: dict[ast.AST, dict[str, list[ast.expr]] | None] = {}
        for name, binds in self.path_bindings.items():
            if not any(isinstance(b, _Pending) for b in binds):
                continue
            out: list[ast.expr | _Pending | None] = []
            for b in binds:
                if not isinstance(b, _Pending):
                    out.append(b)
                    continue
                if isinstance(b.node, ast.Name):
                    values = self._loop_values(b.node)
                else:
                    assert isinstance(b.node, ast.arg)
                    fn = self.parents.get(self.parents.get(b.node))  # type: ignore[arg-type]
                    if fn not in fn_values:
                        fn_values[fn] = self._call_values(fn)  # type: ignore[arg-type]
                    by_param = fn_values[fn]
                    values = None if by_param is None else by_param.get(b.node.arg)
                if values is None:
                    out.append(None)
                    self.path_unknown.add(name)
                else:
                    out.extend(values)
            self.path_bindings[name] = out
        for name, binds in self.path_bindings.items():
            if len(binds) > _MAX_VALUES:
                # too many to follow (`for v in L` written many times)
                self.path_bindings[name] = [None]
                self.path_unknown.add(name)

    def _loop_values(self, target: ast.Name) -> list[ast.expr] | None:
        """The values a loop target takes when the loop runs over a literal collection (written in place, or a
        name bound once to one and only read: `_literal_collection`): a list, tuple or set's items, a dict's keys
        (`for k in d`, `d.keys()`), values (`d.values()`) or both (`for k, v in d.items()`), and the matching
        item of each tuple in `for a, b in [(…), …]`. None for any other loop."""
        loop = _loop_of(target, self.parents)
        if loop is None:
            return None
        it, index, size = loop
        selector = "iter"
        if (
            isinstance(it, ast.Call)
            and isinstance(it.func, ast.Attribute)
            and it.func.attr in ("items", "keys", "values")
            and not it.args
            and not it.keywords
        ):
            selector, it = it.func.attr, it.func.value
        coll = self._literal_collection(it)
        if coll is None:
            return None
        key = (coll, selector, index, size)
        if key not in self._collection_values:  # worked out once however many loops run over it
            self._collection_values[key] = self._collection_items(coll, selector, index, size)
        return self._collection_values[key]

    def _collection_items(
        self,
        coll: ast.Dict | ast.List | ast.Tuple | ast.Set,
        selector: str,
        index: int | None,
        size: int,
    ) -> list[ast.expr] | None:
        if not all(_frozen(e) for e in _items_of(coll)):
            return None  # an item that is itself a list, dict or set can change after it is written
        items: list[ast.expr]
        if isinstance(coll, ast.Dict):
            if any(k is None for k in coll.keys):
                return None  # `{**other, …}`
            keys = [k for k in coll.keys if k is not None]
            if selector == "items":
                if index is None or size != 2:
                    return None
                return self._distinct(keys if index == 0 else coll.values)
            items = coll.values if selector == "values" else keys
        else:
            if selector != "iter":
                return None
            items = coll.elts
        if index is None:
            return self._distinct(items)
        out: list[ast.expr] = []
        for item in items:
            if not isinstance(item, (ast.Tuple, ast.List)) or len(item.elts) != size:
                return None
            out.append(item.elts[index])
        return self._distinct(out)

    def _literal_collection(
        self, expr: ast.expr
    ) -> ast.Dict | ast.List | ast.Tuple | ast.Set | None:
        """`expr` as a literal collection whose items are known: written in place, or a name bound once (by a
        plain assignment to it alone) to one, that the program only reads (`_reads_only`)."""
        if isinstance(expr, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            return expr
        if not isinstance(expr, ast.Name):
            return None
        if expr.id not in self._collections:
            self._collections[expr.id] = self._named_collection(expr.id)
        return self._collections[expr.id]

    def _named_collection(self, name: str) -> ast.Dict | ast.List | ast.Tuple | ast.Set | None:
        binds = self.bindings.get(name) or []
        if len(binds) != 1 or not isinstance(binds[0], (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            return None
        holder = self.parents.get(binds[0])
        if not (
            (isinstance(holder, ast.Assign) and len(holder.targets) == 1)
            or isinstance(holder, ast.AnnAssign)
        ):
            return None  # `a = b = […]`: changed through the other name
        if not all(self._reads_only(n) for n in self.loads.get(name) or []):
            return None
        return binds[0]

    def _reads_only(self, node: ast.Name) -> bool:
        """This read of a collection cannot change it: it is iterated, indexed, compared, formatted, read by a
        method that changes nothing (`_READ_ONLY_METHODS`) or passed to such a builtin (`_READ_ONLY_BUILTINS`).
        Anything else (`d[k] = v`, `l.append(v)`, `m = l`, `f(l)`) may change it."""
        parent = self.parents.get(node)
        if isinstance(parent, (ast.For, ast.AsyncFor, ast.comprehension)):
            return parent.iter is node
        if isinstance(parent, ast.Attribute):
            call = self.parents.get(parent)
            return (
                parent.value is node
                and parent.attr in _READ_ONLY_METHODS
                and isinstance(call, ast.Call)
                and call.func is parent
            )
        if isinstance(parent, ast.Subscript):
            return parent.value is node and isinstance(parent.ctx, ast.Load)
        if isinstance(parent, (ast.Compare, ast.FormattedValue)):
            return True
        if isinstance(parent, ast.Call):
            return (
                any(a is node for a in parent.args)
                and isinstance(parent.func, ast.Name)
                and parent.func.id in _READ_ONLY_BUILTINS
                and parent.func.id not in self.bindings
            )
        return False

    def _call_values(self, fn: ast.AST) -> dict[str, list[ast.expr]] | None:
        """What each parameter of `fn` is passed, over every call of it, when the program only ever calls it by
        its name, directly: a plain function (no method, decorator, `*args` or `**kwargs`), its name bound once,
        each call with plain positional and keyword arguments. A parameter a call leaves out takes its default.
        An argument that is the parameter's own name adds nothing (that name's other bindings hold its values).
        None when the function is used any other way: passed, stored, returned or called through anything."""
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.decorator_list:
            return None
        if isinstance(self.parents.get(fn), ast.ClassDef):
            return None
        a = fn.args
        if a.vararg is not None or a.kwarg is not None:
            return None
        if len(self.bindings.get(fn.name) or []) != 1:
            return None
        positional = [p.arg for p in (*a.posonlyargs, *a.args)]
        params = set(positional) | {p.arg for p in a.kwonlyargs}
        defaults: dict[str, ast.expr] = dict(
            zip(positional[len(positional) - len(a.defaults) :], a.defaults, strict=True)
        )
        defaults.update(
            {p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults, strict=True) if d is not None}
        )
        out: dict[str, list[ast.expr]] = {p: [] for p in params}
        passed = dict.fromkeys(params, 0)  # how many calls pass each parameter
        calls = self.loads.get(fn.name) or []
        if not calls:
            return None  # never called here: what a later program may pass is not seen
        for ref in calls:
            call = self.parents.get(ref)
            if not (isinstance(call, ast.Call) and call.func is ref):
                return None  # the function escapes: what it is called with is not seen
            if any(isinstance(x, ast.Starred) for x in call.args) or len(call.args) > len(
                positional
            ):
                return None
            given = dict(zip(positional, call.args, strict=False))
            for kw in call.keywords:
                if kw.arg is None or kw.arg not in params or kw.arg in given:
                    return None
                given[kw.arg] = kw.value
            for p, value in given.items():
                passed[p] += 1
                if not (isinstance(value, ast.Name) and value.id == p):
                    out[p].append(value)
        for p, n in passed.items():
            if n < len(calls) and p in defaults:
                out[p].append(defaults[p])  # a call leaves it out
        return {p: v for p, v in ((p, self._distinct(v)) for p, v in out.items()) if v is not None}

    @staticmethod
    def _distinct(values: list[ast.expr]) -> list[ast.expr] | None:
        """`values` with repeated strings dropped; None past `_MAX_VALUES`, or for an unpacked item."""
        out: list[ast.expr] = []
        strings: set[str] = set()
        for v in values:
            if isinstance(v, ast.Starred):
                return None
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                if v.value in strings:
                    continue
                strings.add(v.value)
            out.append(v)
            if len(out) > _MAX_VALUES:
                return None
        return out

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
                if node.id in _CLASS_MAKERS:
                    raise _Unfollowed
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
                else:
                    self.loads.setdefault(node.id, []).append(node)
            elif isinstance(node, ast.Attribute):
                if (
                    node.attr.startswith("__")
                    and node.attr.endswith("__")
                    and node.attr not in _SAFE_DUNDERS
                ):
                    raise _Unfollowed
                if node.attr.startswith(_FRAME_PREFIXES) or node.attr in _FRAME_ATTRS:
                    raise _Unfollowed
                if node.attr in _ATTR_CALLERS or node.attr in _CLASS_MAKERS:
                    raise _Unfollowed
            elif isinstance(node, ast.arg):
                # A parameter of a function this reading may follow into: bound to what each call passes.
                self._bind(node.arg, None, _Pending(node))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if isinstance(node, ast.ClassDef) or (
                    node.name.startswith("__") and node.name.endswith("__")
                ):
                    # A class's methods run without their names being read (`K(p)` runs `__init__`): what
                    # their parameters take is not seen.
                    raise _Unfollowed
                self._bind(node.name)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "type"
                and len(node.args) == 3
            ):
                raise _Unfollowed  # `type(name, bases, attrs)` builds a class
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for n in node.names:
                    self._bind(n)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self._bind(node.name)
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                self._bind(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                self._bind(node.rest)
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
            self._bind(key)
        for call, module in imported:
            self._dynamic_import(call, module)
        for name in [*self.shutil_modules, *self.shutil_funcs]:
            if len(self.bindings.get(name) or []) != 1:
                raise _Unfollowed  # `import shutil` and another binding of the name: which one a call reaches is not seen
        self._resolve_path_bindings()
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
        op = self._shutil_op(node.func)
        if op is not None:
            self._check_shutil(node, op)
            return
        if (
            name == "copy"
            and isinstance(node.func, ast.Attribute)
            and (node.args or node.keywords)
            and not (
                isinstance(node.func.value, ast.Name)
                and inspect.ismodule(self.objects.get(node.func.value.id))
            )
        ):
            raise _Unfollowed  # `Path(p).copy(target)` copies a file to its argument
        self._check_write(node, name)

    def _shutil_op(self, func: ast.expr) -> str | None:
        """The `shutil` function a call's `func` names (`shutil.copy`, or `copy` imported from `shutil`), when it
        is one `_check_shutil` follows."""
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in self.shutil_modules
            and func.attr in _SHUTIL_OPS
        ):
            return func.attr
        if isinstance(func, ast.Name):
            return self.shutil_funcs.get(func.id)
        return None

    def _check_shutil(self, node: ast.Call, op: str) -> None:
        """A `shutil` file copy or move (`copy`, `copy2`, `copyfile`, `move`) is followed when both paths are
        written out in full (`_exact_paths`: no part computed) and every value they can take passes: the source
        is a data file (`_DATA_EXTENSIONS`) and the destination is one too, or (but for `copyfile`) a folder written
        as a string with a trailing `/`, where the file keeps its name; each passes `_allowed_path` and has no `..`,
        and the destination is in the user's home or `/tmp` and nowhere programs are run or imported from
        (`_copy_destination`). Folder copies and removals (`copytree`, `rmtree`) are not followed: what a folder
        holds is not known."""
        if any(isinstance(a, ast.Starred) for a in node.args) or any(
            k.arg is None for k in node.keywords
        ):
            raise _Unfollowed
        params = _SHUTIL_OPS[op]
        if len(node.args) > len(params):
            raise _Unfollowed
        given: dict[str, ast.expr] = dict(zip(params, node.args, strict=False))
        for k in node.keywords:
            assert k.arg is not None
            if k.arg in given or (k.arg not in params and k.arg not in _SHUTIL_KEYWORDS):
                raise _Unfollowed  # `copy_function=`
            given[k.arg] = k.value
        src, dst = given.get("src"), given.get("dst")
        if src is None or dst is None:
            raise _Unfollowed
        sources, targets = self._exact_paths(src), self._exact_paths(dst)
        if not sources or not targets:
            raise _Unfollowed
        for path in sources:
            if not (_plain_data_file(path) and _allowed_path(path, path)):
                raise _Unfollowed
        for path in targets:
            # Only a string keeps a trailing `/`: `Path("x.pth/")` is the file `x.pth` (`_as_pathlib`).
            into_folder = op != "copyfile" and path.endswith("/")
            if not (into_folder or _plain_data_file(path)) or not _allowed_path(path, path):
                raise _Unfollowed
            if not _copy_destination(path):
                raise _Unfollowed

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
        if path is None or not self._data_path(path):
            raise _Unfollowed
        if self.tolerant:
            return  # a data file changes nothing later programs reach in the interpreter
        if not self._write_allowed(path):
            raise _Unfollowed  # a dot-directory, or a data file a tool reads settings or commands from

    def _write_allowed(self, path: ast.expr) -> bool:
        """A data file outside dot-directories whose name is not on the deny list (`_DENIED_NAMES`). A path
        written out in full (`_exact_paths`) is judged whole, and may not climb with `..`. Parts of a path the
        program computes are unknown: the known start and end must pass, a name the program completes must not be
        able to end as a denied one, and no string anywhere in the path (a middle `join` argument, a `/` operand)
        may name a dot-directory. A path into a folder data files may go in (`_DATA_DOT_DIRS`) must be written out
        in full: a computed part could climb back out of it."""
        bad, into_data_dir = self._path_strings(path)
        if bad:
            return False
        exact = self._exact_paths(path)
        if exact is not None:
            return all(".." not in t.split("/") and _allowed_path(t, t) for t in exact)
        if into_data_dir or self._misplaced(path, True):
            return False
        prefixes = self._path_prefixes(path)
        suffixes = self._path_suffixes(path)
        if not suffixes:
            return False
        return all(_allowed_path(p, None) for p in prefixes or [""]) and all(
            _allowed_path(None, t) for t in suffixes
        )

    def _per_name(self, kind: str, name: str, compute: Callable[[], _T], cycle: _T) -> _T:
        """What `compute` works out for the name `name`, once per program: many writes through one name stay
        linear. A name that depends on itself takes `cycle`, which never lets more through."""
        key = (kind, name)
        if key in self._path_memo:
            return self._path_memo[key]  # type: ignore[no-any-return]
        if key in self._path_busy:
            return cycle
        self._path_busy.add(key)
        try:
            result = compute()
        finally:
            self._path_busy.discard(key)
        self._path_memo[key] = result
        return result

    def _misplaced(self, expr: ast.expr, start: bool) -> bool:
        """A name this reading tracks but could not work out (`path_unknown`) sits where it can set where the path
        starts: first, or as any part of a `join` or `/` that comes first (an absolute part starts the path over).
        Appended to a known start (`D + k + "_row.txt"`) it is a computed name, judged by the name rules."""
        if isinstance(expr, ast.Name):
            if expr.id in self.path_unknown:
                return start
            return self._per_name(
                "misplaced" if start else "appended",
                expr.id,
                lambda: any(
                    self._misplaced(b, start)
                    for b in self.path_bindings.get(expr.id) or []
                    if isinstance(b, ast.expr)
                ),
                True,
            )
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self._misplaced(expr.left, start) or self._misplaced(expr.right, False)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            return self._misplaced(expr.left, start) or self._misplaced(expr.right, start)
        if isinstance(expr, ast.JoinedStr):
            return any(
                self._misplaced(
                    v.value if isinstance(v, ast.FormattedValue) else v, start and i == 0
                )
                for i, v in enumerate(expr.values)
            )
        if isinstance(expr, ast.Call) and _call_name(expr.func) in (
            "Path",
            "PurePath",
            "join",
            "expanduser",
            "abspath",
            "normpath",
        ):
            return any(self._misplaced(a, start) for a in expr.args)
        if not start:
            return False
        return any(self._misplaced(n, True) for n in ast.walk(expr) if isinstance(n, ast.Name))

    def _binds_of(self, name: str) -> list[ast.expr] | None:
        """The path bindings of `name`, or None when one of them is not followed (or there are none)."""
        binds = self.path_bindings.get(name) or []
        if not binds or not all(isinstance(b, ast.expr) for b in binds):
            return None
        return binds  # type: ignore[return-value]

    def _path_strings(self, expr: ast.expr) -> tuple[bool, bool]:
        """Over every string in `expr` and in what the names in it are set to: (some part starts with a dot,
        other than `.`, `..` and the folders data files may go in; some string names one of those folders)."""
        parents = {child: node for node in ast.walk(expr) for child in ast.iter_child_nodes(node)}
        bad = into = False
        for node in ast.walk(expr):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = _DATA_DOT_DIRS.sub("/scratch/", node.value)
                into = into or text != node.value
                parts = text.split("/")
                parent = parents.get(node)
                appended = (
                    isinstance(parent, ast.BinOp)
                    and isinstance(parent.op, ast.Add)
                    and parent.right is node
                ) or isinstance(parent, ast.JoinedStr)
                if appended and len(parts) == 1 and re.fullmatch(r"\.[A-Za-z0-9]{1,8}", parts[0]):
                    continue  # an extension added to a computed name (`k + ".json"`): the name rules judge it
                bad = bad or any(p.startswith(".") and p not in (".", "..") for p in parts)
            elif isinstance(node, ast.Name):
                got = self._per_name(
                    "strings", node.id, lambda n=node.id: self._name_strings(n), (True, True)
                )
                bad, into = bad or got[0], into or got[1]
            if bad:
                return True, into
        return bad, into

    def _name_strings(self, name: str) -> tuple[bool, bool]:
        bad = into = False
        for b in self.path_bindings.get(name) or []:
            if isinstance(b, ast.expr):
                got = self._path_strings(b)
                bad, into = bad or got[0], into or got[1]
        return bad, into

    def _exact_paths(self, expr: ast.expr) -> list[str] | None:
        """Every value the path `expr` can take, when all of it is written out: strings, names bound only to such
        paths (a loop over a literal collection and a helper's parameter included), `+`, `/`, f-strings with
        nothing computed, and `os.path.join`, `os.path.expanduser` and `Path` of such paths. None when any part
        is computed (`os.pardir`, `.parent`, `dirname`, `chr(46) * 2`, `input()`), or past `_MAX_VALUES`."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value]
        if isinstance(expr, ast.JoinedStr):
            if all(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in expr.values):
                return ["".join(v.value for v in expr.values)]  # type: ignore[attr-defined]
            return None
        if isinstance(expr, ast.Name):
            return self._per_name("exact", expr.id, lambda: self._name_exact(expr.id), None)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            left = self._exact_paths(expr.left)
            right = None if left is None else self._exact_paths(expr.right)
            if left is None or right is None or len(left) * len(right) > _MAX_VALUES:
                return None
            if isinstance(expr.op, ast.Add):
                return [a + b for a in left for b in right]
            return [_as_pathlib(posixpath.join(a, b)) for a in left for b in right]
        if (
            isinstance(expr, ast.Call)
            and expr.args
            and not expr.keywords
            and not any(isinstance(a, ast.Starred) for a in expr.args)
        ):
            fn = self._resolve(expr.func)
            if fn is None or not any(fn is f for f in _EXACT_PATH_CALLS):
                return None
            if fn is posixpath.expanduser and len(expr.args) != 1:
                return None
            out: list[str] = [""]
            for arg in expr.args:
                got = self._exact_paths(arg)
                if got is None or len(out) * len(got) > _MAX_VALUES:
                    return None
                out = [posixpath.join(a, b) if a else b for a in out for b in got]
            if fn is not posixpath.join and fn is not posixpath.expanduser:
                out = [_as_pathlib(t) for t in out]  # `Path("x.pth/")` is the file `x.pth`
            return out
        return None

    def _name_exact(self, name: str) -> list[str] | None:
        binds = self._binds_of(name)
        if binds is None:
            return None
        out: list[str] = []
        for b in binds:
            got = self._exact_paths(b)
            if got is None:
                return None
            out.extend(t for t in got if t not in out)
            if len(out) > _MAX_VALUES:
                return None
        return out

    def _resolve(self, func: ast.expr) -> object | None:
        """The object a call's `func` names through the program's imports (`os.path.join`, `Path`), or None."""
        if isinstance(func, ast.Name):
            if len(self.bindings.get(func.id) or []) != 1:
                return None
            return self.objects.get(func.id)
        if isinstance(func, ast.Attribute):
            base = self._resolve(func.value)
            if base is None or not inspect.ismodule(base):
                return None
            return getattr(base, func.attr, None)
        return None

    def _path_suffixes(self, expr: ast.expr) -> list[str] | None:
        """The known end of each value the path `expr` can take."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value]
        if isinstance(expr, ast.JoinedStr):
            last = expr.values[-1] if expr.values else None
            if isinstance(last, ast.Constant) and isinstance(last.value, str):
                return [last.value]
            return None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            right = self._path_suffixes(expr.right)
            if right is None:
                return None
            return ["/" + r for r in right] if isinstance(expr.op, ast.Div) else right
        if isinstance(expr, ast.Call):
            fn = _call_name(expr.func)
            if (
                fn in ("Path", "PurePath", "join", "expanduser", "abspath", "normpath")
                and expr.args
            ):
                last = self._path_suffixes(expr.args[-1])
                if last is None or fn != "join" or len(expr.args) < 2:
                    return last
                return ["/" + t for t in last]
            return None
        if isinstance(expr, ast.Name):
            return self._per_name(
                "suffixes", expr.id, lambda: self._name_ends(expr.id, self._path_suffixes), None
            )
        return None

    def _path_prefixes(self, expr: ast.expr) -> list[str] | None:
        """The known start of each value the path `expr` can take."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value]
        if isinstance(expr, ast.JoinedStr):
            first = expr.values[0] if expr.values else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return [first.value]
            return None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            left = self._path_prefixes(expr.left)
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
                first = self._path_prefixes(expr.args[0])
                if first is None or fn != "join" or len(expr.args) < 2:
                    return first
                return [p.rstrip("/") + "/" for p in first]
            return None
        if isinstance(expr, ast.Name):
            return self._per_name(
                "prefixes", expr.id, lambda: self._name_ends(expr.id, self._path_prefixes), None
            )
        return None

    def _name_ends(
        self, name: str, ends: Callable[[ast.expr], list[str] | None]
    ) -> list[str] | None:
        binds = self._binds_of(name)
        if binds is None:
            return None
        out: list[str] = []
        seen: set[str] = set()
        for b in binds:
            got = ends(b)
            if got is None:
                return None
            for t in got:
                if t not in seen:
                    seen.add(t)
                    out.append(t)
            if len(out) > _MAX_VALUES:
                raise _Unfollowed  # too many to follow; doubling at every name would not end
        return out or None

    def _outside_import_path(self, path: ast.expr) -> bool:
        """The path's known start is under /tmp or the code tool's scratch space, with no `..` and no `%`
        or `{` before the first computed part."""
        prefixes = self._path_prefixes(path)
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

    def _data_path(self, expr: ast.expr) -> bool:
        """`expr` is a path that ends in a data extension, however the rest of it is computed."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value.lower().endswith(_DATA_EXTENSIONS)
        if isinstance(expr, ast.JoinedStr):
            last = expr.values[-1] if expr.values else None
            return last is not None and self._data_path(last)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            return self._data_path(expr.right)
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
                return self._data_path(expr.args[-1])
            return False
        if isinstance(expr, ast.Name):
            return self._per_name("data", expr.id, lambda: self._name_data(expr.id), False)
        return False

    def _name_data(self, name: str) -> bool:
        binds = self._binds_of(name)
        return binds is not None and all(self._data_path(b) for b in binds)

    def _check_name(self, node: ast.Name) -> None:
        parent = self.parents.get(node)
        if node.id in _WRITERS and not (isinstance(parent, ast.Call) and parent.func is node):
            raise _Unfollowed  # a writer passed around or bound to another name: its writes are not seen
        if node.id in self.shutil_funcs and not (
            isinstance(parent, ast.Call) and parent.func is node
        ):
            raise _Unfollowed  # `map(copy, …)`: the copy is not seen
        if node.id not in self.bindings and node.id not in _BUILTINS and not self.tolerant:
            # A name the program never binds: a function the host provides (a tool, called or passed
            # around), or one this reading cannot see.
            raise _Unfollowed
        if node.id in _ATTR_BY_NAME | _ATTR_CALLERS and not (
            isinstance(parent, ast.Call) and parent.func is node
        ):
            raise _Unfollowed  # `reduce(getattr, …)`
        if node.id in self.objects:
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
            if inspect.ismodule(obj) and obj.__name__ in _DIRECT_ONLY:
                raise _Unfollowed  # `zipfile.shutil.copy(…)`: not seen as a `shutil` call
            child = parent

    def _check_attribute(self, node: ast.Attribute) -> None:
        if node.attr in _WRITERS and isinstance(node.ctx, ast.Load):
            parent = self.parents.get(node)
            if not (isinstance(parent, ast.Call) and parent.func is node):
                raise _Unfollowed  # `wt = Path(p).write_text`, `partial(gzip.open, …)`
        if node.attr in _FILE_MOVES or self._shutil_op(node) is not None:
            parent = self.parents.get(node)
            direct = isinstance(parent, ast.Call) and parent.func is node
            if not (direct and self._shutil_op(node) is not None):
                raise _Unfollowed  # `Path.rename`-like moves, and `shutil` calls not made directly
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
            found = self._request_hosts(url, frozenset())
            if found is None:
                if name == "get" and self._plain_key(url):
                    continue  # `data.get("key")`, `os.environ.get(KEY)`: a lookup, not a request
                return None
            hosts |= found
            seen = True
        return frozenset(hosts) if seen else None

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
            if expr.id not in self._name_keys:
                self._name_keys[expr.id] = _plain_keys(self._values(expr, frozenset()))
            return self._name_keys[expr.id]
        return _plain_keys(self._values(expr, frozenset()))

    def _request_hosts(self, expr: ast.expr, seen: frozenset[str]) -> set[str] | None:
        """The hosts a request URL argument (or a `Request` it names) is aimed at, or None."""
        if isinstance(expr, ast.Call) and _call_name(expr.func) in ("Request", "build_request"):
            inner = _url_arg(expr)
            return None if inner is None else self._request_hosts(inner, seen)
        if isinstance(expr, ast.Name) and expr.id not in seen:
            if expr.id not in self._name_hosts:
                binds = self.bindings.get(expr.id) or []
                if binds and all(isinstance(b, ast.Call) for b in binds):
                    hosts = self._bound_hosts(expr.id, binds, seen)
                else:
                    hosts = _hosts_of(self._values(expr, seen))
                self._name_hosts[expr.id] = hosts
            return self._name_hosts[expr.id]
        return _hosts_of(self._values(expr, seen))

    def _bound_hosts(
        self, name: str, binds: list[ast.expr | None], seen: frozenset[str]
    ) -> set[str] | None:
        out: set[str] = set()
        for b in binds:
            assert b is not None
            got = self._request_hosts(b, seen | {name})
            if got is None:
                return None
            out |= got
        return out

    def _bound_values(
        self, name: str, binds: list[ast.expr | None], seen: frozenset[str]
    ) -> list[tuple[str, bool]] | None:
        out: list[tuple[str, bool]] = []
        for b in binds:
            if b is None:
                return None
            got = self._values(b, seen | {name})
            if got is None:
                return None
            out.extend(got)
            if len(out) > _MAX_VALUES:
                return None  # too many to follow: every host stays a possible destination
        return out

    def _values(self, expr: ast.expr, seen: frozenset[str]) -> list[tuple[str, bool]] | None:
        """The string values `expr` can take, each as (text, exact): `exact` False means only a prefix of
        the value is known. None when nothing is known."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [(expr.value, True)]
        if isinstance(expr, ast.Name):
            binds = self.bindings.get(expr.id)
            if not binds or expr.id in seen:
                return None
            # A name that depends on itself (`u = u + "/x"`) resolves to None however it is reached.
            if expr.id not in self._name_values:
                self._name_values[expr.id] = self._bound_values(expr.id, binds, seen)
            return self._name_values[expr.id]
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
