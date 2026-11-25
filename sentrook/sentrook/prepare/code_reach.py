"""What Python source run by a code tool (Hermes `execute_code`) can reach on the network.

A URL or a quoted shell command inside a string literal (`"curl -X POST https://api.x.io/v1"`) is text the
code holds. It names a destination only when the code reaches a network sink that could act on it: an
HTTP library, a socket, a subprocess or shell, a host web tool, or anything this reading does not follow
(a module outside the known-local list, a dynamic import, `exec`/`eval`, an attribute walk through
dunders or stack frames, a name the code never binds). Code with no such sink only mentions the hosts it
writes. Writing a file counts as a sink unless the file is plainly data (`.json`, `.txt`, …): a quoted
command written into `~/.bashrc` or a `.pth` file runs later.

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
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

__all__ = ["CodeReach", "python_reach"]


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
        "contextlib",
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
        "io",
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
        "tempfile",
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
#: Calls that write a file at their path argument.
_WRITE_CALLS = frozenset({"write_text", "write_bytes", "write_file", "patch"})
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


class _Unfollowed(Exception):
    pass


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
    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
        #: Every value a plain name is bound to; None marks a binding that is not a simple assignment.
        self.bindings: dict[str, list[ast.expr | None]] = {}
        #: Names bound to a restricted module, with the attributes allowed through them.
        self.restricted: dict[str, set[str]] = {}
        #: Names bound to a followed client module, and functions imported from one (alias → name).
        self.http_modules: set[str] = set()
        self.http_funcs: dict[str, str] = {}
        #: Names bound by an import of a local or restricted module, with the object each names.
        self.objects: dict[str, object] = {}
        self.http = False
        #: What each name resolves to, once worked out, so many calls on one name stay linear.
        self._name_values: dict[str, list[tuple[str, bool]] | None] = {}
        self._name_hosts: dict[str, set[str] | None] = {}
        self._name_keys: dict[str, bool] = {}

    # ------------------------------------------------------------------ imports and sinks

    def _bind(self, name: str, value: ast.expr | None = None) -> None:
        self.bindings.setdefault(name, []).append(value)

    def _import(self, node: ast.Import) -> None:
        for a in node.names:
            top = a.name.split(".")[0]
            bound = a.asname or top
            module = a.name if a.asname else top
            self._bind(bound)
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
            if a.name in _ATTR_CALLERS or a.name in _ATTR_BY_NAME or a.name in _OPAQUE_BUILTINS:
                raise _Unfollowed  # `from operator import attrgetter as ag`
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
                if module == "urllib":
                    self.http_modules.add(bound)
                elif a.name in _REQUEST_CALLS:
                    self.http_funcs[bound] = a.name
            return
        if module in _RESTRICTED:
            if any(n not in _RESTRICTED[module] for n in names):
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
            self._bind(name.id, parent.value)
        elif isinstance(parent, ast.AnnAssign) and parent.target is name and parent.value:
            self._bind(name.id, parent.value)
        else:
            self._bind(name.id)  # a loop, `with`, unpacking, `+=` or walrus: not followed

    def scan(self) -> None:
        """Collect bindings and imports; raise `_Unfollowed` at anything this reading does not follow."""
        globals_keys: set[str] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                self._import(node)
            elif isinstance(node, ast.ImportFrom):
                self._import_from(node)
            elif isinstance(node, ast.Name):
                if node.id == "globals" and (key := self._globals_key(node)) is not None:
                    globals_keys.add(key)
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
                self._bind(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._bind(node.name)
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
        if not (isinstance(sub, ast.Subscript) and sub.value is call):
            return None
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
            if attr.value.startswith("__") or attr.value in _REQUEST_CALLS:
                raise _Unfollowed
            obj = node.args[0]
            if isinstance(obj, ast.Name) and obj.id in self.restricted:
                raise _Unfollowed
        self._check_write(node, name)

    def _check_write(self, node: ast.Call, name: str | None) -> None:
        """A call that writes a file is followed only when the file is plainly data (`_DATA_EXTENSIONS`)."""
        path: ast.expr | None = None
        if name == "open":
            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            module_open = receiver is None or (
                isinstance(receiver, ast.Name) and inspect.ismodule(self.objects.get(receiver.id))
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
        if path is None or not self._data_path(path, frozenset()):
            raise _Unfollowed

    def _data_path(self, expr: ast.expr, seen: frozenset[str]) -> bool:
        """`expr` is a path that ends in a data extension, however the rest of it is computed."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value.lower().endswith(_DATA_EXTENSIONS)
        if isinstance(expr, ast.JoinedStr):
            last = expr.values[-1] if expr.values else None
            return last is not None and self._data_path(last, seen)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            return self._data_path(expr.right, seen)
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
        if node.id not in self.bindings and node.id not in _BUILTINS:
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

    def _check_chain(self, node: ast.Name) -> None:
        """Walk the attributes taken from an imported module or name, on the real objects: none may be
        private or a module outside the local list (`shutil.os.system`, `os.path.os`, `tempfile._os`)."""
        obj = self.objects[node.id]
        child: ast.AST = node
        for _ in range(_CHAIN_DEPTH):
            parent = self.parents.get(child)
            allowed = _allowed_attrs(obj)
            if not (isinstance(parent, ast.Attribute) and parent.value is child):
                if allowed is not None:
                    raise _Unfollowed  # a restricted module used as a value (`f(shutil.os)`)
                return
            if parent.attr.startswith("_"):
                raise _Unfollowed
            if allowed is not None and parent.attr not in allowed:
                if child is node and node.id in self.restricted:
                    allowed = self.restricted[node.id]  # `import urllib.request` adds `request`
                if parent.attr not in allowed:
                    raise _Unfollowed
            if not hasattr(obj, parent.attr):
                return
            obj = getattr(obj, parent.attr)
            _check_module(obj)
            child = parent

    def _check_attribute(self, node: ast.Attribute) -> None:
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
        self.module_bound: set[str] = set()
        #: Checking a function body, which runs only when called, after the module has run.
        self.in_function = False

    def run(self, tree: ast.Module) -> None:
        self.module_bound = self.block(tree.body, set(), frozenset())
        self.in_function = True
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
        if self.in_function and name in self.module_bound:
            return True  # read in a function, which runs after the module binds it
        return (name in _BUILTINS or name in _SAFE_DUNDER_NAMES) and name not in self.stored

    def expr(self, node: ast.AST, bound: set[str], enclosing: frozenset[str]) -> None:
        stack = [node]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if not self.ok(n.id, bound, enclosing):
                    raise _Unfollowed
            elif isinstance(n, ast.Lambda):
                stack.extend([*n.args.defaults, *(d for d in n.args.kw_defaults if d)])
                self.deferred.append((n, enclosing | frozenset(bound)))
                continue
            elif isinstance(n, _COMPREHENSIONS):
                inner = set(bound)
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
                stack.append(n.value)
                bound.add(n.target.id)
                continue
            stack.extend(ast.iter_child_nodes(n))

    def block(self, stmts: list[ast.stmt], bound: set[str], enclosing: frozenset[str]) -> set[str]:
        """Check `stmts` in order; return the names definitely bound after them."""
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = stmt.args
                for d in [*stmt.decorator_list, *a.defaults, *(d for d in a.kw_defaults if d)]:
                    self.expr(d, bound, enclosing)
                bound.add(stmt.name)  # bound before the body can run, so it may call itself
                self.deferred.append((stmt, enclosing | frozenset(bound)))
            elif isinstance(stmt, ast.ClassDef):
                for d in [*stmt.decorator_list, *stmt.bases, *(k.value for k in stmt.keywords)]:
                    self.expr(d, bound, enclosing)
                self.block(stmt.body, set(bound), enclosing)
                bound.add(stmt.name)
            elif isinstance(stmt, ast.If):
                self.expr(stmt.test, bound, enclosing)
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
                bound |= self.block(stmt.body, set(bound), enclosing)
            elif isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
                done = self.block(stmt.body + stmt.orelse, set(bound), enclosing)
                for h in stmt.handlers:
                    if h.type is not None:
                        self.expr(h.type, bound, enclosing)
                    names = {h.name} if h.name else set()
                    done &= self.block(h.body, bound | names, enclosing)
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
            else:
                self.expr(stmt, bound, enclosing)
                bound |= _stmt_binds(stmt)
        return bound


@lru_cache(maxsize=256)
def python_reach(source: str) -> CodeReach | None:
    """What `source` (Python) can reach; None when it does not parse, so callers keep reading it as text."""
    try:
        tree = ast.parse(source)
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
