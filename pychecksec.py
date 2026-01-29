import os,ast,sys
import importlib.util
import importlib.machinery


if len(sys.argv) < 2:
    print("Error: you must specify a target Python file.")
    print(f"Usage: {sys.argv[0]} /path/to/target.py")
    quit()

path = sys.argv[1]

if not os.path.exists(path):
    print(f"Error: target does not exist: {path}")
    quit()

if os.path.isdir(path):
    print(f"Error: target is a directory, not a file: {path}")
    quit()

if not os.access(path, os.R_OK):
    print(f"Error: target is not readable: {path}")
    quit()


RESET = "\033[0m"
BOLD  = "\033[1m"
# Save original state
_ORIG_CWD = os.getcwd()
_ORIG_SYS_PATH = sys.path.copy()

# Emulate target script import environment
_target_dir = os.path.dirname(os.path.abspath(path))
os.chdir(_target_dir)

# Ensure target directory is highest-priority import location (if "" in sys.path)
if sys.path and sys.path[0] != _target_dir:
    sys.path.insert(0, _target_dir)


# Helper soup
def exists(p: str) -> bool:
    return os.path.exists(p)
def is_writable(p: str) -> bool:
    return os.access(p, os.W_OK)
def is_readable(p: str) -> bool:
    return os.access(p, os.R_OK)
def is_parent_writable(path: str) -> bool:
    parent = os.path.dirname(os.path.abspath(path))
    return os.access(parent, os.W_OK)
def extractimports(p):
    with open(p, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=p)

    imports = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.name] = None

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports[node.module] = None

    return list(imports)
def resolve_import_paths(imports: list[str]) -> list[str]:
    resolved = []

    for name in imports:
        top = name.split(".")[0]  # resolve at top-level package
        spec = importlib.util.find_spec(top)

        if spec is None:
            continue

        # Built-in or frozen modules
        if spec.origin in ("built-in", "frozen", None):
            resolved.append(f"{top}:{spec.origin}")
            continue

        # Packages
        if spec.submodule_search_locations:
            pkg_path = os.path.abspath(spec.submodule_search_locations[0])
            resolved.append(f"{top}:{pkg_path}")
            continue

        # Single-file modules
        resolved.append(f"{top}:{os.path.abspath(spec.origin)}")

    return resolved
def mark_writability(resolved: list[str]) -> list[str]:
    out = []

    for entry in resolved:
        name, path = entry.split(":", 1)

        if path in ("built-in", "frozen", None):
            out.append(f"{name}:{path}:notwritable")
            continue

        # Check actual filesystem writability
        writable = os.access(path, os.W_OK)

        out.append(
            f"{name}:{path}:{'writable' if writable else 'notwritable'}"
        )

    return out
def report_writable_imports(entries: list[str]) -> None:
    for entry in entries:
        module, path, status = entry.rsplit(":", 2)

        if status == "writable":
            printwhite(f"[+] - {path} from module {module} is writable")
def report_writable_syspath(entries: list[str]) -> None:
    for entry in entries:
        priority, path, status = entry.rsplit(":", 2)

        if status == "writable":
            printwhite(f"[+] - {path} is writable and is number {priority} to be imported from")
def report_writable_pycache(entries: list[str]) -> None:
    for entry in entries:
        package, path, status = entry.rsplit(":", 2)

        if status == "writable":
            printwhite(f"[+] - pycache directory {path} is writable, from package : {package}")
def report_import_shadowing(findings: list[str]) -> None:
    for f in findings:
        _, mod, idx, where, why = f.split(":", 4)

        if why == "already-exists":
            printwhite(f"[+] - import '{mod}' is ALREADY shadowed by {where} (sys.path index {idx})")

        elif why == "plantable":
            printwhite(f"[+] - import '{mod}' can be shadowed in {where} (sys.path index {idx}) by placing either {mod}.py OR {mod}/__init__.py")

def normalized_sys_path() -> list[str]:
    out = []
    cwd = os.getcwd()

    for idx, p in enumerate(sys.path):
        real = os.path.abspath(cwd) if p == "" else os.path.abspath(p)
        out.append(f"{idx}:{real}")

    return out

def collect_pycache_dirs(imports: list[str]) -> list[str]:
    out = []

    for name in imports:
        top = name.split(".")[0]
        spec = importlib.util.find_spec(top)

        if not spec or spec.origin in ("built-in", "frozen", None):
            continue

        # Only .py-backed modules/packages
        if spec.origin.endswith(".py"):
            base = os.path.dirname(os.path.abspath(spec.origin))
            out.append(f"{top}:{os.path.join(base, '__pycache__')}")

    return out
def resolve_startup_hook(name: str) -> str | None:
    spec = importlib.util.find_spec(name)

    if not spec or spec.origin in ("built-in", "frozen", None):
        return None

    # only report real files
    if os.path.isfile(spec.origin):
        return f"{name}:{os.path.abspath(spec.origin)}"

    return None
def report_critical_startup_hooks(entries: list[str]) -> None:
    for entry in entries:
        hook, path, status = entry.rsplit(":", 2)

        if status == "writable" or is_parent_writable(path):
            printwhite(f"[+] - startup hook {hook} at {path} is writable or in writable directory")


def report_env_poisoning(findings: list[str]) -> None:
    for entry in findings:
        key, val, status = entry.split(":", 2)

        if key == "PYTHONPATH" and status == "writable":
            printwhite(f"[+] - environment poisoning: PYTHONPATH includes writable directory {val}")

        elif key == "PYTHONHOME" and status == "set":
            printwhite(f"[+] - environment poisoning: PYTHONHOME is set ({val}) and may alter stdlib roots")

        elif key == "LD_PRELOAD" and status == "set":
            printwhite(f"[+] - environment poisoning: LD_PRELOAD is set ({val})")

        elif key == "LD_LIBRARY_PATH" and status == "writable":
            printwhite(f"[+] - environment poisoning: LD_LIBRARY_PATH includes writable directory {val}")
def sys_path_indexed() -> list[tuple[int, str]]:
    out = []
    cwd = os.getcwd()

    for idx, p in enumerate(sys.path):
        if p == "":
            out.append((idx, os.path.abspath(cwd)))
        else:
            out.append((idx, os.path.abspath(p)))
    return out
def check_import_shadowing(imports: list[str]) -> list[str]:
    findings = []

    # Resolve each top-level import once
    resolved = {}
    for name in imports:
        top = name.split(".")[0]
        if top in resolved:
            continue

        spec = importlib.util.find_spec(top)
        if not spec:
            resolved[top] = None
            continue

        # Skip built-in/frozen
        if spec.origin in ("built-in", "frozen"):
            resolved[top] = ("builtin", None, None)
            continue

        # Namespace package: handled elsewhere (your namespace check)
        if spec.origin is None and spec.submodule_search_locations:
            resolved[top] = ("namespace", None, None)
            continue

        # Package: stop at the PARENT directory of the package folder
        if spec.submodule_search_locations:
            pkg_dir = os.path.abspath(list(spec.submodule_search_locations)[0])
            stop_dir = os.path.dirname(pkg_dir)  # this is the sys.path entry that provided it
            resolved[top] = ("package", pkg_dir, stop_dir)
            continue

        # Normal module file: stop at directory containing the .py/.so
        origin_abs = os.path.abspath(spec.origin)
        stop_dir = os.path.dirname(origin_abs)
        resolved[top] = ("module", origin_abs, stop_dir)

    ext_suffixes = list(importlib.machinery.EXTENSION_SUFFIXES)
    sp = sys_path_indexed()

    for top, info in resolved.items():
        if info is None:
            continue

        kind, origin_path, stop_dir = info
        if kind in ("builtin", "namespace"):
            continue

        # Scan sys.path entries up to (and including) the provider entry (stop_dir)
        for idx, d in sp:
            if not os.path.isdir(d):
                continue

            d_abs = os.path.abspath(d)

            # 1) already shadowed checks
            c1 = os.path.join(d_abs, f"{top}.py")
            c2 = os.path.join(d_abs, top, "__init__.py")

            if os.path.exists(c1):
                findings.append(f"HIGH:{top}:{idx}:{c1}:already-exists")
                break

            if os.path.exists(c2):
                findings.append(f"HIGH:{top}:{idx}:{c2}:already-exists")
                break

            found_ext = False
            for suf in ext_suffixes:
                c3 = os.path.join(d_abs, f"{top}{suf}")
                if os.path.exists(c3):
                    findings.append(f"HIGH:{top}:{idx}:{c3}:already-exists")
                    found_ext = True
                    break
            if found_ext:
                break

            # Stop once we reach the sys.path entry that actually provided the real import
            if d_abs == stop_dir:
                break

            # 2) plantable if writable+traversable
            if os.access(d_abs, os.W_OK) and os.access(d_abs, os.X_OK):
                findings.append(f"HIGH:{top}:{idx}:{d_abs}:plantable")
                break

    return findings

def check_namespace_packages(imports: list[str]) -> list[str]:
    findings = []

    for name in imports:
        top = name.split(".")[0]
        spec = importlib.util.find_spec(top)

        if not spec:
            continue

        # Namespace package: origin is None, but has search locations
        if spec.origin is None and spec.submodule_search_locations:
            for d in spec.submodule_search_locations:
                d = os.path.abspath(d)
                if os.access(d, os.W_OK) and os.access(d, os.X_OK):
                    findings.append(f"{top}:{d}:namespace-writable")

    return findings

def scan_pth_files(site_dirs: list[str]) -> list[str]:
    """
    Returns findings like:
      'writable-pth:/path/file.pth'
      'exec-line:/path/file.pth'
      'writable-added-path:/path/file.pth:/added/path'
    """
    findings = []

    for sd in site_dirs:
        try:
            for fn in os.listdir(sd):
                if not fn.endswith(".pth"):
                    continue

                pth = os.path.join(sd, fn)

                # If .pth itself is writable
                if os.access(pth, os.W_OK):
                    findings.append(f"writable-pth:{pth}")

                # Parse .pth lines
                try:
                    with open(pth, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            s = line.strip()
                            if not s or s.startswith("#"):
                                continue

                            # Some .pth lines execute code on startup
                            if s.startswith("import "):
                                findings.append(f"exec-line:{pth}")
                                continue

                            # Otherwise treat as a path being added
                            added = os.path.abspath(os.path.expanduser(s))
                            if os.path.isdir(added) and os.access(added, os.W_OK) and os.access(added, os.X_OK):
                                findings.append(f"writable-added-path:{pth}:{added}")

                except OSError:
                    continue

        except OSError:
            continue

    return findings
def report_pth_findings(findings: list[str]) -> None:
    for f in findings:
        parts = f.split(":")

        kind = parts[0]

        if kind == "writable-pth":
            pth = parts[1]
            printwhite(f"[+] - writable .pth file: {pth} (startup path/code injection risk)")

        elif kind == "exec-line":
            pth = parts[1]
            printwhite(f"[+] - .pth executes code at startup: {pth} (contains 'import ...')")

        elif kind == "writable-added-path":
            pth = parts[1]
            added = parts[2]
            printwhite(f"[+] - .pth adds writable directory to sys.path: {added} (from {pth})")

def report_namespace_findings(findings: list[str]) -> None:
    for entry in findings:
        pkg, d, _ = entry.split(":", 2)
        printwhite(f"[+] - namespace injection possible: package '{pkg}' has writable location {d}")
def split_env_paths(val: str) -> list[str]:
    return [p for p in val.split(":") if p]
def check_env_poisoning() -> list[str]:
    findings = []

    pp = os.environ.get("PYTHONPATH")
    if pp:
        for d in split_env_paths(pp):
            d = os.path.abspath(d)
            if os.path.isdir(d) and os.access(d, os.W_OK) and os.access(d, os.X_OK):
                findings.append(f"PYTHONPATH:{d}:writable")

    ph = os.environ.get("PYTHONHOME")
    if ph:
        findings.append(f"PYTHONHOME:{ph}:set")

    lp = os.environ.get("LD_PRELOAD")
    if lp:
        findings.append(f"LD_PRELOAD:{lp}:set")

    llp = os.environ.get("LD_LIBRARY_PATH")
    if llp:
        for d in split_env_paths(llp):
            d = os.path.abspath(d)
            if os.path.isdir(d) and os.access(d, os.W_OK) and os.access(d, os.X_OK):
                findings.append(f"LD_LIBRARY_PATH:{d}:writable")

    return findings

def mark_replaceability(resolved: list[str]) -> list[str]:
    """
    Input: entries like 'name:/path/to/module.py' OR 'name:/path/to/package_dir'
    Output: 'name:path:replaceable' for non-writable file where parent dir is writable
    """
    out = []

    for entry in resolved:
        name, path = entry.split(":", 1)

        if path in ("built-in", "frozen", None):
            continue

        p = os.path.abspath(path)

        # If it's a directory (package dir), replacement typically means dropping files inside
        # That’s covered by writable-dir checks, but still useful to flag.
        if os.path.isdir(p):
            if os.access(p, os.W_OK) and os.access(p, os.X_OK):
                out.append(f"{name}:{p}:replaceable")
            continue

        # If it's a file: not writable but parent writable => replace risk
        if os.path.isfile(p) and (not os.access(p, os.W_OK)):
            parent = os.path.dirname(p)
            if os.access(parent, os.W_OK) and os.access(parent, os.X_OK):
                out.append(f"{name}:{p}:replaceable")

    return out

def discover_site_package_dirs() -> list[str]:
    dirs = set()

    try:
        import site
        for d in getattr(site, "getsitepackages", lambda: [])():
            dirs.add(os.path.abspath(d))
        usd = getattr(site, "getusersitepackages", lambda: None)()
        if usd:
            dirs.add(os.path.abspath(usd))
    except Exception:
        pass

    # Also include sys.path entries that look like site-packages/dist-packages
    for p in sys.path:
        if not p:
            continue
        ap = os.path.abspath(p)
        if "site-packages" in ap or "dist-packages" in ap:
            dirs.add(ap)

    return [d for d in dirs if os.path.isdir(d)]


def scan_pth_files(site_dirs: list[str]) -> list[str]:
    """
    Returns findings like:
      'CRIT:/path/file.pth:writable-pth'
      'CRIT:/path/file.pth:exec-line'
      'HIGH:/path/file.pth:/added/path:writable-added-path'
    """
    findings = []

    for sd in site_dirs:
        try:
            for fn in os.listdir(sd):
                if not fn.endswith(".pth"):
                    continue
                pth = os.path.join(sd, fn)

                # writable .pth itself
                if os.access(pth, os.W_OK):
                    findings.append(f"CRIT:{pth}:writable-pth")

                # parse lines
                try:
                    with open(pth, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            s = line.strip()
                            if not s or s.startswith("#"):
                                continue

                            if s.startswith("import "):
                                findings.append(f"CRIT:{pth}:exec-line")
                                continue

                            # treat as path add
                            added = os.path.abspath(os.path.expanduser(s))
                            if os.path.isdir(added) and os.access(added, os.W_OK) and os.access(added, os.X_OK):
                                findings.append(f"HIGH:{pth}:{added}:writable-added-path")
                except OSError:
                    continue

        except OSError:
            continue

    return findings


def report_pth_findings(findings: list[str]) -> None:
    for f in findings:
        parts = f.split(":")

        sev = parts[0]
        if sev == "CRIT" and parts[2] == "writable-pth":
            printwhite(f"[+] - writable .pth file: {parts[1]} (startup path/code injection risk)")
        elif sev == "CRIT" and parts[2] == "exec-line":
            printwhite(f"[+] - .pth executes code at startup: {parts[1]} (contains 'import ...')")
        elif sev == "HIGH" and parts[3] == "writable-added-path":
            printwhite(f"[+] - .pth adds writable directory to sys.path: {parts[2]} (from {parts[1]})")

def report_replaceable_imports(entries: list[str]) -> None:
    for entry in entries:
        module, path, status = entry.rsplit(":", 2)
        if status == "replaceable":
            printwhite(f"[+] - {path} from module {module} is NOT writable but is REPLACEABLE (parent dir writable)")

def printgreen(text):
    # Bold neon green (CTF title color)
    print(f"\033[1;38;2;168;234;33m{text}\033[0m")
def printwhite(text):
    # Bold bright white (result / [+] lines)
    print(f"\033[1;97m{text}\033[0m")
def _rgb(r, g, b, bold=True):
    return f"\033[{1 if bold else 0};38;2;{r};{g};{b}m"


print(
    f"{_rgb(0,140,200)}pychecksec v0.1{RESET} -"
    f"{_rgb(0,170,120)} Brought to you by 0xUnd3adBeef{RESET} @"
    f" \033[1;48;2;168;234;33;38;2;0;0;0m hos.team \033[0m"
)



print("")
if not exists(path):
    print("Target script couldn't be reached, can't proceed")
    quit()

if is_writable(path):
    print("File exists and is writable (!)")
else:
    print("File exists and is NOT writable")

if is_readable(path):
    print("File is readable")
else:
    print("File is NOT readable, can't proceed")
    quit()

if is_parent_writable(path):
    print("Parent directory writable - import shadowing is likely (!)")


print(f"Gathering imported libraries from {path}")
targetImports = extractimports(path)

#print(targetImports) # debug stuff
targetPaths = resolve_import_paths(targetImports)
#print(targetPaths) # debug stuff
markedPathList = mark_writability(targetPaths)
#print(markedPathList) # debug stuff
print("")
printgreen("====== Listing writable library files / directories ======")
report_writable_imports(markedPathList)


print("")
printgreen("====== Listing writable sys.path directories ======")
sysPathList = normalized_sys_path()
#print(sysPathList) # debug stuff
sysPathList_w = mark_writability(sysPathList)
#print(sysPathList_w) # debug stuff
report_writable_syspath(sysPathList_w)

print("")
printgreen("====== Listing writable __pycache__ directories ======")
pycacheDirs = collect_pycache_dirs(targetImports)
#print(pycacheDirs) # debug stuff
pycacheDirs_w = mark_writability(pycacheDirs)
#print(pycacheDirs_w) # debug stuff
report_writable_pycache(pycacheDirs_w)

print("")
printgreen("====== Checking writable startup hooks (sitecustomize / usercustomize) ======")

startupHooks = []
sc = resolve_startup_hook("sitecustomize")
uc = resolve_startup_hook("usercustomize")

if sc:
    startupHooks.append(sc)
if uc:
    startupHooks.append(uc)

#print(startupHooks) # debug stuff
startupHooks_w = mark_writability(startupHooks)
#print(startupHooks_w) # debug stuff
report_critical_startup_hooks(startupHooks_w)

print("")
printgreen("====== Checking import shadowing / plantable hijacks ======")
shadowFindings = check_import_shadowing(targetImports)
# print(shadowFindings)
report_import_shadowing(shadowFindings)


print("")
printgreen("====== Checking namespace package injection ======")
ns = check_namespace_packages(targetImports)
report_namespace_findings(ns)

print("")
printgreen("====== Checking environment poisoning ======")
envFindings = check_env_poisoning()
report_env_poisoning(envFindings)

print("")
printgreen("====== Listing replaceable (parent-dir writable) imports ======")
replaceable = mark_replaceability(targetPaths)
report_replaceable_imports(replaceable)

print("")
printgreen("====== Checking .pth poisoning (site-packages path injection) ======")
sp_dirs = discover_site_package_dirs()
pth_findings = scan_pth_files(sp_dirs)
report_pth_findings(pth_findings)


# Restore original state cuz why not
os.chdir(_ORIG_CWD)
sys.path[:] = _ORIG_SYS_PATH
