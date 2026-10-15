#!/bin/bash
#
# Build cowctl and start its prompt on this machine: no Docker, no object storage
# server, no storage credentials. Files that tasks produce are kept on local disk
# (COW_DATA_PERSISTENCE_TYPE=local) and refer to each other by file:// URLs.
#
#   ./run_local.sh                       build if needed, then open the cowctl prompt
#   ./run_local.sh exec rule --rule-name X --catalog globalcatalog --user-inputs '{...}'
#                                        run one cowctl command and exit
#   ./run_local.sh --rebuild             rebuild the binary even if it looks up to date
#   ./run_local.sh --reinstall           recreate the Python environment
#   ./run_local.sh --choose-python       pick the Python again
#
# Needs: Go, Python 3.10+ and uv (https://docs.astral.sh/uv/), on Mac or Linux.
# Nothing has to be configured: it finds the Python itself, and asks which one to use
# only when it finds several (the answer is remembered).
#
# Everything it creates is in .cowctl-local/ (ignored by git): the binary, the Python
# environment and a config file with this machine's paths. The repo's tracked files
# are not changed. Files produced by rules are in ~/.cowctl/storage unless
# COW_LOCAL_STORAGE_PATH says otherwise.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="$REPO/.cowctl-local"
BIN="$STATE/bin/cowctl"
VENV="$STATE/venv"

rebuild=0
reinstall=0
choose_python=0
while [ $# -gt 0 ]; do
    case "$1" in
        --rebuild) rebuild=1; shift ;;
        --reinstall) reinstall=1; shift ;;
        --choose-python) choose_python=1; shift ;;
        -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── prerequisites ───────────────────────────────────────────────────────────────

command -v go >/dev/null 2>&1 || die "Go is not installed (https://go.dev/dl/)."
command -v uv >/dev/null 2>&1 || die "uv is not installed. cowctl uses it to create each Python task's environment. Install it with: brew install uv   (or: curl -LsSf https://astral.sh/uv/install.sh | sh)"

# Every Python 3.10+ on this machine, newest first, one "version<TAB>real path" per line.
# Looks on the PATH and where Python is usually installed (Homebrew, python.org, pyenv, the
# system), and lists an interpreter once however many links lead to it.
find_pythons() {
    {
        for name in python3.14 python3.13 python3.12 python3.11 python3.10 python3 python; do
            command -v "$name" 2>/dev/null || true
        done
        ls /opt/homebrew/bin/python3.1[0-9] /usr/local/bin/python3.1[0-9] /usr/bin/python3 \
            /Library/Frameworks/Python.framework/Versions/3.1[0-9]/bin/python3 \
            "$HOME"/.pyenv/versions/*/bin/python3 /usr/bin/python3.1[0-9] 2>/dev/null || true
    } | while IFS= read -r candidate; do
        [ -x "$candidate" ] || continue
        "$candidate" -c 'import os, sys; v = sys.version_info
if v >= (3, 10) and sys.prefix == sys.base_prefix:
    print("%d.%d.%d\t%s" % (v[0], v[1], v[2], os.path.realpath(sys.executable)))' 2>/dev/null || true
    done | awk -F'\t' '!seen[$2]++' | sort -t. -k1,1nr -k2,2nr -k3,3nr
}

# Ask which one to use. The newest one is the default, except that a version released
# after the libraries were pinned (3.14+) is not recommended while an older one exists.
choose_python_interactively() {
    local i=0 default=1 line version path
    local versions=() paths=()
    while IFS=$'\t' read -r version path; do
        [ -n "$path" ] || continue
        versions[i]="$version"
        paths[i]="$path"
        i=$((i + 1))
    done <<< "$1"
    for ((n = 0; n < i; n++)); do
        case "${versions[n]}" in 3.14.*|3.15.*|3.16.*) ;; *) default=$((n + 1)); break ;; esac
    done
    {
        echo
        echo "Several Python versions were found. Which one should cowctl use to run the tasks?"
        for ((n = 0; n < i; n++)); do
            printf '  %d) %-8s %s%s\n' $((n + 1)) "${versions[n]}" "${paths[n]}" "$([ $((n + 1)) = "$default" ] && echo '   (recommended)')"
        done
    } > /dev/tty
    while true; do
        printf 'Enter a number [%s]: ' "$default" > /dev/tty
        read -r line < /dev/tty || return 1
        line="${line:-$default}"
        if [[ "$line" =~ ^[0-9]+$ ]] && [ "$line" -ge 1 ] && [ "$line" -le "$i" ]; then
            CHOSEN_PY="${paths[line - 1]}"
            return 0
        fi
        echo "Please enter a number from 1 to $i." > /dev/tty
    done
}

PY=""
# The earlier choice, if it is still there.
if [ "$choose_python" != 1 ] && [ -s "$STATE/python" ]; then
    saved="$(cat "$STATE/python")"
    if [ -x "$saved" ] && "$saved" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PY="$saved"
    fi
fi
if [ -z "$PY" ]; then
    found="$(find_pythons)"
    count="$(printf '%s\n' "$found" | grep -c . || true)"
    if [ "$count" -eq 0 ]; then
        die "Python 3.10 or higher was not found. Install it (for example: brew install python@3.12) and run this again."
    elif [ "$count" -eq 1 ]; then
        PY="$(printf '%s\n' "$found" | cut -f2)"
    elif [ -t 0 ] && [ -w /dev/tty ] && choose_python_interactively "$found"; then
        PY="$CHOSEN_PY"
    else
        # Nobody to ask (a script, a pipe): the newest that is not too new for the libraries.
        PY="$(printf '%s\n' "$found" | grep -v '^3\.1[4-9]\.' | head -n 1 | cut -f2)"
        [ -n "$PY" ] || PY="$(printf '%s\n' "$found" | head -n 1 | cut -f2)"
        say "Several Pythons were found; using $PY (run with --choose-python in a terminal to pick another)"
    fi
    mkdir -p "$STATE"
    echo "$PY" > "$STATE/python"
fi

mkdir -p "$STATE/bin"

# ── the binary ──────────────────────────────────────────────────────────────────

# The committed go.mod needs `go mod tidy` before it builds (the container image runs it);
# done here on a copy, so that tracked files stay as they are.
needs_build() {
    [ "$rebuild" = 1 ] && return 0
    [ -x "$BIN" ] || return 0
    [ -n "$(find "$REPO/src/cowctl" "$REPO/src/cowlibrary" "$REPO/catalog/applicationtypes/go" \
        \( -name '*.go' -o -name go.mod -o -name go.sum \) -newer "$BIN" 2>/dev/null | head -n 1)" ]
}

if needs_build; then
    say "Building cowctl (the first build downloads Go modules and can take a few minutes)"
    cp "$REPO/src/cowctl/go.mod" "$STATE/cowctl.mod"
    cp "$REPO/src/cowctl/go.sum" "$STATE/cowctl.sum"
    (
        cd "$REPO/src/cowctl"
        go mod tidy -modfile="$STATE/cowctl.mod" >/dev/null
        go build -buildvcs=false -modfile="$STATE/cowctl.mod" -o "$BIN" .
    ) || die "the build failed."
fi

# ── the Python environment ──────────────────────────────────────────────────────

# Every Python task gets its own virtual environment that inherits the packages of the
# interpreter it was created from, so the libraries are made visible to it below: the library
# source itself (always current) and the packages it depends on.
# The same lists the container image installs for every task to inherit: the tools every
# task can count on (requests, msal, sqlalchemy, yapf, ...), the libraries, and the data library.
REQS=("$REPO/src/requirements.txt" "$REPO/src/compliancecowcards/requirements.txt"
      "$REPO/catalog/applicationtypes/python/requirements.txt")
STAMP="$(cat "${REQS[@]}" | cksum | cut -d' ' -f1)-$PY"

if [ "$reinstall" = 1 ] || [ ! -x "$VENV/bin/python" ] || [ "$(cat "$STATE/venv.stamp" 2>/dev/null)" != "$STAMP" ]; then
    say "Setting up the Python environment ($PY)"
    rm -rf "$VENV"
    uv venv -q "$VENV" --python "$PY"
    uv pip install -q --python "$VENV/bin/python" -r "${REQS[0]}" -r "${REQS[1]}" -r "${REQS[2]}" \
        || die "installing the Python requirements failed."
    echo "$STAMP" > "$STATE/venv.stamp"
fi
SITE="$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"

# ── configuration for this machine ──────────────────────────────────────────────

# The container's config has /policycow/... paths; this is the same file with the repo's.
sed "s#/policycow#$REPO#g" "$REPO/etc/cowconfig.yaml" > "$STATE/cowconfig.yaml"

# What the container reads from its env files: application URLs and credentials come
# from the same files here.
set +u
set -a
for f in "$REPO/etc/userconfig.env" "$REPO/etc/policycow.env" "$REPO/etc/.credentials.env"; do
    # shellcheck disable=SC1090
    [ -f "$f" ] && . "$f"
done
set +a
set -u

export COW_DATA_PERSISTENCE_TYPE=local
export COW_LOCAL_STORAGE_PATH="${COW_LOCAL_STORAGE_PATH:-$HOME/.cowctl/storage}"
unset MINIO_ACCESS_KEY MINIO_SECRET_KEY

export POLICYCOW_DEFAULTCONFIGPATH="$STATE/cowconfig.yaml"
export POLICYCOW_TASKPATH="$REPO/catalog/globalcatalog/tasks"
export POLICYCOW_RULESPATH="$REPO/catalog/globalcatalog/rules"
export POLICYCOW_EXECUTIONPATH="$REPO/cowexecutions"
export POLICYCOW_RULEGROUPPATH="$REPO/catalog/globalcatalog/rulegroups"
export POLICYCOW_SYNTHESIZERPATH="$REPO/catalog/globalcatalog/synthesizers"
export POLICYCOW_DOWNLOADSPATH="$REPO/exported-data"
export POLICYCOW_APPLICATIONSCOPEPATH="$REPO/catalog/applicationscope"
export POLICYCOW_YAMLFILESPATH="$REPO/catalog/globalcatalog/yamlfiles"
export POLICYCOW_DASHBOARDSPATH="$REPO/catalog/globalcatalog/dashboards"
export POLICYCOW_DECLARATIVES_PATH="$REPO/catalog/globalcatalog/declaratives"
export POLICYCOW_DASH_APP_CONNECTIONS_PATH="$REPO/catalog/applicationtypes"
export POLICYCOW_APPLICATION_CLASS_PATH="$REPO/catalog/globalcatalog/yamlfiles/applicationtypes"
export POLICYCOW_CREDENTIALS_PATH="$REPO/catalog/globalcatalog/yamlfiles/credentialtypes"

# The packages of this environment are what the container's global packages are to a task: they
# are used when the task's own virtual environment does not have them, never in place of what it
# installed. PYTHONPATH cannot do that (it comes before the task's own packages, so a task that
# pins pyarrow==22 would run on whatever version is here). A sitecustomize on it adds them to the
# end of the search path instead. Only the library source, which tasks do not install, goes first.
HOOK="$STATE/pyhook"
mkdir -p "$HOOK"
cat > "$HOOK/sitecustomize.py" <<PYEOF
import site
site.addsitedir("$SITE")
PYEOF

export UV_PYTHON="$PY"
export PYTHONPATH="$REPO/src/compliancecowcards:$HOOK${PYTHONPATH:+:$PYTHONPATH}"
export PATH="$VENV/bin:$PATH"

mkdir -p "$COW_LOCAL_STORAGE_PATH" "$REPO/cowexecutions"

# ── go ──────────────────────────────────────────────────────────────────────────

if [ $# -eq 0 ]; then
    say "Files that rules produce are kept in $COW_LOCAL_STORAGE_PATH"
    say "Give a file input as a path, e.g.  exec rule --user-inputs '{\"InputFile\": \"/path/to/file.csv\"}'"
fi
exec "$BIN" "$@"
