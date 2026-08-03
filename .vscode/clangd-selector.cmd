:;exec bash "$0" "$@"
@goto :WINDOWS

# ============================================================================
#
# Universal clangd selector
#
# Selects the most appropriate clangd for the current project by inspecting
# compile_commands.json.
#
# Supported toolchains:
#   - Android NDK
#   - Apple Xcode
#   - Apple CommandLineTools
#   - Homebrew LLVM
#   - Generic LLVM
#
# Windows simply launches the first clangd.exe on PATH.
#
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

COMPILE_COMMANDS="$ROOT/compile_commands.json"

log()
{
    echo "clangd-selector: $*" >&2
}

##########################################################################
# Find host platform used inside Android NDK
##########################################################################

host_tag()
{
    case "$(uname -s)" in
        Darwin)
            echo "darwin-x86_64"
            ;;
        Linux)
            echo "linux-x86_64"
            ;;
        *)
            return 1
            ;;
    esac
}

##########################################################################
# Detect preferred clangd from compile_commands.json
#
# Output:
#     absolute/path/to/clangd
#
# Returns nothing if no preference could be determined.
##########################################################################

detect_clangd()
{
python3 <<PY 2>/dev/null
import json
import os
import shlex
from pathlib import Path
from collections import Counter

DB = "$COMPILE_COMMANDS"

HOST = {
    "Darwin": "darwin-x86_64",
    "Linux": "linux-x86_64",
}.get(os.uname().sysname)

if HOST is None:
    raise SystemExit(0)

try:
    with open(DB, "r", encoding="utf-8") as f:
        db = json.load(f)
except Exception:
    raise SystemExit(0)


##########################################################################
# Helpers
##########################################################################

def argv(entry):
    if isinstance(entry.get("arguments"), list):
        return entry["arguments"]

    cmd = entry.get("command")
    if cmd:
        try:
            return shlex.split(cmd)
        except Exception:
            return []

    return []


def normalize(path):
    try:
        return str(Path(path).resolve())
    except Exception:
        return path


##########################################################################
# Classify one compiler
##########################################################################

votes = Counter()

for entry in db[:50]:

    args = argv(entry)

    if not args:
        continue

    compiler = normalize(args[0])
    lower = compiler.lower()

    ######################################################################
    # Android NDK
    ######################################################################

    if (
        "/ndk/" in lower or
        "\\ndk\\" in lower or
        "toolchains/llvm/prebuilt" in lower.replace("\\","/")
    ):

        p = Path(compiler)

        try:
            idx = p.parts.index("toolchains")
            ndk = Path(*p.parts[:idx])

            clangd = (
                ndk /
                "toolchains" /
                "llvm" /
                "prebuilt" /
                HOST /
                "bin" /
                "clangd"
            )

            votes[str(clangd)] += 100
            continue

        except Exception:
            pass

    ######################################################################
    # Xcode
    ######################################################################

    if "/Applications/Xcode.app/" in compiler:

        clangd = (
            "/Applications/Xcode.app/"
            "Contents/Developer/Toolchains/"
            "XcodeDefault.xctoolchain/usr/bin/clangd"
        )

        votes[clangd] += 90
        continue

    ######################################################################
    # Apple CommandLineTools
    ######################################################################

    if "/Library/Developer/CommandLineTools/" in compiler:

        clangd = (
            "/Library/Developer/CommandLineTools/"
            "usr/bin/clangd"
        )

        votes[clangd] += 80
        continue

    ######################################################################
    # Homebrew LLVM (Apple Silicon)
    ######################################################################

    if compiler.startswith("/opt/homebrew/opt/llvm/"):

        votes["/opt/homebrew/opt/llvm/bin/clangd"] += 70
        continue

    ######################################################################
    # Homebrew LLVM (Intel)
    ######################################################################

    if compiler.startswith("/usr/local/opt/llvm/"):

        votes["/usr/local/opt/llvm/bin/clangd"] += 70
        continue

    ######################################################################
    # Generic LLVM
    ######################################################################

    name = Path(compiler).name.lower()

    if name in (
        "clang",
        "clang++",
        "clang-cl",
        "clang-cl.exe",
    ):
        votes["clangd"] += 50
        continue


##########################################################################
# Print the winner
##########################################################################

if votes:

    clangd, _ = votes.most_common(1)[0]
    print(clangd)

PY
}

##########################################################################
# Android fallback discovery
##########################################################################

find_ndk_clangd()
{
    local ndk=""
    local host

    for v in \
        ANDROID_NDK_HOME \
        ANDROID_NDK \
        NDK_HOME
    do
        if [[ -n "${!v:-}" ]]; then
            ndk="${!v}"
            break
        fi
    done

    if [[ -z "$ndk" ]]; then

        for sdk in \
            ANDROID_HOME \
            ANDROID_SDK_ROOT \
            ANDROID_SDK_HOME \
            ANDROID_SDK
        do
            if [[ -n "${!sdk:-}" ]] &&
               [[ -d "${!sdk}/ndk" ]]
            then
                ndk="$(
                    ls -1 "${!sdk}/ndk" |
                    sort -V |
                    tail -1
                )"

                ndk="${!sdk}/ndk/$ndk"
                break
            fi
        done
    fi

    [[ -z "$ndk" ]] && return 1

    host="$(host_tag)" || return 1

    local c="$ndk/toolchains/llvm/prebuilt/$host/bin/clangd"

    [[ -x "$c" ]] && echo "$c"
}

##########################################################################
# Generic LLVM search
##########################################################################

find_system_clangd()
{
    local c

    c="$(command -v clangd 2>/dev/null || true)"

    if [[ -n "$c" && -x "$c" ]]; then
        echo "$c"
        return
    fi

    for c in \
        /opt/homebrew/opt/llvm/bin/clangd \
        /usr/local/opt/llvm/bin/clangd \
        /usr/local/bin/clangd \
        /usr/bin/clangd
    do
        [[ -x "$c" ]] && {
            echo "$c"
            return
        }
    done
}

##########################################################################
# Main
##########################################################################

CLANGD=""

if [[ -f "$COMPILE_COMMANDS" ]]; then

    CLANGD="$(detect_clangd || true)"

    if [[ -n "$CLANGD" ]]; then

        if [[ "$CLANGD" = "clangd" ]]; then
            CLANGD="$(find_system_clangd || true)"
        elif [[ ! -x "$CLANGD" ]]; then
            CLANGD=""
        fi
    fi
fi

##########################################################################
# Fallback chain
##########################################################################

if [[ -z "$CLANGD" ]]; then
    CLANGD="$(find_system_clangd || true)"
fi

if [[ -z "$CLANGD" ]]; then
    log "ERROR: unable to locate clangd"
    exit 1
fi

log "using clangd: $CLANGD"

exec "$CLANGD" "$@"

exit 0

:WINDOWS

@echo off
setlocal

REM ===========================================================================
REM Windows
REM
REM We intentionally do NOT inspect compile_commands.json here.
REM LLVM for Windows ships a single clangd.exe which works regardless of
REM whether the project uses clang++, clang-cl, MSVC compatibility, etc.
REM ===========================================================================

set "CLANGD="

where clangd.exe >nul 2>&1

if errorlevel 1 (
    echo clangd-selector: ERROR: clangd.exe not found on PATH 1>&2
    exit /b 1
)

for /f "delims=" %%A in ('where clangd.exe') do (
    set "CLANGD=%%A"
    goto :launch
)

echo clangd-selector: ERROR: unable to locate clangd.exe 1>&2
exit /b 1

:launch

"%CLANGD%" %*
exit /b %ERRORLEVEL%