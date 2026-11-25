"""F07 Leaked secret in git history: an API key was committed then deleted.

Expected (vuln branch/history): the key is recoverable from `git log -p`.
This PoC greps the repository history for the planted marker.
"""

import subprocess

from lab import banner

MARKER = "AKIA"  # AWS-style access key id prefix


def run():
    banner("Leaked key in git history")
    out = subprocess.run(
        ["git", "log", "-p", "-S", MARKER, "--all"], capture_output=True, text=True
    ).stdout
    found = MARKER in out
    print(f"key marker {MARKER!r} present in history: {found}")
    return found


if __name__ == "__main__":
    print("LEAK PRESENT" if run() else "no leak found (clean history)")
