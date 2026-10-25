#!/usr/bin/env python3
"""SecureConfig: read-only local security configuration audit.

Checks the host (firewall, common loopback ports) and the Secure Authentication
Lab project itself (secret handling, cookie flags, Git ignore rules).
Standard library only. It never modifies settings, never sends data anywhere,
and never prints or stores secret values.
"""
import argparse
import json
import os
import platform
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent

COMMON_LOCAL_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3306: "MySQL",
    5432: "PostgreSQL",
    5000: "Flask development server (this lab)",
    6379: "Redis",
    8080: "Alternate HTTP / development server",
}

PLACEHOLDER_SECRETS = {"", "replace-with-a-long-random-secret", "changeme", "secret"}


# --------------------------------------------------------------------------
# Host checks
# --------------------------------------------------------------------------
def run_read_only(command, timeout=3):
    """Run a read-only system command; return output or None."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode == 0:
            return (result.stdout + "\n" + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def firewall_check(system):
    if system == "Windows":
        output = run_read_only(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if output:
            lowered = output.lower()
            if "state" in lowered and "on" in lowered:
                return {"status": "enabled", "evidence": "Windows firewall reports one or more profiles On"}
            if "state" in lowered and "off" in lowered:
                return {"status": "review", "evidence": "Windows firewall output includes an Off state; verify each profile"}
        return {"status": "unknown", "evidence": "Could not reliably parse netsh output"}
    if system == "Linux":
        output = run_read_only(["ufw", "status"])
        if output:
            first_line = output.lower().splitlines()[0] if output.splitlines() else ""
            if "inactive" in first_line:
                return {"status": "review", "evidence": "UFW reports Status: inactive; another firewall may still be active"}
            if "active" in first_line:
                return {"status": "enabled", "evidence": "UFW reports Status: active"}
        return {"status": "unknown", "evidence": "UFW unavailable or status not recognized; check your firewall tool manually"}
    if system == "Darwin":
        output = run_read_only(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if output:
            lowered = output.lower()
            if "disabled" in lowered:
                return {"status": "review", "evidence": output}
            if "enabled" in lowered:
                return {"status": "enabled", "evidence": output}
        return {"status": "unknown", "evidence": "Could not read macOS application firewall state"}
    return {"status": "unknown", "evidence": "Unsupported operating system"}


def check_loopback_ports(ports=None):
    results = []
    for port, service in (ports or COMMON_LOCAL_PORTS).items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            is_open = sock.connect_ex(("127.0.0.1", port)) == 0
        except OSError:
            is_open = False
        finally:
            sock.close()
        results.append({
            "port": port,
            "service_hint": service,
            "status": "open_on_loopback" if is_open else "not_detected",
            "note": "Review whether this local service is needed" if is_open
                    else "No TCP listener detected on loopback",
        })
    return results


# --------------------------------------------------------------------------
# Project checks (Secure Authentication Lab)
# --------------------------------------------------------------------------
def parse_env_file(path):
    """Minimal KEY=VALUE parser (no third-party packages, no variable expansion)."""
    values = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def _item(check, status, detail):
    return {"check": check, "status": status, "detail": detail}


def project_config_check(project_dir=PROJECT_DIR):
    """Audit this project's configuration. Statuses: pass, review, unknown."""
    project_dir = Path(project_dir)
    findings = []
    env_path = project_dir / ".env"

    # 1. .env presence and SECRET_KEY quality (value is never reported)
    if not env_path.is_file():
        findings.append(_item("env_file", "review",
                              ".env not found; the app will refuse to start without SECRET_KEY"))
        env = {}
    else:
        env = parse_env_file(env_path)
        findings.append(_item("env_file", "pass", ".env present"))
        key = env.get("SECRET_KEY", "")
        if key.lower() in PLACEHOLDER_SECRETS:
            findings.append(_item("secret_key", "review", "SECRET_KEY is empty or still a placeholder"))
        elif len(key) < 32:
            findings.append(_item("secret_key", "review",
                                  f"SECRET_KEY is {len(key)} characters; use at least 32 random bytes (64 hex chars)"))
        else:
            findings.append(_item("secret_key", "pass",
                                  f"SECRET_KEY length is {len(key)} characters (value not shown)"))

        # 2. Cookie flag
        if env.get("COOKIE_SECURE", "0") == "1":
            findings.append(_item("cookie_secure", "pass", "COOKIE_SECURE=1 (requires HTTPS)"))
        else:
            findings.append(_item("cookie_secure", "review",
                                  "COOKIE_SECURE is 0: fine for localhost HTTP, not for any HTTPS deployment"))

        # 3. Rate-limit backend
        if env.get("RATELIMIT_STORAGE_URI", "memory://").startswith("memory://"):
            findings.append(_item("ratelimit_storage", "review",
                                  "In-memory rate limiting is per-process; use Redis for multi-process deployments"))
        else:
            findings.append(_item("ratelimit_storage", "pass", "Shared rate-limit storage configured"))

        # 4. File permissions (POSIX only)
        if os.name == "posix":
            mode = stat.S_IMODE(env_path.stat().st_mode)
            if mode & 0o077:
                findings.append(_item("env_permissions", "review",
                                      f".env mode is {oct(mode)}; consider chmod 600 .env"))
            else:
                findings.append(_item("env_permissions", "pass", f".env mode is {oct(mode)}"))

    # 5. Git ignore rules protect secrets and local data
    gitignore = project_dir / ".gitignore"
    if gitignore.is_file():
        lines = {l.strip() for l in gitignore.read_text(encoding="utf-8", errors="replace").splitlines()}
        for pattern, label in ((".env", "env_gitignored"), ("auth_lab.db", "db_gitignored")):
            if pattern in lines:
                findings.append(_item(label, "pass", f"{pattern} is listed in .gitignore"))
            else:
                findings.append(_item(label, "review", f"{pattern} is NOT listed in .gitignore"))
    else:
        findings.append(_item("gitignore", "review", ".gitignore not found"))

    # 6. Dependency pinning (upper bounds reduce surprise breaking changes)
    req = project_dir / "requirements.txt"
    if req.is_file():
        unbounded = [l.strip() for l in req.read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.startswith("#") and "<" not in l and "==" not in l]
        if unbounded:
            findings.append(_item("requirements_bounds", "review",
                                  "Dependencies without an upper bound or pin: " + ", ".join(unbounded)))
        else:
            findings.append(_item("requirements_bounds", "pass", "All dependencies are bounded or pinned"))
    return findings


# --------------------------------------------------------------------------
def build_report(project_dir=PROJECT_DIR):
    system = platform.system()
    return {
        "tool": "SecureConfig",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Local host and this project only; loopback TCP checks use 127.0.0.1",
        "platform": {
            "system": system,
            "release": platform.release(),
            "python_version": platform.python_version(),
        },
        "checks": {
            "firewall": firewall_check(system),
            "loopback_ports": check_loopback_ports(),
            "project_config": project_config_check(project_dir),
        },
        "limitations": [
            "This is a small learning tool, not a full security scanner.",
            "Only a short list of TCP ports on 127.0.0.1 is checked.",
            "Firewall parsing and availability vary by operating system.",
            "A result of unknown means the check could not verify the state.",
            "Project checks read configuration only; they do not test the running app.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only local security configuration audit")
    parser.add_argument("--output", default="reports/secureconfig-report.json", help="JSON report path")
    parser.add_argument("--project-dir", default=str(PROJECT_DIR), help="Project folder to audit")
    args = parser.parse_args(argv)

    report = build_report(args.project_dir)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    checks = report["checks"]
    review = [f["check"] for f in checks["project_config"] if f["status"] == "review"]
    open_ports = [str(p["port"]) for p in checks["loopback_ports"] if p["status"] == "open_on_loopback"]
    print(f"Audit complete. Report saved to: {output_path}")
    print(f"Firewall status: {checks['firewall']['status']}")
    print("Detected loopback ports: " + (", ".join(open_ports) if open_ports else "none from the tested list"))
    print("Project items to review: " + (", ".join(review) if review else "none"))
    print("Review the JSON report before sharing it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
