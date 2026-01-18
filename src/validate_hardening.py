#!/usr/bin/env python3
import json
import os
import subprocess
from datetime import datetime
from typing import Dict, Any, List

CONTROL_MAPPINGS = {
    "SSH Hardening": {
        "CIS": ["CIS Ubuntu Linux Benchmark - SSH Configuration (varies by version)"],
        "ISO27001": ["A.8.9 Configuration management", "A.8.20 Network security"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-4"]
    },
    "Firewall Enabled": {
        "CIS": ["CIS Ubuntu Linux Benchmark - Firewall Configuration"],
        "ISO27001": ["A.8.20 Network security"],
        "NIST_CSF": ["PR.PT-4"]
    },
    "Automatic Updates": {
        "CIS": ["CIS Ubuntu Linux Benchmark - Patch Management / Updates"],
        "ISO27001": ["A.8.8 Management of technical vulnerabilities"],
        "NIST_CSF": ["PR.IP-12"]
    },
    "Password Aging Policy": {
        "CIS": ["CIS Ubuntu Linux Benchmark - Password Policies"],
        "ISO27001": ["A.5.17 Authentication information", "A.8.2 Privileged access rights"],
        "NIST_CSF": ["PR.AC-1"]
    }
}



def run(cmd: List[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""


def check_ssh_config() -> Dict[str, Any]:
    result = {"control": "SSH Hardening", "mappings": CONTROL_MAPPINGS.get("SSH Hardening", {}), "checks": []}
    sshd = "/etc/ssh/sshd_config"

    if not os.path.exists(sshd):
        result["status"] = "NOT APPLICABLE"
        return result

    content = run(["grep", "-Ei", "PermitRootLogin|PasswordAuthentication", sshd])

    root_login = "no" if "PermitRootLogin no" in content else "yes"
    password_auth = "no" if "PasswordAuthentication no" in content else "yes"

    result["checks"].append({
        "setting": "PermitRootLogin",
        "value": root_login,
        "risk": "HIGH" if root_login == "yes" else "LOW"
    })

    result["checks"].append({
        "setting": "PasswordAuthentication",
        "value": password_auth,
        "risk": "MEDIUM" if password_auth == "yes" else "LOW"
    })

    result["status"] = "FAIL" if any(c["risk"] != "LOW" for c in result["checks"]) else "PASS"
    return result


def check_firewall() -> Dict[str, Any]:
    active = run(["ufw", "status"])
    enabled = "active" in active.lower()

    return {
        return {
        "control": "Firewall Enabled",
        "mappings": CONTROL_MAPPINGS.get("Firewall Enabled", {}),
        "enabled": enabled,
        "risk": "HIGH" if not enabled else "LOW",
        "status": "FAIL" if not enabled else "PASS"
    }


def check_updates() -> Dict[str, Any]:
    auto = run(["systemctl", "is-enabled", "unattended-upgrades"])
    enabled = "enabled" in auto

    return {
        return {
        "control": "Automatic Updates",
        "mappings": CONTROL_MAPPINGS.get("Automatic Updates", {}),
        "enabled": enabled,
        "risk": "MEDIUM" if not enabled else "LOW",
        "status": "FAIL" if not enabled else "PASS"
    }


def check_password_policy() -> Dict[str, Any]:
    defs = run(["grep", "-E", "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE", "/etc/login.defs"])
    risk = "LOW" if "PASS_MAX_DAYS" in defs else "MEDIUM"

    return {
        return {
        "control": "Password Aging Policy",
        "mappings": CONTROL_MAPPINGS.get("Password Aging Policy", {}),
        "details": defs,
        "risk": risk,
        "status": "PASS" if risk == "LOW" else "REVIEW"
    }


def main() -> None:
    findings = []
    findings.append(check_ssh_config())
    findings.append(check_firewall())
    findings.append(check_updates())
    findings.append(check_password_policy())

    overall = "PASS"
    if any(f.get("risk") == "HIGH" or f.get("status") == "FAIL" for f in findings):
        overall = "FAIL"
    elif any(f.get("risk") == "MEDIUM" for f in findings):
        overall = "REVIEW"

    report = {
        "generated_at": datetime.now().isoformat(),
        "overall_status": overall,
        "controls": findings
    }

    os.makedirs("reports", exist_ok=True)

    with open("reports/hardening_report.json", "w") as f:
        json.dump(report, f, indent=2)

    with open("reports/hardening_report.md", "w") as f:
        f.write("# 🔐 Linux Hardening Validation Report\n\n")
        f.write(f"- Generated: `{report['generated_at']}`\n")
        f.write(f"- Overall Status: **{overall}**\n\n")

        for c in findings:
    f.write(f"## {c['control']}\n")

    # Show mappings neatly
    if "mappings" in c and c["mappings"]:
        f.write("**Mappings:**\n")
        for std, refs in c["mappings"].items():
            f.write(f"- {std}: {', '.join(refs)}\n")
        f.write("\n")

    # Show the rest of the fields
    for k, v in c.items():
        if k in ("control", "mappings"):
            continue
        f.write(f"- **{k}**: `{v}`\n")
    f.write("\n")


    print("✅ Hardening report generated")
    print("- reports/hardening_report.md")
    print("- reports/hardening_report.json")


if __name__ == "__main__":
    main()

