#!/usr/bin/env python3
import json
import os
import subprocess
from datetime import datetime
from typing import Dict, Any, List


def run(cmd: List[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""


# -----------------------------
# CONTROL → STANDARD MAPPINGS
# -----------------------------
CONTROL_MAPPINGS = {
    "SSH Hardening": {
        "CIS": ["CIS Ubuntu Linux Benchmark - SSH Configuration"],
        "ISO27001": ["A.8.9 Configuration management", "A.8.20 Network security"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-4"]
    },
    "Firewall Enabled": {
        "CIS": ["CIS Ubuntu Linux Benchmark - Firewall Configuration"],
        "ISO27001": ["A.8.20 Network security"],
        "NIST_CSF": ["PR.PT-4"]
    },
    "Automatic Updates": {
        "CIS": ["CIS Ubuntu Linux Benchmark - Patch Management"],
        "ISO27001": ["A.8.8 Management of technical vulnerabilities"],
        "NIST_CSF": ["PR.IP-12"]
    },
    "Password Aging Policy": {
        "CIS": ["CIS Ubuntu Linux Benchmark - Password Policy"],
        "ISO27001": ["A.5.17 Authentication information", "A.8.2 Privileged access rights"],
        "NIST_CSF": ["PR.AC-1"]
    }
}

# -----------------------------
# RISK JUSTIFICATIONS
# -----------------------------
RISK_JUSTIFICATIONS = {
    "SSH Hardening": {
        "HIGH": "Allowing root login or password-based SSH authentication increases the risk of brute-force attacks and full system compromise.",
        "MEDIUM": "Password-based SSH authentication is vulnerable to credential stuffing and brute-force attacks.",
        "LOW": "SSH is hardened using recommended security configurations, reducing unauthorized access risk."
    },
    "Firewall Enabled": {
        "HIGH": "Without an active firewall, the system is exposed to unsolicited network traffic and external attacks.",
        "LOW": "An active firewall limits network exposure and reduces the system attack surface."
    },
    "Automatic Updates": {
        "MEDIUM": "Without automatic updates, known vulnerabilities may remain unpatched and exploitable.",
        "LOW": "Automatic updates reduce exposure to publicly known security vulnerabilities."
    },
    "Password Aging Policy": {
        "MEDIUM": "Weak or undefined password aging increases the likelihood of long-term credential compromise.",
        "LOW": "Password aging policies reduce the risk of long-term credential reuse and compromise."
    }
}


# -----------------------------
# CONTROL CHECKS
# -----------------------------
def check_ssh_config() -> Dict[str, Any]:
    result = {
        "control": "SSH Hardening",
        "mappings": CONTROL_MAPPINGS["SSH Hardening"],
        "checks": []
    }

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

    overall_risk = "LOW"
    if any(c["risk"] == "HIGH" for c in result["checks"]):
        overall_risk = "HIGH"
    elif any(c["risk"] == "MEDIUM" for c in result["checks"]):
        overall_risk = "MEDIUM"

    result["risk"] = overall_risk
    result["risk_justification"] = RISK_JUSTIFICATIONS["SSH Hardening"][overall_risk]
    result["status"] = "FAIL" if overall_risk != "LOW" else "PASS"

    return result


def check_firewall() -> Dict[str, Any]:
    active = run(["ufw", "status"])
    enabled = "active" in active.lower()

    risk = "LOW" if enabled else "HIGH"

    return {
        "control": "Firewall Enabled",
        "mappings": CONTROL_MAPPINGS["Firewall Enabled"],
        "enabled": enabled,
        "risk": risk,
        "risk_justification": RISK_JUSTIFICATIONS["Firewall Enabled"][risk],
        "status": "PASS" if enabled else "FAIL"
    }


def check_updates() -> Dict[str, Any]:
    auto = run(["systemctl", "is-enabled", "unattended-upgrades"])
    enabled = "enabled" in auto

    risk = "LOW" if enabled else "MEDIUM"

    return {
        "control": "Automatic Updates",
        "mappings": CONTROL_MAPPINGS["Automatic Updates"],
        "enabled": enabled,
        "risk": risk,
        "risk_justification": RISK_JUSTIFICATIONS["Automatic Updates"][risk],
        "status": "PASS" if enabled else "FAIL"
    }


def check_password_policy() -> Dict[str, Any]:
    defs = run(["grep", "-E", "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE", "/etc/login.defs"])

    risk = "LOW" if "PASS_MAX_DAYS" in defs else "MEDIUM"

    return {
        "control": "Password Aging Policy",
        "mappings": CONTROL_MAPPINGS["Password Aging Policy"],
        "details": defs,
        "risk": risk,
        "risk_justification": RISK_JUSTIFICATIONS["Password Aging Policy"][risk],
        "status": "PASS" if risk == "LOW" else "REVIEW"
    }


# -----------------------------
# MAIN
# -----------------------------
def main() -> None:
    findings = [
        check_ssh_config(),
        check_firewall(),
        check_updates(),
        check_password_policy()
    ]

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

            if c.get("mappings"):
                f.write("**Mappings:**\n")
                for std, refs in c["mappings"].items():
                    f.write(f"- {std}: {', '.join(refs)}\n")
                f.write("\n")

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

