import nmap
import json
import socket
from datetime import datetime
from fpdf import FPDF
import os

# ---------- Load CVE Database ----------
def load_cve_db():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cve_path = os.path.join(base_dir, "cve_db.json")

    with open(cve_path, "r") as f:
        return json.load(f)

# ---------- Port & Service Scan ----------
def scan_target(target):
    scanner = nmap.PortScanner()
    results = []

    try:
        print("[+] Performing fast service scan (Pn + F + sV)...")
        scanner.scan(target, arguments="-Pn -F -sV")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return results
    except Exception as e:
        print(f"[!] Scan error: {e}")
        return results

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                service = scanner[host][proto][port].get('name', 'unknown')

                product = scanner[host][proto][port].get('product', '')
                version = scanner[host][proto][port].get('version', '')
                full_version = f"{product} {version}".strip()

                results.append({
                    "port": port,
                    "service": service,
                    "version": full_version
                })

    return results

# ---------- Vulnerability Check ----------
def check_vulnerabilities(services, cve_db):
    findings = []

    for s in services:
        for key in cve_db:
            if key in s["version"]:
                vuln = cve_db[key]
                findings.append({
                    "port": s["port"],
                    "service": s["service"],
                    "version": s["version"],
                    "cve": vuln["cve"],
                    "severity": vuln["severity"],
                    "description": vuln["description"],
                    "solution": vuln["solution"]
                })
    return findings

# ---------- Risk Calculation ----------
def calculate_risk(findings):
    levels = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in findings:
        levels[f["severity"]] += 1

    if levels["HIGH"] > 0:
        return "HIGH"
    elif levels["MEDIUM"] > 0:
        return "MEDIUM"
    else:
        return "LOW"

# ---------- PDF Report ----------
def generate_pdf(target, ip, services, findings, risk):
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "SMART VULNERABILITY ASSESSMENT REPORT", ln=True)

    pdf.ln(5)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Target: {target}", ln=True)
    pdf.cell(0, 8, f"IP Address: {ip}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {datetime.now()}", ln=True)

    pdf.ln(8)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Open Ports & Services", ln=True)

    pdf.set_font("Arial", "", 12)
    if services:
        for s in services:
            pdf.cell(
                0, 8,
                f"Port {s['port']} | {s['service']} | {s['version']}",
                ln=True
            )
    else:
        pdf.cell(0, 8, "No open services detected.", ln=True)

    pdf.ln(8)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Vulnerability Findings", ln=True)

    pdf.set_font("Arial", "", 12)
    if findings:
        for f in findings:
            pdf.multi_cell(
                0, 8,
                f"CVE: {f['cve']}\n"
                f"Service: {f['service']} ({f['version']})\n"
                f"Severity: {f['severity']}\n"
                f"Description: {f['description']}\n"
                f"Recommendation: {f['solution']}\n"
            )
            pdf.ln(3)
    else:
        pdf.cell(0, 8, "No known vulnerabilities found.", ln=True)

    pdf.ln(8)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, f"Overall Risk Level: {risk}", ln=True)

    filename = f"{target}_report.pdf"
    pdf.output(filename)

    print(f"[+] Report generated: {filename}")

# ---------- MAIN ----------
def main():
    print("\nSMART VULNERABILITY ASSESSMENT TOOL")
    print("=" * 45)

    target = input("Enter target IP or domain: ").strip()

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Invalid target.")
        return

    print(f"\nTarget     : {target}")
    print(f"IP Address: {ip}")
    print(f"Scan Time : {datetime.now()}")
    print("-" * 45)

    services = scan_target(target)

    print(f"[+] Open services found: {len(services)}")

    cve_db = load_cve_db()
    findings = check_vulnerabilities(services, cve_db)

    print(f"[+] Vulnerabilities found: {len(findings)}")

    risk = calculate_risk(findings)
    print(f"[+] Overall Risk Level: {risk}")

    generate_pdf(target, ip, services, findings, risk)

    print("\nScan completed successfully.")
    print("=" * 45)

if __name__ == "__main__":
    main()
