import json
import re
import os
import sys
import uuid
from datetime import datetime
from collections import Counter, defaultdict
sys.path.insert(0, '/home/projekt')
from rag.rag import store_result, scan_collection, already_ingested

def strip_ansi(text):
    return re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])').sub('', text)

# ─── STRUCTURED LOG INGESTION (log1.txt - log5.txt) ──────

def ingest_structured_log(filepath):
    """Ingest new structured format logs with [SOURCE] [ACTION] tags."""
    filename = os.path.basename(filepath)

    if already_ingested(filename):
        print(f"  [*] Skipping {filename} - already ingested")
        return {"nmap_hosts": {}, "vuln_endpoints": [],
                "burp_actions": defaultdict(list), "headers": []}

    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()

    lines = content.splitlines()
    nmap_lines = [l for l in lines if '[SOURCE: Nmap]' in l]
    burp_lines = [l for l in lines if '[SOURCE: Burp Suite]' in l]
    msf_lines  = [l for l in lines if '[SOURCE: Metasploit]' in l]

    # Nmap
    nmap_hosts = {}
    services = defaultdict(list)
    for l in nmap_lines:
        host = re.search(r'Host: ([\d.]+)', l)
        ports = re.search(r'Ports: (.+)', l)
        if host and ports:
            nmap_hosts[host.group(1)] = ports.group(1).strip()
            port_info = ports.group(1)
            if 'Node.js' in port_info or '3000' in port_info:
                services['nodejs'].append(f"{host.group(1)}: {port_info}")
            elif 'ssh' in port_info.lower():
                services['ssh'].append(f"{host.group(1)}: {port_info}")
            elif 'mysql' in port_info.lower() or 'mariadb' in port_info.lower():
                services['database'].append(f"{host.group(1)}: {port_info}")
            elif 'http' in port_info.lower():
                services['web'].append(f"{host.group(1)}: {port_info}")

    # Burp
    burp_actions = defaultdict(list)
    for l in burp_lines:
        action = re.search(r'\[ACTION: ([^\]]+)\]', l)
        endpoint = re.search(r'(?:GET|POST|PUT|DELETE|OPTIONS) (/\S*)', l)
        if action and endpoint:
            burp_actions[action.group(1)].append(endpoint.group(1))

    security_actions = ['AUTH_ATTEMPT', 'ATTACK_PROBE', 'FUZZING',
                       'CONFIG_EXTRACT', 'DIR_ENUM', 'BYPASS_PROBE',
                       'ACCOUNT_MOD']
    security_findings = []
    for action in security_actions:
        if action in burp_actions:
            security_findings.append(
                f"{action} ({len(burp_actions[action])}x):\n" +
                '\n'.join([f"  - {e}" for e in sorted(set(burp_actions[action]))]))

    # Metasploit
    msf_vulns = [l for l in msf_lines if 'VULN_FOUND' in l]
    msf_enums = [l for l in msf_lines if '[ACTION: ENUM]' in l]
    msf_fails = [l for l in msf_lines if '[ACTION: FAIL]' in l]

    vuln_endpoints = []
    for l in msf_vulns:
        url = re.search(r'Found (http://\S+)', l)
        if url:
            vuln_endpoints.append(url.group(1))

    headers_found = []
    for l in msf_enums:
        header = re.search(r'\[\+\] [\d.:]+\s*:\s*(.+)', l)
        if header:
            headers_found.append(header.group(1).strip())

    failed_modules = []
    for l in msf_fails:
        mod = re.search(r'Failed to load module: (\S+)', l)
        if mod:
            failed_modules.append(mod.group(1))

    summary = f"""STRUCTURED PENTEST LOG: {filename}
Ingested: {datetime.now().isoformat()}
Total entries: {len(lines)}

=== STATISTICS ===
Nmap: {len(nmap_lines)} entries, {len(nmap_hosts)} hosts
Burp Suite: {len(burp_lines)} entries
Metasploit: {len(msf_lines)} entries, {len(vuln_endpoints)} vulnerabilities

=== NMAP HOSTS ({len(nmap_hosts)}) ===
Node.js/3000 ({len(services['nodejs'])}): {chr(10).join(services['nodejs'][:10])}
SSH ({len(services['ssh'])}): {chr(10).join(services['ssh'][:5])}
Database ({len(services['database'])}): {chr(10).join(services['database'][:5])}
Web ({len(services['web'])}): {chr(10).join(services['web'][:5])}

=== BURP SUITE SECURITY FINDINGS ===
{chr(10).join(security_findings) if security_findings else 'None identified'}

=== BURP SUITE ALL ACTIONS ===
{chr(10).join([f"{a} ({len(e)}x): {', '.join(sorted(set(e))[:5])}"
               for a, e in sorted(burp_actions.items())])}

=== METASPLOIT VULNERABLE ENDPOINTS ({len(vuln_endpoints)}) ===
{chr(10).join(sorted(set(vuln_endpoints)))}

=== HTTP HEADERS DISCOVERED ===
{chr(10).join(sorted(set(headers_found)))}

=== FAILED MODULES ===
{chr(10).join(sorted(set(failed_modules)))}

=== RAW LOG ===
{content}"""

    doc_id = store_result(summary, {
        "type": "structured_pentest_log",
        "source": filename,
        "target": "juiceshop",
        "nmap_hosts": str(len(nmap_hosts)),
        "msf_vulns": str(len(vuln_endpoints))
    })
    print(f"  [+] {filename}: {len(nmap_hosts)} hosts, "
          f"{len(vuln_endpoints)} vulns -> {doc_id[:8]}")

    return {
        "nmap_hosts": nmap_hosts,
        "vuln_endpoints": vuln_endpoints,
        "burp_actions": burp_actions,
        "headers": headers_found
    }

# ─── LEGACY MSF LOG (cycle*.txt) ─────────────────────────

def ingest_msf_log(filepath):
    filename = os.path.basename(filepath)

    if already_ingested(filename):
        print(f"  [*] Skipping {filename} - already ingested")
        return []

    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
    clean = strip_ansi(content)

    findings = re.findall(r'\[\+\].*', clean)
    errors   = re.findall(r'\[-\].*', clean)
    info     = re.findall(r'\[\*\].*', clean)

    summary = f"""METASPLOIT CYCLE LOG: {filename}
Ingested: {datetime.now().isoformat()}

=== FINDINGS ({len(findings)}) ===
{chr(10).join(findings)}

=== INFO ===
{chr(10).join(info)}

=== ERRORS ===
{chr(10).join(errors)}

=== FULL LOG ===
{clean}"""

    doc_id = store_result(summary, {
        "type": "metasploit_cycle",
        "source": filename,
        "target": "juiceshop",
        "findings_count": str(len(findings))
    })
    print(f"  [+] {filename}: {len(findings)} findings -> {doc_id[:8]}")
    return findings

# ─── BURP URL LIST ────────────────────────────────────────

def ingest_burp_urls(filepath):
    filename = os.path.basename(filepath)

    if already_ingested(filename):
        print(f"  [*] Skipping {filename} - already ingested")
        return

    with open(filepath, 'r', errors='ignore') as f:
        urls = [l.strip() for l in f if l.strip()]

    juice_urls = [u for u in urls if '127.0.0.1:3000' in u or 'juiceshop' in u]
    api_urls   = [u for u in juice_urls if '/api/' in u]
    rest_urls  = [u for u in juice_urls if '/rest/' in u]
    ftp_urls   = [u for u in juice_urls if '/ftp/' in u]
    admin_urls = [u for u in juice_urls if '/admin' in u]

    security_findings = []
    if admin_urls:
        security_findings.append(f"EXPOSED ADMIN ({len(admin_urls)}):")
        security_findings += [f"  - {u}" for u in sorted(set(admin_urls))]
    if ftp_urls:
        security_findings.append(f"EXPOSED FTP ({len(ftp_urls)} paths)")
    if [u for u in juice_urls if "'" in u or 'union' in u.lower()]:
        security_findings.append("SQL INJECTION PROBE detected")

    summary = f"""BURP SUITE URL DISCOVERY: {filename}
Ingested: {datetime.now().isoformat()}
Total URLs: {len(juice_urls)}

=== SECURITY FINDINGS ===
{chr(10).join(security_findings) if security_findings else 'None'}

=== API ENDPOINTS ({len(api_urls)}) ===
{chr(10).join(sorted(set(api_urls)))}

=== REST ENDPOINTS ({len(rest_urls)}) ===
{chr(10).join(sorted(set(rest_urls)))}

=== FTP ENDPOINTS ({len(ftp_urls)}) ===
{chr(10).join(sorted(set(ftp_urls)))}

=== ALL ENDPOINTS ===
{chr(10).join(sorted(set(juice_urls)))}"""

    doc_id = store_result(summary, {
        "type": "burp_urls",
        "source": filename,
        "target": "juiceshop",
        "url_count": str(len(juice_urls))
    })
    print(f"  [+] {filename}: {len(juice_urls)} URLs -> {doc_id[:8]}")

# ─── NETWORK JSON ─────────────────────────────────────────

def ingest_network_json(filepath):
    filename = os.path.basename(filepath)

    if already_ingested(filename):
        print(f"  [*] Skipping {filename} - already ingested")
        return

    print(f"  [*] Loading {filename}...")
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()

    arrays = re.split(r'\n\]\n\[', content)
    arrays[0] = arrays[0] + '\n]'
    for i in range(1, len(arrays) - 1):
        arrays[i] = '[' + arrays[i] + '\n]'
    arrays[-1] = '[' + arrays[-1]

    all_packets = []
    dates = set()
    for arr in arrays:
        try:
            data = json.loads(arr)
            all_packets.extend(data)
            for p in data:
                idx = p.get('_index', '')
                if idx:
                    dates.add(idx.replace('packets-', ''))
        except Exception as e:
            print(f"  [!] Parse error: {e}")

    print(f"  [*] Parsed {len(all_packets)} packets")

    src_ips   = Counter()
    dst_ips   = Counter()
    http_uris = Counter()
    uri_by_src = defaultdict(set)

    for p in all_packets:
        layers = p.get('_source', {}).get('layers', {})
        src = layers.get('ip.src', [''])[0]
        dst = layers.get('ip.dst', [''])[0]
        uri = layers.get('http.request.uri', [''])[0]

        if src: src_ips[src] += 1
        if dst: dst_ips[dst] += 1
        if uri and uri != '*':
            http_uris[uri] += 1
            if src: uri_by_src[src].add(uri)

    attacker = src_ips.most_common(1)[0][0] if src_ips else "unknown"
    sensitive = [u for u in http_uris if any(x in u for x in
        ['/admin', '/ftp', 'passwd', 'sql', 'union', '../', 'whoami'])]

    summary = f"""NETWORK CAPTURE: {filename}
Dates: {', '.join(sorted(dates))}
Ingested: {datetime.now().isoformat()}
Packets: {len(all_packets)}
Unique URIs: {len(http_uris)}
Main IP: {attacker}

=== SENSITIVE ENDPOINTS ===
{chr(10).join([f"  {http_uris[u]}x {u}" for u in sensitive]) if sensitive else 'None'}

=== TOP HTTP URIS ===
{chr(10).join([f"  {c:4d}x {u}" for u, c in http_uris.most_common(50)])}

=== TOP SOURCE IPs ===
{chr(10).join([f"  {c:5d}x {ip}" for ip, c in src_ips.most_common(10)])}"""

    doc_id = store_result(summary, {
        "type": "network_capture",
        "source": filename,
        "packet_count": str(len(all_packets)),
        "uri_count": str(len(http_uris))
    })
    print(f"  [+] {filename}: {len(all_packets)} packets -> {doc_id[:8]}")

# ─── MAIN ────────────────────────────────────────────────

def ingest_all(dirpath):
    if not scan_collection:
        print("[!] ChromaDB not connected!")
        return

    files = os.listdir(dirpath)
    structured = sorted([f for f in files if f.startswith('log') and f.endswith('.txt')])
    cycles     = sorted([f for f in files if 'cycle' in f.lower() and f.endswith('.txt')])
    burp_files = [f for f in files if 'burp' in f.lower() and f.endswith('.txt')]
    json_files = [f for f in files if f.endswith('.json')]

    print(f"\n[*] Files found:")
    print(f"    {len(structured)} structured logs")
    print(f"    {len(cycles)} cycle logs")
    print(f"    {len(burp_files)} Burp URL files")
    print(f"    {len(json_files)} JSON files\n")

    all_hosts = {}
    all_vulns = []

    if structured:
        print("[*] Ingesting structured logs...")
        for f in structured:
            r = ingest_structured_log(os.path.join(dirpath, f))
            all_hosts.update(r['nmap_hosts'])
            all_vulns.extend(r['vuln_endpoints'])

    all_findings = []
    if cycles:
        print("\n[*] Ingesting cycle logs...")
        for f in cycles:
            all_findings.extend(ingest_msf_log(os.path.join(dirpath, f)))

    if burp_files:
        print("\n[*] Ingesting Burp URL files...")
        for f in burp_files:
            ingest_burp_urls(os.path.join(dirpath, f))

    if json_files:
        print("\n[*] Ingesting network JSON...")
        for f in json_files:
            ingest_network_json(os.path.join(dirpath, f))

    # Master summary
    if all_hosts or all_vulns:
        master = f"""MASTER PENTEST SUMMARY - OWASP JUICE SHOP
Generated: {datetime.now().isoformat()}

=== ALL HOSTS ({len(all_hosts)}) ===
{chr(10).join([f"{ip}: {info}" for ip, info in sorted(all_hosts.items())])}

=== ALL VULNERABLE ENDPOINTS ({len(set(all_vulns))}) ===
{chr(10).join(sorted(set(all_vulns)))}

=== CRITICAL SECURITY FINDINGS ===
- FTP directory exposed at /ftp/ (200 OK)
- Admin config at /rest/admin/application-configuration
- API errors at /api/ (500)
- Restricted endpoint at /restricted/ (500)
- CORS misconfiguration: Access-Control-Allow-Origin: *
- X-Powered-By: Express (information disclosure)
- Authentication endpoint at /rest/user/login"""

        store_result(master, {
            "type": "master_summary",
            "target": "juiceshop"
        })
        print(f"\n[+] Master summary stored")

    print("\n[*] Done! Search with:")
    print("    search ftp vulnerability")
    print("    search admin endpoints")
    print("    search authentication")
    print("    search metasploit findings")

log_dir = sys.argv[1] if len(sys.argv) > 1 else "/home/projekt/logs"
print(f"[*] Ingesting from: {log_dir}")
print(f"[*] ChromaDB: {'Connected' if scan_collection else 'NOT CONNECTED'}")
ingest_all(log_dir)
