import subprocess
import json
import sys
import time
import os
sys.path.insert(0, '/home/projekt')

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage
from tools.msf_tool import metasploit_scan, metasploit_vuln_scan
from rag.rag import store_result, search_results

# ─── LLM SETUP ───────────────────────────────────────────
# Fast model for tool calling
llm_tools = ChatOllama(
    model="llama3.2",
    base_url="http://ollama:11434",
    temperature=0
)

# Larger model for analysis
llm_analysis = ChatOllama(
    model="gpt-oss-safeguard:20b",
    base_url="http://ollama:11434",
    temperature=0
)

# ─── TOOLS ───────────────────────────────────────────────

@tool
def nmap_scan(target: str) -> str:
    """Scan a target with nmap to find open ports and services."""
    print(f"[*] Running nmap on {target}...")
    result = subprocess.run(
        ["nmap", "-sV", "-sC", "--open", target],
        capture_output=True, text=True
    )
    store_result(result.stdout, {"type": "nmap", "target": target})
    return result.stdout

@tool
def nmap_web_scan(target: str) -> str:
    """Run nmap web scripts on a target."""
    print(f"[*] Running nmap web scan on {target}...")
    result = subprocess.run(
        ["nmap", "-sV", "-p", "80,443,3000,8080,8443",
         "--script", "http-title,http-headers,http-methods,http-enum",
         target],
        capture_output=True, text=True
    )
    store_result(result.stdout, {"type": "nmap_web", "target": target})
    return result.stdout

@tool
def burp_scan(target: str) -> str:
    """
    Run Burp Suite scan against a target using proxy method.
    Sends requests through Burp proxy and captures findings.
    """
    print(f"[*] Running Burp Suite scan on {target}...")
    output = []

    # Start Burp in background
    burp_proc = subprocess.Popen(
        ["burpsuite", "--disable-extensions", "--headless=true"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    print("[*] Waiting for Burp to start...")
    time.sleep(15)

    # Probe endpoints through Burp proxy
    endpoints = [
        f"http://{target}:3000",
        f"http://{target}:3000/api/v1/products",
        f"http://{target}:3000/api/v1/users",
        f"http://{target}:3000/rest/user/whoami",
        f"http://{target}:3000/rest/admin/application-configuration",
        f"http://{target}:3000/ftp/",
        f"http://{target}:3000/#/login",
        f"http://{target}:3000/#/search",
    ]

    for endpoint in endpoints:
        result = subprocess.run(
            ["curl", "-s", "-x", "http://127.0.0.1:8080",
             "-k", "--max-time", "10", endpoint],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            output.append(f"Crawled: {endpoint} - OK")
        else:
            output.append(f"Failed: {endpoint}")

    time.sleep(5)
    burp_proc.terminate()

    findings = "\n".join(output)
    store_result(findings, {"type": "burp", "target": target})
    return f"Burp Suite crawl:\n{findings}\nCheck Burp GUI for detailed findings."

@tool
def curl_probe(target: str) -> str:
    """Probe web target endpoints with curl."""
    print(f"[*] Probing {target}...")
    results = []

    checks = [
        (f"http://{target}:3000", "Main page"),
        (f"http://{target}:3000/api/v1/products", "Products API"),
        (f"http://{target}:3000/api/v1/users", "Users API"),
        (f"http://{target}:3000/rest/admin/application-configuration", "Admin config"),
        (f"http://{target}:3000/ftp", "FTP directory"),
        (f"http://{target}:3000/metrics", "Metrics endpoint"),
        (f"http://{target}:3000/rest/user/whoami", "Whoami endpoint"),
        (f"http://{target}:3000/rest/admin/application-version", "App version"),
    ]

    for url, desc in checks:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w",
             "%{http_code} %{size_download} %{content_type}",
             "--max-time", "5", url],
            capture_output=True, text=True
        )
        results.append(f"{desc}: {url} -> {result.stdout.strip()}")

    header_result = subprocess.run(
        ["curl", "-s", "-I", "--max-time", "5", f"http://{target}:3000"],
        capture_output=True, text=True
    )
    results.append(f"\nHTTP Headers:\n{header_result.stdout}")

    output = "\n".join(results)
    store_result(output, {"type": "curl_probe", "target": target})
    return output

@tool
def save_finding(content: str) -> str:
    """Save an important finding for future reference."""
    doc_id = store_result(content, {"type": "finding"})
    return f"Saved with ID: {doc_id}"

@tool
def search_previous_scans(query: str) -> str:
    """Search previous scan results and findings."""
    results = search_results(query)
    if results['documents'] and results['documents'][0]:
        return json.dumps(results['documents'][0], indent=2)
    return "No previous results found"

# ─── TOOLS MAP ───────────────────────────────────────────

tools = [
    nmap_scan,
    nmap_web_scan,
    burp_scan,
    curl_probe,
    metasploit_scan,
    metasploit_vuln_scan,
    save_finding,
    search_previous_scans
]

tools_map = {t.name: t for t in tools}

# ─── HELPER FUNCTIONS ────────────────────────────────────

def run_tool(name: str, target: str = "juiceshop"):
    if name in tools_map:
        print(f"[*] Executing {name} on {target}...")
        result = tools_map[name].invoke({"target": target})
        print(result)
        return result
    return f"Tool {name} not found"

def analyze(content: str) -> str:
    print("[*] Analyzing with AI...")
    response = llm_analysis.invoke(
        f"""You are an expert penetration tester analyzing scan results.

Provide a structured analysis with:
1. Services and ports discovered
2. Vulnerabilities identified
3. Security misconfigurations
4. Recommended next steps
5. Risk rating (Critical/High/Medium/Low)

Results:
{content}"""
    )
    return response.content

def full_recon(target: str = "juiceshop"):
    print(f"\n{'='*50}")
    print(f"Full Reconnaissance on {target}")
    print('='*50)

    print("\n[Phase 1] Port Scanning...")
    nmap = run_tool("nmap_scan", target)

    print("\n[Phase 2] Web Scanning...")
    web = run_tool("nmap_web_scan", target)

    print("\n[Phase 3] Endpoint Probing...")
    probe = run_tool("curl_probe", target)

    print("\n[Phase 4] Metasploit Scanning...")
    msf = run_tool("metasploit_scan", target)

    combined = f"""
=== NMAP SCAN ===
{nmap}

=== WEB SCAN ===
{web}

=== ENDPOINT PROBE ===
{probe}

=== METASPLOIT ===
{msf}
"""
    save_finding.invoke({"content": f"Full recon on {target}:\n{combined}"})

    print("\n" + "="*50)
    print("AI Analysis:")
    print("="*50)
    print(analyze(combined))

def show_help():
    print("""
Commands:
  recon [target]    - Full reconnaissance (all tools)
  scan [target]     - nmap port scan
  web [target]      - nmap web scan
  probe [target]    - curl endpoint probe
  msf [target]      - Metasploit scan
  burp [target]     - Burp Suite scan
  search <query>    - Search previous results
  help              - Show this help
  exit              - Quit

Default target: juiceshop
Examples:
  scan
  recon juiceshop
  search ftp vulnerabilities
    """)

# ─── MAIN LOOP ───────────────────────────────────────────

print("="*50)
print("Pentesting AI Agent v2")
print("Target: juiceshop (OWASP Juice Shop)")
print("Type 'help' for commands")
print("="*50 + "\n")

while True:
    try:
        user_input = input("You: ").strip()
    except KeyboardInterrupt:
        print("\nExiting...")
        break

    if not user_input:
        continue

    parts = user_input.strip().split()
    cmd = parts[0].lower()
    target = parts[1] if len(parts) > 1 else "juiceshop"

    if cmd == "exit":
        break
    elif cmd == "help":
        show_help()
    elif cmd == "recon":
        full_recon(target)
    elif cmd == "scan":
        run_tool("nmap_scan", target)
    elif cmd == "web":
        run_tool("nmap_web_scan", target)
    elif cmd == "probe":
        run_tool("curl_probe", target)
    elif cmd == "msf":
        run_tool("metasploit_scan", target)
    elif cmd == "burp":
        run_tool("burp_scan", target)
    elif cmd == "search":
        query = " ".join(parts[1:]) if len(parts) > 1 else ""
        if query:
            print(search_previous_scans.invoke({"query": query}))
        else:
            print("Please provide a search query")
    elif any(x in user_input.lower() for x in ["nmap", "port", "scan"]):
        run_tool("nmap_scan", "juiceshop")
    elif any(x in user_input.lower() for x in ["metasploit", "msf", "exploit", "vuln"]):
        run_tool("metasploit_scan", "juiceshop")
    elif any(x in user_input.lower() for x in ["burp"]):
        run_tool("burp_scan", "juiceshop")
    elif any(x in user_input.lower() for x in ["recon", "full"]):
        full_recon("juiceshop")
    else:
        print("\n[*] AI Response:")
        response = llm_tools.invoke(
            f"""You are a pentesting assistant for OWASP Juice Shop.
Answer the question or suggest which command to use.
Commands: recon, scan, web, probe, msf, burp, search

Question: {user_input}"""
        )
        print(f"\nAgent: {response.content}\n")
