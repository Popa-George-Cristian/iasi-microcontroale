#!/usr/bin/env python3
"""MCP server that runs commands on a remote Kali Linux VM via SSH."""

import json
import subprocess
import sys

KALI_HOST = "127.0.0.1"  # NAT — connect via localhost port forward
KALI_PORT = 2222  # VirtualBox NAT forwards host 2222 → guest 22
KALI_USER = "kali"

def ssh_run(command, timeout=30):
    """Run command on Kali VM via SSH."""
    ssh_cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes",
        "-i", f"{__import__('os').path.expanduser('~')}/.ssh/kali_vm",
        "-p", str(KALI_PORT),
        f"{KALI_USER}@{KALI_HOST}",
        command
    ]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s", 1
    except Exception as e:
        return str(e), 1

def send(msg):
    data = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(data)}\r\n\r\n{data}")
    sys.stdout.flush()

def recv():
    # Read Content-Length header
    line = ""
    while True:
        ch = sys.stdin.read(1)
        if ch == "":
            return None
        line += ch
        if line.endswith("\r\n\r\n"):
            break
    length = int(line.split(":")[1].strip().split("\r\n")[0])
    body = sys.stdin.read(length)
    return json.loads(body)

def handle_request(req):
    method = req.get("method")
    id = req.get("id")

    if method == "initialize":
        send({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "kali-mcp", "version": "1.0.0"}
            }
        })
    elif method == "notifications/initialized":
        pass  # no response needed
    elif method == "tools/list":
        send({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "tools": [
                    {
                        "name": "kali_exec",
                        "description": "Execute a shell command on the Kali Linux VM. Use for running attack tools (nmap, hping3, hydra, etc), capturing packets, or any shell operation.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "string",
                                    "description": "Shell command to run on Kali"
                                },
                                "timeout": {
                                    "type": "integer",
                                    "description": "Timeout in seconds (default 30)",
                                    "default": 30
                                }
                            },
                            "required": ["command"]
                        }
                    }
                ]
            }
        })
    elif method == "tools/call":
        tool = req["params"]["name"]
        args = req["params"].get("arguments", {})
        if tool == "kali_exec":
            output, code = ssh_run(args["command"], args.get("timeout", 30))
            send({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "content": [{"type": "text", "text": f"Exit code: {code}\n{output}"}]
                }
            })
        else:
            send({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool}"}
            })
    else:
        if id is not None:
            send({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": f"Unknown method: {method}"}
            })

def main():
    while True:
        req = recv()
        if req is None:
            break
        handle_request(req)

if __name__ == "__main__":
    main()
