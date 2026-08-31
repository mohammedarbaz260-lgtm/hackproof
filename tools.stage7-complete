import subprocess

SAFE_COMMANDS = {
    "whoami": ["whoami"],
    "hostname": ["hostname"],
    "pwd": ["pwd"],
    "list files": ["ls", "-la"],
    "network interfaces": ["ip", "addr"],
    "list listening ports": ["ss", "-tuln"],
}

TOOL_DESCRIPTIONS = {
    "whoami": "Show the current user.",
    "hostname": "Show the system hostname.",
    "pwd": "Show the current working directory.",
    "list files": "List files in the current directory.",
    "network interfaces": "Show network interface information.",
    "list listening ports": "Show listening network sockets.",
}


def run_safe_tool(tool_name):
    if tool_name not in SAFE_COMMANDS:
        return "Tool not allowed."

    try:
        result = subprocess.run(
            SAFE_COMMANDS[tool_name],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return result.stderr.strip()

        return result.stdout.strip()

    except Exception as e:
        return f"Tool error: {e}"
