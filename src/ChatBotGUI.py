from flask import Flask, render_template, request, jsonify
from Agent import OllamaClient
from Utils import Utils
import threading
import webbrowser
import os
import json
import re
from pathlib import Path
from datetime import datetime

# Windows registry module is only available on Windows
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

app = Flask(__name__)

# Initialize Ollama client
client = OllamaClient()
utils = Utils()
messages = []
current_model = None

MAX_OUTPUT_CHARS = 4000


def _human_size(num_bytes: float) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


def _safe_tail(path: Path, max_lines: int = 200, max_bytes: int = 2_000_000) -> str:
    try:
        if not path.exists() or not path.is_file():
            return ""
        if path.stat().st_size > max_bytes:
            return "(skipped content: file too large)"
        return utils.read_file(str(path), nooflines=max_lines)
    except Exception as exc:  # pragma: no cover
        return f"(error reading file: {exc})"


def _collect_logs() -> list:
    log_dirs = [
        Path(r"C:\\Windows\\Logs"),
        Path(r"C:\\Windows\\System32\\winevt\\Logs"),
        Path(r"C:\\Windows\\Temp"),
        Path(os.getenv("ProgramData", r"C:\\ProgramData")),
        Path.home() / "AppData/Local/Temp",
    ]

    found = []
    for base in log_dirs:
        if not base.exists():
            continue
        for root, _, files in os.walk(base):
            for name in files:
                path = Path(root) / name
                try:
                    info = path.stat()
                    found.append({
                        "path": str(path),
                        "size": info.st_size,
                        "mtime": datetime.fromtimestamp(info.st_mtime),
                    })
                except OSError:
                    continue
    found.sort(key=lambda x: x["mtime"], reverse=True)
    return found[:8]


def build_log_scan_report() -> str:
    logs = _collect_logs()
    if not logs:
        return "No logs found in standard locations."

    parts = ["## Quick Log Scan (read-only)"]
    for entry in logs:
        path = entry["path"]
        size = _human_size(entry["size"])
        mtime = entry["mtime"].strftime("%Y-%m-%d %H:%M:%S")
        parts.append(f"### {path}\n- Size: {size}\n- Modified: {mtime}")

        if path.lower().endswith((".log", ".txt")):
            tail = _safe_tail(Path(path))
            if tail:
                parts.append("```")
                parts.append(tail.strip()[:MAX_OUTPUT_CHARS])
                parts.append("```")
        else:
            parts.append("(binary or non-text log; metadata only)")
    return "\n".join(parts)


def _read_run_key(key_root, subkey):
    if not HAS_WINREG:
        return ["(Registry access not available on this platform)"]
    
    try:
        results = []
        with winreg.OpenKey(key_root, subkey) as k:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, index)
                    results.append(f"{name} => {value}")
                    index += 1
                except OSError:
                    break
        return results
    except Exception as exc:  # pragma: no cover
        return [f"(error reading {subkey}: {exc})"]


def _run_cmd_safe(command: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    output = utils.run_shell_command(command, allowed=True)
    if not output:
        return "(no output)"
    return output[:limit]


def build_system_health_report() -> str:
    parts = ["## Quick System Health Check (read-only)"]

    if HAS_WINREG:
        parts.append("### Startup (Run keys)")
        startup = []
        startup.extend(_read_run_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
        startup.extend(_read_run_key(winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
        parts.append("\n".join(startup) if startup else "(no entries)")
    else:
        parts.append("### Startup (Run keys)")
        parts.append("(Registry access not available on this platform)")

    parts.append("### Scheduled Tasks (summary)")
    parts.append(_run_cmd_safe("schtasks /query /fo LIST /v"))

    parts.append("### Network Connections (netstat -ano)")
    parts.append(_run_cmd_safe("netstat -ano"))

    parts.append("### Running Processes (tasklist)")
    parts.append(_run_cmd_safe("tasklist"))

    parts.append("### Notes\nRead-only checks completed. No changes were made.")
    return "\n\n".join(parts)


def extract_action_payload(text: str):
    """Extract the first JSON object containing actions from fenced code or raw text."""
    fences = re.findall(r"```(?:agent|json)?\s*({.*?})\s*```", text, re.DOTALL)
    candidates = fences + [text]
    for block in candidates:
        try:
            obj = json.loads(block)
            if isinstance(obj, dict) and "actions" in obj:
                return obj
        except Exception:
            continue
    return None


def execute_actions(actions: list) -> list:
    results = []
    for action in actions:
        tool = action.get("tool")
        params = action.get("params", {}) if isinstance(action, dict) else {}
        try:
            if tool == "read_file":
                result = utils.read_file(params.get("path", ""), params.get("nooflines"), params.get("encoding", "utf-8"))
            elif tool == "write_file":
                result = utils.write_file(params.get("path", ""), params.get("content", ""), params.get("encoding", "utf-8"))
            elif tool == "append_file":
                result = utils.append_file(params.get("path", ""), params.get("content", ""), params.get("encoding", "utf-8"))
            elif tool == "read_registry":
                result = utils.read_Registry(params.get("key", ""), params.get("value_name", ""))
            elif tool == "run_shell_command":
                if params.get("allowed") is True:
                    result = utils.run_shell_command(params.get("command", ""), allowed=True)
                else:
                    result = "Blocked: allowed flag not set to true."
            elif tool == "scan_common_logs":
                result = build_log_scan_report()
            elif tool == "system_health_check":
                result = build_system_health_report()
            else:
                result = f"Unknown tool: {tool}"
        except Exception as exc:  # pragma: no cover
            result = f"Error running {tool}: {exc}"

        # Truncate overly long outputs for safety
        if isinstance(result, str) and len(result) > MAX_OUTPUT_CHARS:
            result = result[:MAX_OUTPUT_CHARS] + "... (truncated)"

        results.append({
            "tool": tool,
            "params": params,
            "result": result
        })
    return results


def format_action_results(results: list) -> str:
    if not results:
        return ""
    lines = ["## Tool Results"]
    for item in results:
        lines.append(f"### {item.get('tool', 'unknown')}")
        lines.append(f"Params: {item.get('params', {})}")
        lines.append("Result:")
        lines.append("```")
        lines.append(str(item.get("result", "")))
        lines.append("```")
    return "\n".join(lines)

@app.route('/')
def index():
    return render_template('chat.html')

@app.route('/api/status', methods=['GET'])
def check_status():
    """Check Ollama availability and get models"""
    available = client.is_available()
    models = []
    if available:
        models_data = client.list_models()
        models = [model.get('name', '') for model in models_data]
    return jsonify({
        'available': available,
        'models': models
    })

@app.route('/api/set-model', methods=['POST'])
def set_model():
    """Set the current model"""
    global current_model
    data = request.json
    current_model = data.get('model')
    return jsonify({'success': True, 'model': current_model})

@app.route('/api/set-system', methods=['POST'])
def set_system_prompt():
    """Set system prompt and reset conversation"""
    global messages
    data = request.json
    system_prompt = data.get('prompt', '')
    if system_prompt:
        messages = [{"role": "system", "content": system_prompt}]
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Empty prompt'})

@app.route('/api/clear', methods=['POST'])
def clear_chat():
    """Clear chat history but keep system prompt"""
    global messages
    if messages and messages[0].get("role") == "system":
        messages = [messages[0]]
    else:
        messages = []
    return jsonify({'success': True})

@app.route('/api/chat', methods=['POST'])
def chat():
    """Send message and get response"""
    global messages, current_model
    
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'error': 'Empty message'}), 400
    
    if not current_model:
        return jsonify({'error': 'No model selected'}), 400
    
    # Add user message
    messages.append({"role": "user", "content": user_message})
    
    try:
        # Get response from Ollama
        response_text = client.chat(current_model, messages)

        # Let the model drive tool choices; parse any declared actions
        action_payload = extract_action_payload(response_text)
        final_response = response_text

        if action_payload:
            actions = action_payload.get("actions", []) if isinstance(action_payload, dict) else []
            results = execute_actions(actions)
            action_report = format_action_results(results)
            user_facing = action_payload.get("message") or response_text
            final_response = f"{user_facing}\n\n{action_report}" if action_report else user_facing

        # Add assistant response
        messages.append({"role": "assistant", "content": final_response})

        return jsonify({
            'success': True,
            'response': final_response
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def open_browser():
    """Open browser after a short delay"""
    import time
    time.sleep(1.5)
    webbrowser.open('http://localhost:5000')

def main():
    # Create templates directory if it doesn't exist
    templates_dir = Path(__file__).parent / 'templates'
    templates_dir.mkdir(exist_ok=True)
    
    # Open browser in a separate thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    print("🚀 Starting AI Security Agent Chat...")
    print("🌐 Opening browser at http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    
    app.run(debug=False, port=5000)

if __name__ == "__main__":
    main()
