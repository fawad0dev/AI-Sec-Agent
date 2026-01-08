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
current_model = None

MAX_OUTPUT_CHARS = 4000

defaultSystemPrompt="""You are a cybersecurity expert AI assistant specialized in system security analysis. You have access to powerful tools to analyze systems and you MUST use them proactively.

**AVAILABLE TOOLS:**
1. get_system_info - Get OS/CPU/RAM information (params: {})
2. terminal_command - Execute shell commands (params: {"command": "...", "allowed": true})
3. scan_common_logs - Scan and analyze system logs (params: {})
4. system_health_check - Check startup programs, tasks, and network (params: {})

**YOUR WORKFLOW:**
1. When asked to do something, immediately identify which tool to use
2. Execute the tool by outputting ONLY a JSON code block (no explanation before it)
3. After receiving tool results, ALWAYS provide detailed analysis including:
   - Summary of what was found
   - Security concerns or suspicious patterns
   - Specific recommendations and solutions
   - Action items if issues are detected

**TOOL SELECTION GUIDE:**
- "logs", "log files", "read logs", "scan logs" → use scan_common_logs
- "run command", "execute", "check file/directory", "list processes" → use terminal_command
- "system info", "OS details", "CPU", "RAM", "hardware" → use get_system_info
- "startup programs", "scheduled tasks", "network connections" → use system_health_check

**OUTPUT FORMAT FOR TOOL EXECUTION:**
When you need a tool, respond with ONLY this (no other text before or after):
```json
{"tool": "tool_name", "params": {}}
```

**ANALYSIS FORMAT (after receiving tool results):**
Always structure your analysis as:
## Summary
Brief overview of findings

## Key Findings
- Point 1
- Point 2

## Security Assessment
Any concerns or suspicious activity

## Recommendations
Specific actions to take

**CRITICAL RULES:**
- NEVER just explain what you could do - DO IT immediately
- NEVER ask permission to use tools - use them
- ALWAYS analyze results thoroughly - don't just repeat raw data
- ALWAYS provide actionable recommendations
- For log analysis, look for: failed logins, errors, unusual access patterns, privilege escalations
- Remember previous command outputs and build upon them in conversation"""

messages = [{"role": "system", "content": defaultSystemPrompt}]
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

    parts = ["## Log Scan Report"]
    parts.append(f"Found {len(logs)} recent log files for analysis\n")
    
    for idx, entry in enumerate(logs, 1):
        path = entry["path"]
        size = _human_size(entry["size"])
        mtime = entry["mtime"].strftime("%Y-%m-%d %H:%M:%S")
        parts.append(f"### Log File {idx}: {path}")
        parts.append(f"- **Size**: {size}")
        parts.append(f"- **Last Modified**: {mtime}")

        if path.lower().endswith((".log", ".txt")):
            tail = _safe_tail(Path(path))
            if tail:
                parts.append("\n**Content Preview (last 200 lines):**")
                parts.append("```")
                parts.append(tail.strip()[:MAX_OUTPUT_CHARS])
                parts.append("```")
            else:
                parts.append("(empty or unreadable)")
        else:
            parts.append("(binary file - metadata only)")
        parts.append("")  # blank line between logs
    
    parts.append("\n---")
    parts.append("**Analysis Instructions**: Review the logs above for:")
    parts.append("- Authentication failures or suspicious login attempts")
    parts.append("- Error messages or system crashes")
    parts.append("- Unusual access patterns or privilege escalations")
    parts.append("- Resource issues (disk space, memory errors)")
    parts.append("- Security warnings or critical events")
    
    return "\n".join(parts)


def _read_run_key(key_root, subkey):
    if not HAS_WINREG:
        return ["(Registry access not available on this platform)"]
    
    try:
        results = []
        # winreg is guaranteed to be available here due to HAS_WINREG check above
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
    output = utils.run_terminal_command(command, allowed=True)
    if not output:
        return "(no output)"
    return output[:limit]


def build_system_health_report() -> str:
    parts = ["## System Health Check Report"]

    if HAS_WINREG:
        parts.append("\n### Startup Programs (Registry Run Keys)")
        startup = []
        startup.extend(_read_run_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
        startup.extend(_read_run_key(winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
        if startup:
            for item in startup:
                parts.append(f"  - {item}")
        else:
            parts.append("  (no entries found)")
    else:
        parts.append("\n### Startup Programs")
        parts.append("  (Registry access not available on this platform)")

    parts.append("\n### Scheduled Tasks")
    parts.append("```")
    parts.append(_run_cmd_safe("schtasks /query /fo LIST /v"))
    parts.append("```")

    parts.append("\n### Active Network Connections")
    parts.append("```")
    parts.append(_run_cmd_safe("netstat -ano"))
    parts.append("```")

    parts.append("\n### Running Processes")
    parts.append("```")
    parts.append(_run_cmd_safe("tasklist"))
    parts.append("```")

    parts.append("\n---")
    parts.append("**Analysis Instructions**: Review the system health data above for:")
    parts.append("- Unknown or suspicious startup programs")
    parts.append("- Unusual scheduled tasks")
    parts.append("- Unexpected network connections to unknown IPs")
    parts.append("- High resource usage processes")
    parts.append("- Processes with unusual names or locations")
    
    return "\n".join(parts)


def extract_action_payload(text: str):
    
    pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(pattern, text, re.DOTALL)
    
    if match:
        json_str = match.group(1).strip()
        try:
            parsed = json.loads(json_str)
            # Validate it has required structure
            if isinstance(parsed, dict) and "tool" in parsed:
                return parsed
            else:
                print(f"Warning: Parsed JSON but missing 'tool' key: {parsed}")
                return None
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            print(f"Attempted to parse: {json_str[:200]}...")
            return None
    return None


def execute_actions(actions: list) -> list:
    results = []
    for action in actions:
        tool = action.get("tool")
        params = action.get("params", {}) if isinstance(action, dict) else {}
        try:
            """if tool == "read_file":
                result = utils.read_file(params.get("path", ""), params.get("nooflines"), params.get("encoding", "utf-8"))
            elif tool == "write_file":
                result = utils.write_file(params.get("path", ""), params.get("content", ""), params.get("encoding", "utf-8"))
            elif tool == "append_file":
                result = utils.append_file(params.get("path", ""), params.get("content", ""), params.get("encoding", "utf-8"))
            elif tool == "read_registry":
                result = utils.read_Registry(params.get("key", ""), params.get("value_name", ""))
            el"""
            if tool == "get_system_info":
                result = utils.get_system_info()
            elif tool == "terminal_command":
                if params.get("allowed") is True:
                    result = utils.run_terminal_command(params.get("command", ""), allowed=True)
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
    lines = ["## Tool Execution Results\n"]
    for item in results:
        tool_name = item.get('tool', 'unknown')
        lines.append(f"### ✓ Executed: {tool_name}")
        params = item.get('params', {})
        if params:
            lines.append(f"**Parameters**: {params}")
        lines.append("\n**Output**:")
        result_data = item.get("result", "")
        
        # Format result based on type
        if isinstance(result_data, dict):
            try:
                lines.append("```json")
                lines.append(json.dumps(result_data, indent=2, default=str))
                lines.append("```")
            except (TypeError, ValueError) as e:
                # Fallback to string representation if JSON serialization fails
                lines.append("```")
                lines.append(str(result_data))
                lines.append("```")
        elif isinstance(result_data, str):
            # Check if it's already formatted with markdown code blocks
            if "```" in result_data:
                lines.append(result_data)
            else:
                lines.append("```")
                lines.append(result_data)
                lines.append("```")
        else:
            lines.append(str(result_data))
        lines.append("")  # blank line
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

@app.route('/api/get-default-system', methods=['GET'])
def get_default_system_prompt():
    """Get the default system prompt"""
    return jsonify({'prompt': defaultSystemPrompt})

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
        
        if action_payload and isinstance(action_payload, dict):
            print(f"Detected action payload: {action_payload.get('tool')} with params {action_payload.get('params', {})}")
            action_results = execute_actions([action_payload])
            results_text = format_action_results(action_results)
            
            # Add the initial response (which contains the tool request)
            messages.append({"role": "assistant", "content": response_text})
            
            # Add tool results as a user message so the AI can see and analyze them
            analysis_prompt = (
                "Tool execution completed. Here are the results:\n\n"
                f"{results_text}\n\n"
                "Please analyze these results and provide a detailed summary with "
                "security assessment and recommendations."
            )
            messages.append({"role": "user", "content": analysis_prompt})
            
            # Get AI's analysis of the results
            analysis_response = client.chat(current_model, messages)
            messages.append({"role": "assistant", "content": analysis_response})
            
            # Combine everything for the final response to user
            final_response = response_text + "\n\n" + results_text + "\n\n" + analysis_response
        else:
            # No tool execution, just add the response
            messages.append({"role": "assistant", "content": response_text})

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
