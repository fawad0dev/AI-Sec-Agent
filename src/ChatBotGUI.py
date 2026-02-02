from flask import Flask, render_template, request, jsonify
from Agent import OllamaClient
from Utils import Utils
import threading
import webbrowser
import os
import json
import re
import platform
from pathlib import Path
from datetime import datetime

# Windows registry module is only available on Windows
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

# Cache the OS type to avoid repeated system calls
OS_TYPE = platform.system()

app = Flask(__name__)

# Initialize Ollama client
client = OllamaClient()
utils = Utils()
current_model = None

MAX_OUTPUT_CHARS = 4000

# Analysis prompt used after tool execution
ANALYSIS_PROMPT_TEMPLATE = (
    "Tool execution completed. Here are the results:\n\n"
    "{results}\n\n"
    "Please analyze these results and provide a detailed summary with "
    "security assessment and recommendations."
)

defaultSystemPrompt=f"""You are a cybersecurity expert AI assistant specialized in system security analysis. You have access to powerful tools to analyze systems and you MUST use them proactively.

**DETECTED OPERATING SYSTEM: {OS_TYPE}**

**AVAILABLE TOOLS:**
1. get_system_info - Get OS/CPU/RAM information (params: {{}})
2. terminal_command - Execute ANY shell command (params: {{"command": "...", "allowed": true}})

**CRITICAL: YOU MUST AUTONOMOUSLY DECIDE WHICH COMMANDS TO USE**
When a user asks you to perform ANY security task, YOU decide the appropriate commands:
1. Analyze the user's request and determine what information is needed
2. Choose the RIGHT command(s) for the current OS ({OS_TYPE})
3. Execute the commands using the terminal_command tool
4. Analyze the ACTUAL results

**YOUR AUTONOMOUS DECISION-MAKING:**
You are empowered to run ANY appropriate command to fulfill the user's request. Examples:

**Process & System Monitoring:**
- List processes: {{"tool": "terminal_command", "params": {{"command": "{'tasklist' if OS_TYPE == 'Windows' else 'ps aux'}", "allowed": true}}}}
- Check CPU/Memory: {{"tool": "terminal_command", "params": {{"command": "{'wmic cpu get loadpercentage' if OS_TYPE == 'Windows' else 'top -bn1 | head -20'}", "allowed": true}}}}
- Running services: {{"tool": "terminal_command", "params": {{"command": "{'sc query' if OS_TYPE == 'Windows' else 'systemctl list-units --type=service'}", "allowed": true}}}}

**Network Analysis:**
- Network connections: {{"tool": "terminal_command", "params": {{"command": "{'netstat -ano' if OS_TYPE == 'Windows' else 'netstat -tuln'}", "allowed": true}}}}
- Open ports: {{"tool": "terminal_command", "params": {{"command": "{'netstat -an | findstr LISTEN' if OS_TYPE == 'Windows' else 'ss -tuln'}", "allowed": true}}}}
- Network interfaces: {{"tool": "terminal_command", "params": {{"command": "{'ipconfig /all' if OS_TYPE == 'Windows' else 'ifconfig -a'}", "allowed": true}}}}

**File System & Security:**
- List directory: {{"tool": "terminal_command", "params": {{"command": "{'dir' if OS_TYPE == 'Windows' else 'ls -la'}", "allowed": true}}}}
- Find files: {{"tool": "terminal_command", "params": {{"command": "{'where /r C:\\\\ filename' if OS_TYPE == 'Windows' else 'find / -name filename 2>/dev/null'}", "allowed": true}}}}
- Check permissions: {{"tool": "terminal_command", "params": {{"command": "{'icacls path' if OS_TYPE == 'Windows' else 'ls -l path'}", "allowed": true}}}}

**Log Analysis:**
- System logs: {{"tool": "terminal_command", "params": {{"command": "{'wevtutil qe System /c:50 /f:text' if OS_TYPE == 'Windows' else 'tail -100 /var/log/syslog'}", "allowed": true}}}}
- Auth logs: {{"tool": "terminal_command", "params": {{"command": "{'wevtutil qe Security /c:50 /f:text' if OS_TYPE == 'Windows' else 'tail -100 /var/log/auth.log'}", "allowed": true}}}}

**Startup & Scheduled Tasks:**
- Startup programs: {{"tool": "terminal_command", "params": {{"command": "{'wmic startup get caption,command' if OS_TYPE == 'Windows' else 'systemctl list-unit-files --state=enabled'}", "allowed": true}}}}
- Scheduled tasks: {{"tool": "terminal_command", "params": {{"command": "{'schtasks /query /fo LIST' if OS_TYPE == 'Windows' else 'crontab -l'}", "allowed": true}}}}

**User & Account Information:**
- Current user: {{"tool": "terminal_command", "params": {{"command": "{'whoami' if OS_TYPE == 'Windows' else 'whoami'}", "allowed": true}}}}
- List users: {{"tool": "terminal_command", "params": {{"command": "{'net user' if OS_TYPE == 'Windows' else 'cat /etc/passwd'}", "allowed": true}}}}
- User groups: {{"tool": "terminal_command", "params": {{"command": "{'net localgroup' if OS_TYPE == 'Windows' else 'groups'}", "allowed": true}}}}

**YOUR DECISION-MAKING PROCESS:**
1. User makes a request → Determine what data you need
2. Choose the appropriate command(s) for {OS_TYPE}
3. Execute using: {{"tool": "terminal_command", "params": {{"command": "your_chosen_command", "allowed": true}}}}
4. Analyze the real results and provide insights

**IMPORTANT PRINCIPLES:**
✅ YOU decide which commands to run based on the user's goal
✅ Choose OS-appropriate commands automatically ({OS_TYPE})
✅ Run multiple commands if needed to fully answer the request
✅ Always execute commands rather than describing what they would do
✅ Adapt commands based on what you learn from previous outputs

**OUTPUT FORMAT FOR TOOL EXECUTION:**
```json
{{"tool": "terminal_command", "params": {{"command": "your_chosen_command", "allowed": true}}}}
```

**ANALYSIS FORMAT (after receiving tool results):**
## Summary
Brief overview of findings

## Key Findings
- Point 1
- Point 2

## Security Assessment
Any concerns or suspicious activity

## Recommendations
Specific actions to take

**ABSOLUTE RULES:**
- ❌ NEVER make up command outputs or results
- ❌ NEVER describe what a command would show without running it
- ✅ ALWAYS decide which command(s) to run based on the user's needs
- ✅ ALWAYS use OS-appropriate commands for {OS_TYPE}
- ✅ ALWAYS execute commands and analyze real results
- ✅ Run multiple commands sequentially if needed for complete analysis

Remember: YOU are in control of deciding which commands to run. Be proactive, intelligent, and security-focused in your command selection."""

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


def _run_cmd_safe(command: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    print(f"Executing command: {command}")
    output = utils.run_terminal_command(command, allowed=True)
    if not output:
        return "(no output)"
    return output[:limit]

def extract_action_payload(text: str):
    """
    Extract tool call JSON from AI response.
    Looks for JSON code blocks with 'tool' and 'params' keys.
    """
    # Try to find JSON code block (with or without 'json' language specifier)
    pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(pattern, text, re.DOTALL)
    
    if match:
        json_str = match.group(1).strip()
        try:
            parsed = json.loads(json_str)
            # Validate it has required structure
            if isinstance(parsed, dict) and "tool" in parsed:
                print(f"✓ Successfully extracted tool call: {parsed.get('tool')}")
                return parsed
            else:
                print(f"⚠ Warning: Parsed JSON but missing 'tool' key: {parsed}")
                return None
        except json.JSONDecodeError as e:
            print(f"✗ JSON decode error: {e}")
            print(f"Attempted to parse: {json_str[:200]}...")
            return None
    
    # If no code block found, check if AI is trying to explain instead of execute
    print(f"⚠ No tool call JSON found in response. Response preview: {text[:200]}...")
    return None


def execute_actions(actions: list) -> list:
    results = []
    for action in actions:
        tool = action.get("tool")
        params = action.get("params", {}) if isinstance(action, dict) else {}
        try:
            if tool == "get_system_info":
                result = utils.get_system_info()
            elif tool == "terminal_command":
                if params.get("allowed") is True:
                    result = utils.run_terminal_command(params.get("command", ""), allowed=True)
                else:
                    result = "Blocked: allowed flag not set to true."
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


def _json_serializer(obj):
    """Custom JSON serializer for objects not serializable by default json code"""
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    elif hasattr(obj, '__str__'):
        return str(obj)
    return repr(obj)


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
                lines.append(json.dumps(result_data, indent=2, default=_json_serializer))
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
        print(f"\n{'='*60}")
        print(f"USER MESSAGE: {user_message[:100]}")
        print(f"AI RESPONSE (first 300 chars): {response_text[:300]}")
        print(f"{'='*60}\n")

        # Let the model drive tool choices; parse any declared actions
        action_payload = extract_action_payload(response_text)
        final_response = response_text
        
        if action_payload and isinstance(action_payload, dict):
            print(f"✓ Executing tool: {action_payload.get('tool')} with params {action_payload.get('params', {})}")
            action_results = execute_actions([action_payload])
            results_text = format_action_results(action_results)
            
            # Add the initial response (which contains the tool request)
            messages.append({"role": "assistant", "content": response_text})
            
            # Add tool results as a user message so the AI can see and analyze them
            analysis_prompt = ANALYSIS_PROMPT_TEMPLATE.format(results=results_text)
            messages.append({"role": "user", "content": analysis_prompt})
            
            # Get AI's analysis of the results
            analysis_response = client.chat(current_model, messages)
            messages.append({"role": "assistant", "content": analysis_response})
            
            # Combine everything for the final response to user
            final_response = response_text + "\n\n" + results_text + "\n\n" + analysis_response
        else:
            # Check if the user was asking for a command/action but AI didn't use tools
            # This is a best-effort detection to help users understand why they might not get expected results
            command_keywords = ['run', 'execute', 'check', 'list', 'show', 'get', 'scan', 'find', 
                              'display', 'view', 'analyze', 'monitor', 'test', 'search', 'command']
            user_lower = user_message.lower()
            
            # If user is asking for an action but no tool was called, warn them
            # Note: This may have false positives but helps guide users when AI doesn't follow instructions
            if any(keyword in user_lower for keyword in command_keywords):
                print(f"⚠ WARNING: User requested action but AI didn't use any tool!")
                print(f"⚠ User message: {user_message}")
                print(f"⚠ AI response: {response_text[:200]}...")
                
                # Add a note to the response to make it clear
                # Use OS-appropriate command examples
                example_cmd = "dir" if OS_TYPE == "Windows" else "ls -la"
                example_cmd2 = "tasklist" if OS_TYPE == "Windows" else "ps aux"
                warning = (f"\n\n---\n**⚠️ Note**: The AI responded without using any tools. "
                          f"If you expected a command to be executed, please try rephrasing your request "
                          f"to be more explicit (e.g., 'run the command {example_cmd}' or 'execute {example_cmd2}').")
                final_response = response_text + warning
            
            # No tool execution, just add the response
            messages.append({"role": "assistant", "content": response_text})

        return jsonify({
            'success': True,
            'response': final_response
        })
    except Exception as e:
        print(f"✗ Error in chat endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
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
