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

defaultSystemPrompt="""You are a cybersecurity expert AI assistant specialized in system security analysis. You have access to powerful tools to analyze systems and you MUST use them proactively.

**AVAILABLE TOOLS:**
1. get_system_info - Get OS/CPU/RAM information (params: {})
2. terminal_command - Execute shell commands based on operating system (params: {"command": "...", "allowed": true})

**CRITICAL: YOU MUST USE TOOLS - NEVER MAKE UP INFORMATION**
When a user asks you to run a command, check system info, or perform any action:
1. You MUST use the appropriate tool - DO NOT make up or fabricate responses
2. You MUST output the tool call in JSON format
3. You MUST wait for real tool results before analyzing

**YOUR WORKFLOW:**
1. User asks you to do something → Identify which tool to use
2. Output a JSON code block with the tool call (you can add a brief note before the JSON if needed)
3. Wait for tool results to be provided back to you
4. Analyze the ACTUAL results - never invent or assume what the results might be

**TOOL SELECTION GUIDE:**
- User wants to "run/execute a command", "check file/directory", "list processes", "show network", etc. → use terminal_command
- User asks for "system info", "OS details", "CPU", "RAM", "hardware" → use get_system_info
- ANY command that needs terminal execution → use terminal_command with {"command": "the_actual_command", "allowed": true}

**OUTPUT FORMAT FOR TOOL EXECUTION:**
When you need to use a tool, your response must include a JSON code block like this:
```json
{"tool": "tool_name", "params": {...}}
```

Examples:
- To run "ps aux": ```json\n{"tool": "terminal_command", "params": {"command": "ps aux", "allowed": true}}\n```
- To get system info: ```json\n{"tool": "get_system_info", "params": {}}\n```

**ANALYSIS FORMAT (after receiving tool results):**
Once you receive the actual tool results, structure your analysis as:
## Summary
Brief overview of findings

## Key Findings
- Point 1
- Point 2

## Security Assessment
Any concerns or suspicious activity

## Recommendations
Specific actions to take

**ABSOLUTE RULES - NEVER BREAK THESE:**
- ❌ NEVER make up command outputs or system information
- ❌ NEVER say "here's what the command would show" without running it
- ❌ NEVER fabricate data or pretend you ran a command when you didn't
- ✅ ALWAYS use tools when user requests an action
- ✅ ALWAYS wait for real tool results before providing analysis
- ✅ ALWAYS base your analysis on actual data, not assumptions
- ✅ If you don't have the data yet, use a tool to get it first

Remember: Your job is to ACTUALLY EXECUTE tools and analyze REAL results, not to explain what COULD happen."""

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
            command_keywords = ['run', 'execute', 'check', 'list', 'show', 'get', 'scan', 'find', 
                              'display', 'view', 'analyze', 'monitor', 'test', 'search']
            user_lower = user_message.lower()
            
            # If user is asking for an action but no tool was called, warn them
            if any(keyword in user_lower for keyword in command_keywords):
                print(f"⚠ WARNING: User requested action but AI didn't use any tool!")
                print(f"⚠ User message: {user_message}")
                print(f"⚠ AI response: {response_text[:200]}...")
                
                # Add a note to the response to make it clear
                warning = ("\n\n---\n**⚠️ Note**: The AI responded without using any tools. "
                          "If you expected a command to be executed, please try rephrasing your request "
                          "to be more explicit (e.g., 'run the command ls -la' or 'execute ps aux').")
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
