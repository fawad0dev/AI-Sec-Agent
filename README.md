# AI Security Agent

A cybersecurity-focused AI assistant that can analyze system logs, monitor system health, execute commands, and provide security recommendations. 

**Two interfaces available:**
1. **Web Interface** (ChatBotGUI.py) - Interactive chat-based AI assistant powered by Ollama for local LLM inference
2. **CLI Agent** (ai_sec_agent.py) - Command-line security automation agent with comprehensive scanning and auditing capabilities

**Cross-Platform Support**: Works on Windows, Linux, and macOS with automatic OS detection and platform-specific commands.

## Quick Start

### Web Interface (AI Chat Assistant)
```bash
cd src
python ChatBotGUI.py
# Opens browser at http://localhost:5000
```

### CLI Agent (Security Automation)
```bash
# System audit
./ai_sec_agent.py --audit-system --yes

# Scan logs
./ai_sec_agent.py --scan-logs --yes

# Scan website
./ai_sec_agent.py --scan-website https://example.com

# Run command with retries
./ai_sec_agent.py --command "ps aux" --yes --retries 3
```

See [AI_SEC_AGENT_CLI.md](AI_SEC_AGENT_CLI.md) for complete CLI documentation.

## Features

### Web Interface Features

- 🔍 **Log Analysis**: Automatically scan and analyze system logs for security issues
- 🏥 **System Health Monitoring**: Check startup programs, scheduled tasks, and network connections
- 💻 **Command Execution**: Run terminal commands with built-in safety controls
- 🧠 **Persistent Memory**: AI remembers command outputs throughout the conversation
- 📊 **Structured Analysis**: Provides summary, findings, security assessment, and recommendations
- 🔒 **Security-First**: Designed specifically for cybersecurity analysis and threat detection
- 🌐 **Cross-Platform**: Automatically detects OS type (Windows, Linux, macOS) and uses appropriate commands

### CLI Agent Features
- 🔐 **Security Scanning**: Log analysis, website scanning, directory scanning, system auditing
- 💻 **Command Execution**: Run arbitrary commands with streaming output, retries, and safety controls
- 📊 **Structured Reporting**: JSON reports with findings, command history, and remediation steps
- 🔒 **Safety First**: Dangerous command blocking, explicit confirmations, legal reminders
- 🛠️ **Tool Management**: Auto-install security tools (nmap, nikto, etc.) using OS package managers
- 🔍 **Full Transparency**: Real-time "THINKING" statements and command output streaming

## Requirements

### Web Interface Requirements

### Web Interface Requirements
- Python 3.8+
- Ollama (running locally on port 11434)
- Required Python packages:
  - Flask
  - requests
  - psutil
- **Supported Operating Systems**: Windows, Linux, macOS

### CLI Agent Requirements
- Python 3.7+
- Standard library only (no external dependencies)
- **Supported Operating Systems**: Windows, Linux, macOS
- Optional: Security tools (nmap, nikto, gobuster) - can be auto-installed

## Installation

### Option 1: Web Interface Setup

### Option 1: Web Interface Setup

Follow these steps to get the AI Security Agent running from clone to chat:

### 1. Clone the Repository

```bash
git clone https://github.com/fawad0dev/AI-Sec-Agent.git
cd AI-Sec-Agent
```

### 2. Install Ollama

Download and install Ollama from https://ollama.ai/

Verify Ollama is running:
```bash
ollama serve
```

### 3. Pull an AI Model

Download a model (e.g., llama2, mistral, codellama):
```bash
ollama pull llama2
```

### 4. Install Python Dependencies

Install required Python packages using pip:
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install flask requests psutil
```

### 5. Run the Application

Navigate to the src directory and start the Flask application:
```bash
cd src
python ChatBotGUI.py
```

### 6. Start Chatting

The application will automatically open in your browser at http://localhost:5000

You can now interact with the AI Security Agent! Try commands like:
- "scan the last 100 logs"
- "check system health"
- "show system information"

### Option 2: CLI Agent Setup

No installation needed! Just make the script executable:

```bash
chmod +x ai_sec_agent.py

# Run security audit
./ai_sec_agent.py --audit-system --yes

# Get help
./ai_sec_agent.py --help
```

For complete CLI documentation, see [AI_SEC_AGENT_CLI.md](AI_SEC_AGENT_CLI.md).

## Usage

### Web Interface Usage

### Web Interface Usage

#### Basic Commands

**Scan Logs:**
```
User: scan the last 100 logs
AI: [Executes scan_common_logs immediately and provides analysis]
```

**System Health Check:**
```
User: check system health
AI: [Scans startup programs, tasks, network connections, and analyzes]
```

**Run Commands:**
```
User: list running processes
AI: [Executes appropriate terminal command and analyzes output]
```

**Get System Info:**
```
User: show system information
AI: [Retrieves OS, CPU, RAM details]
```

### AI Capabilities

The AI assistant will:
1. ✅ **Act immediately** - No asking for permission, just does it
2. ✅ **Remember context** - References previous command outputs
3. ✅ **Analyze thoroughly** - Provides security insights, not just raw data
4. ✅ **Give recommendations** - Actionable steps to address issues
5. ✅ **Structure responses** - Consistent format: Summary → Findings → Assessment → Recommendations

## Available Tools

1. **scan_common_logs** - Scans system logs for security issues
   - Looks for: failed logins, errors, unusual access patterns, privilege escalations
   
2. **system_health_check** - Comprehensive system health analysis
   - Checks: startup programs, scheduled tasks, network connections, running processes
   
3. **terminal_command** - Execute shell commands
   - Parameters: `{"command": "your_command", "allowed": true}`
   
4. **get_system_info** - System information
   - Returns: OS, version, CPU, RAM, network status

### CLI Agent Usage

#### Quick Examples

**Scan System Logs:**
```bash
./ai_sec_agent.py --scan-logs --yes
```

**Audit System Security:**
```bash
./ai_sec_agent.py --audit-system --yes
```

**Scan Website:**
```bash
./ai_sec_agent.py --scan-website https://example.com
```

**Run Commands with Retries:**
```bash
./ai_sec_agent.py --command "curl https://api.example.com" --yes --retries 3 --timeout 10
```

For complete CLI documentation and all options, see [AI_SEC_AGENT_CLI.md](AI_SEC_AGENT_CLI.md).

## Architecture

## Architecture

### Web Interface Architecture
```
src/
├── ChatBotGUI.py    # Main Flask app with enhanced AI workflow
├── Agent.py         # Ollama client for LLM communication
├── Utils.py         # System utilities (file I/O, commands, registry)
└── templates/
    └── chat.html    # Web interface
```

### CLI Agent Architecture
```
ai_sec_agent.py      # Standalone CLI security automation agent
├── OSDetector       # OS and environment detection
├── CommandRunner    # Command execution with streaming/retries
├── ToolInstaller    # Security tool installation
├── ReportGenerator  # JSON reports and summaries
├── LogScanner       # Log file analysis
└── SystemAuditor    # System security auditing
```

## Recent Improvements

### Version 2.2 (Current)

**New CLI Security Automation Agent:**

1. **Standalone Security Agent** - Complete CLI tool for security automation
   - Run arbitrary commands with full safety controls
   - Automatic OS detection and tool installation
   - Comprehensive JSON reporting with findings
   
2. **Security Scanning Capabilities**
   - Log scanning for suspicious patterns
   - Website vulnerability scanning
   - Directory scanning for suspicious files
   - System security auditing
   
3. **Advanced Execution Features**
   - Real-time command output streaming
   - Retry logic with exponential backoff
   - Dangerous command blocking with override options
   - Full command history tracking with timestamps

4. **Transparency and Safety**
   - "THINKING" statements showing agent decisions
   - Explicit consent prompts for dangerous operations
   - Legal reminders for network scanning
   - Comprehensive audit trail in JSON reports

### Version 2.1

**Enhanced tool execution and reliability:**

1. **Improved AI Instruction** - Strengthened system prompt to prevent hallucination
   - Explicit "NEVER make up information" directives
   - Clear examples of when and how to use tools
   - Stronger enforcement of tool usage for commands

2. **Better Debugging** - Enhanced logging and error detection
   - Console logging shows when tools are/aren't being used
   - Detection of when AI fails to use tools for action requests
   - User-facing warnings when AI responds without tool execution

3. **Cross-Platform Fixes** - Improved compatibility
   - Fixed winreg import issues on non-Windows platforms
   - Better OS detection and platform-specific behavior

### Version 2.0

**Major enhancements to AI behavior and analysis capabilities:**

1. **Conversation Memory** - AI now remembers tool outputs across the conversation
   - Tool results stored as user messages for AI to reference
   - Enables multi-turn troubleshooting and analysis

2. **Automatic Analysis** - AI analyzes tool results automatically
   - No manual follow-up needed
   - Structured output with security insights

3. **Proactive Behavior** - AI acts immediately instead of asking permission
   - Enhanced system prompt with explicit action directives
   - Clear workflow: Identify → Execute → Analyze

4. **Enhanced Log Analysis** - Log scanning now provides meaningful insights
   - Analysis instructions guide AI to identify security concerns
   - Looks for failed logins, errors, privilege escalations, unusual patterns

## Security Considerations

⚠️ **Important Security Notes:**

- Commands require `"allowed": true` flag to execute
- Runs with privileges of the executing user
- Review commands before allowing execution in production
- Log scanning is read-only by default
- Designed for security analysis, not system modification

## Configuration

### System Prompt Customization

You can customize the AI's behavior by modifying the system prompt in the web interface. The default prompt emphasizes:
- Proactive tool usage
- Thorough analysis
- Security-focused insights
- Structured, actionable output

### Model Selection

Select different Ollama models from the dropdown:
- `llama2` - General purpose, good balance
- `mistral` - Fast and efficient
- `codellama` - Better for technical analysis
- Custom models - Any model pulled via Ollama

## Troubleshooting

**Ollama not available:**
- Ensure Ollama is running: `ollama serve`
- Check Ollama is accessible at http://localhost:11434

**No models available:**
- Pull a model: `ollama pull llama2`
- Refresh the models list in the web interface

**AI is making up information instead of running commands:**
- Check the browser console (F12) for debug output showing tool execution
- Look for messages like "✓ Successfully extracted tool call" or "⚠ No tool call JSON found"
- If you see warnings that no tool was used, try rephrasing your request more explicitly:
  - Instead of: "what processes are running?"
  - Try: "run the command to list all processes" or "execute ps aux"
- Make sure the system prompt hasn't been changed - reset it using the "Set System Prompt" button with the default prompt
- Some AI models are better at following instructions than others - try using `mistral` or `llama2` if available

**Logs not found:**
- **Windows**: Checks `C:\Windows\Logs`, `C:\Windows\System32\winevt\Logs`, etc.
- **Linux**: Checks `/var/log`, `/var/log/syslog`, `/var/log/auth.log`, etc.
- **macOS**: Checks `/var/log`, `/Library/Logs`, `~/Library/Logs`, etc.
- Ensure you have read permissions for log directories

**Commands not executing:**
- Verify `"allowed": true` in command parameters
- Check user permissions for the command
- The system automatically detects your OS and uses appropriate commands
- Check the console output for error messages

## Cross-Platform Support

The AI Security Agent automatically detects your operating system and uses platform-specific commands:

**Windows**:
- Registry-based startup programs
- `schtasks` for scheduled tasks
- `netstat -ano` for network connections
- `tasklist` for running processes

**Linux**:
- `systemctl` for startup services
- `crontab` for scheduled tasks
- `netstat -tuln` or `ss -tuln` for network connections
- `ps aux` for running processes

**macOS**:
- `launchctl` for launch agents/daemons
- `crontab` for scheduled tasks
- `netstat -tuln` for network connections
- `ps aux` for running processes

## Contributing

This is an open-source security tool. Contributions welcome for:
- Additional security analysis tools
- Improved threat detection patterns
- Support for more log formats
- Cross-platform enhancements

## Acknowledgments

- Powered by Ollama for local LLM inference
- Built with Flask for web interface
- Designed for cybersecurity professionals
