# AI Security Agent

A cybersecurity-focused AI assistant that can analyze system logs, monitor system health, execute commands, and provide security recommendations. Powered by Ollama for local LLM inference.

## Features

- 🔍 **Log Analysis**: Automatically scan and analyze system logs for security issues
- 🏥 **System Health Monitoring**: Check startup programs, scheduled tasks, and network connections
- 💻 **Command Execution**: Run terminal commands with built-in safety controls
- 🧠 **Persistent Memory**: AI remembers command outputs throughout the conversation
- 📊 **Structured Analysis**: Provides summary, findings, security assessment, and recommendations
- 🔒 **Security-First**: Designed specifically for cybersecurity analysis and threat detection

## Requirements

- Python 3.8+
- Ollama (running locally on port 11434)
- Required Python packages:
  - Flask
  - requests
  - psutil

## Installation

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

## Usage

### Basic Commands

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

## Architecture

```
src/
├── ChatBotGUI.py    # Main Flask app with enhanced AI workflow
├── Agent.py         # Ollama client for LLM communication
├── Utils.py         # System utilities (file I/O, commands, registry)
└── templates/
    └── chat.html    # Web interface
```

## Recent Improvements

### Version 2.0 (Current)

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

**Logs not found:**
- Windows: Checks `C:\Windows\Logs`, `C:\Windows\System32\winevt\Logs`, etc.
- Ensure you have read permissions for log directories

**Commands not executing:**
- Verify `"allowed": true` in command parameters
- Check user permissions for the command

## Contributing

This is an open-source security tool. Contributions welcome for:
- Additional security analysis tools
- Improved threat detection patterns
- Support for more log formats
- Cross-platform enhancements

## License

[Your License Here]

## Acknowledgments

- Powered by Ollama for local LLM inference
- Built with Flask for web interface
- Designed for cybersecurity professionals
