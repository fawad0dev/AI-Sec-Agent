# AI-Sec-Agent CLI - Security Automation Agent

A comprehensive security automation agent with full terminal access for Linux, macOS, and Windows. This agent can perform security-oriented tasks including log scanning, website scanning, directory checks, system auditing, and arbitrary command execution with full transparency and safety controls.

## Features

### Core Capabilities
- **OS Detection**: Automatically detects operating system, distribution, and package managers
- **Tool Installation**: Bootstraps required security tools (nmap, nikto, gobuster, etc.) using appropriate package managers
- **Command Execution**: Runs arbitrary commands with streaming output, retries, and full tracking
- **Safety Controls**: Built-in denylist for dangerous commands with explicit confirmation requirements
- **Comprehensive Reporting**: Generates both machine-readable JSON reports and human-friendly summaries
- **Transparency**: Streams "THINKING" statements and command outputs in real-time

### Security Features
- **Log Scanning**: Scan system logs for suspicious patterns (failed logins, privilege escalation, suspicious commands)
- **Website Scanning**: Check websites for security vulnerabilities (missing headers, etc.)
- **Directory Scanning**: Recursively scan directories for suspicious files
- **System Auditing**: Comprehensive security audit (startup programs, scheduled tasks, open ports, user accounts)
- **Safety First**: Requires explicit confirmation for destructive operations

### Execution Features
- **Streaming Output**: Real-time stdout/stderr display with prefixes
- **Retry Logic**: Configurable retry attempts with exponential backoff
- **Timeout Control**: Per-command timeout settings
- **Command History**: Full tracking of all commands with timestamps, exit codes, and output
- **Error Handling**: Graceful handling of failures with detailed error messages

## Installation

### Requirements
- Python 3.7+
- Standard library modules only (no external dependencies for core functionality)

### Setup
```bash
# Make the script executable
chmod +x ai_sec_agent.py

# Run directly
./ai_sec_agent.py --help

# Or run with Python
python3 ai_sec_agent.py --help
```

## Usage

### Basic Commands

#### Scan System Logs
```bash
# Scan common system log locations
./ai_sec_agent.py --scan-logs --yes

# Scan specific log files
./ai_sec_agent.py --scan-logs /var/log/auth.log /var/log/syslog --yes
```

#### Scan a Website
```bash
# Scan a website (requires authorization!)
./ai_sec_agent.py --scan-website https://example.com

# Non-interactive mode
./ai_sec_agent.py --scan-website https://example.com --yes
```

#### Scan a Directory
```bash
# Scan for suspicious files
./ai_sec_agent.py --scan-directory /home/user/downloads --yes
```

#### System Audit
```bash
# Comprehensive system security audit
./ai_sec_agent.py --audit-system --yes
```

#### Run Arbitrary Command
```bash
# Run a simple command
./ai_sec_agent.py --command "ls -la" --yes

# Run with retries
./ai_sec_agent.py --command "curl https://example.com" --yes --retries 3 --timeout 10

# Run a potentially destructive command (requires explicit flag)
./ai_sec_agent.py --command "rm /tmp/testfile" --allow-destructive --yes
```

### Command-Line Options

```
Actions:
  --scan-logs [PATH ...]       Scan system logs for security issues
  --scan-website URL           Scan website for vulnerabilities (requires authorization)
  --scan-directory PATH        Scan directory for suspicious files
  --audit-system               Perform comprehensive system security audit
  --command CMD                Run arbitrary command

Options:
  --yes, --non-interactive     Skip confirmations (use with caution)
  --allow-destructive          Allow commands matching dangerous patterns
  --timeout TIMEOUT            Command timeout in seconds (default: 300)
  --retries RETRIES            Number of retries for failed commands (default: 0)
  --output-dir OUTPUT_DIR      Output directory for reports (default: current directory)
```

## Output Format

### Console Output
The agent provides real-time console output with structured messages:

```
THINKING: <status message>
[STDOUT] <command output line>
[STDERR] <command error line>
RESULT: cmd='<command>' exit=<code> time=<seconds>s attempts=<n>
FINDING: [<severity>] <title> — <remediation>
REPORT: saved to <path> — Summary: <findings summary>
```

### JSON Report
Every execution generates a comprehensive JSON report with:

```json
{
  "metadata": {
    "agent_version": "AI-Sec-Agent v1.0",
    "user": "username",
    "timestamp": "2026-02-02T17:30:00.000000",
    "os": { "os": "Linux", "distro": "ubuntu", "package_manager": "apt" },
    "cwd": "/current/working/directory",
    "args": { "command": "...", "timeout": 300 }
  },
  "command_history": [
    {
      "id": "uuid",
      "command": "full command string",
      "start_ts": "ISO8601 timestamp",
      "end_ts": "ISO8601 timestamp",
      "elapsed_seconds": 1.23,
      "exit_code": 0,
      "timeout": false,
      "stdout": "captured output",
      "stderr": "captured errors",
      "attempt_number": 1
    }
  ],
  "findings": [
    {
      "id": "uuid",
      "type": "vulnerability|suspicious|info",
      "title": "Short title",
      "description": "Detailed description",
      "severity": "critical|high|medium|low|info",
      "evidence": "Supporting evidence",
      "location": "file path or URL",
      "suggested_fix": "Concrete remediation steps",
      "confidence": "low|medium|high"
    }
  ],
  "actions": [
    {
      "action": "installed_tool|tried_command|escalation_suggested",
      "details": "Details about the action"
    }
  ],
  "summary": {
    "total_commands": 5,
    "successful_commands": 4,
    "failed_commands": 1,
    "findings_count": 3
  }
}
```

## Safety Features

### Dangerous Pattern Blocking
The agent blocks obviously dangerous commands by default:
- `rm -rf /` - Recursive force delete of root
- `mkfs` - Filesystem creation
- `dd if=` - Direct disk write
- `format` - Disk formatting
- `shutdown`, `reboot` - System shutdown/reboot
- And more...

To override, use `--allow-destructive` flag (still requires interactive confirmation unless using `--yes`).

### Confirmation Prompts
For potentially dangerous operations, the agent requires explicit `YES` confirmation:
- Network-facing operations (website scans)
- Destructive commands (when using --allow-destructive)
- System-modifying actions

### Legal and Ethical Reminders
- Network scanning requires explicit authorization
- Only scan systems and websites you own or have permission to test
- Unauthorized scanning may be illegal

## Examples

### Example 1: Complete System Audit
```bash
./ai_sec_agent.py --audit-system --yes --output-dir ./reports
```

Output:
```
THINKING: Starting system audit...
THINKING: Checking startup programs...
RESULT: cmd='systemctl list-unit-files...' exit=0 time=0.8s attempts=1
FINDING: [info] Startup services enumerated — Review enabled services...
THINKING: Checking scheduled tasks...
THINKING: Checking open network ports...
FINDING: [info] Open network ports detected — Review open ports...
THINKING: Checking user accounts...
REPORT: saved to ./reports/report-20260202-173000.json — Summary: 2 findings (0 critical)
```

### Example 2: Website Security Scan
```bash
./ai_sec_agent.py --scan-website https://example.com
```

Output:
```
⚠️  Legal Notice: Only scan websites you own or have explicit permission to test.
Unauthorized scanning may be illegal.
About to scan: https://example.com
Type YES to proceed: YES

THINKING: Starting website scan of https://example.com...
THINKING: Attempt 1 running `curl -I https://example.com` (timeout=30s)
[STDOUT] HTTP/1.1 200 OK
[STDOUT] Content-Type: text/html
RESULT: cmd='curl -I https://example.com' exit=0 time=0.5s attempts=1
FINDING: [medium] Missing X-Frame-Options header — Add 'X-Frame-Options: DENY' header
FINDING: [low] Missing X-Content-Type-Options header — Add 'X-Content-Type-Options: nosniff' header
```

### Example 3: Command Execution with Retries
```bash
./ai_sec_agent.py --command "curl -f https://unreliable-api.com/data" --yes --retries 3 --timeout 10
```

Output:
```
THINKING: Attempt 1 running `curl -f https://unreliable-api.com/data` (timeout=10s)
RESULT: cmd='curl -f https://unreliable-api.com/data' exit=22 time=0.3s attempts=1
THINKING: Command failed with exit code 22. Retrying in 1.0s...
THINKING: Attempt 2 running `curl -f https://unreliable-api.com/data` (timeout=10s)
RESULT: cmd='curl -f https://unreliable-api.com/data' exit=0 time=0.5s attempts=2
```

## Architecture

The agent is organized into modular components:

- **OSDetector**: Detects operating system, distribution, and package managers
- **CommandRunner**: Executes commands with streaming, retries, and safety checks
- **ToolInstaller**: Installs security tools using appropriate package managers
- **ReportGenerator**: Generates structured JSON reports and human summaries
- **LogScanner**: Scans system logs for security issues
- **SystemAuditor**: Performs comprehensive system security audits
- **AISecAgent**: Main orchestration class

## Supported Platforms

- **Linux**: Ubuntu, Debian, Fedora, CentOS, Arch, and other distributions
- **macOS**: All modern versions
- **Windows**: Windows 10/11 (with appropriate tools)

### Package Managers Supported
- apt (Debian/Ubuntu)
- yum/dnf (Fedora/CentOS/RHEL)
- pacman (Arch Linux)
- brew (macOS)
- choco (Windows)

## Security Considerations

⚠️ **Important Notes:**
- This tool provides extensive system access - use responsibly
- Always review commands before allowing execution
- Network scanning requires legal authorization
- Keep detailed logs for compliance and auditing
- Use `--yes` flag carefully - it bypasses safety confirmations
- The agent logs all commands and outputs for full transparency

## Contributing

This is an open-source security tool. Contributions welcome for:
- Additional security scanning modules
- Support for more security tools
- Enhanced pattern detection
- Cross-platform improvements
- Bug fixes and optimizations

## License

This tool is part of the AI-Sec-Agent project. See main repository for license details.

## Acknowledgments

Built with security best practices in mind:
- Transparent operation with full logging
- Safety-first approach with confirmation prompts
- Comprehensive reporting for compliance
- Modular design for easy extension
