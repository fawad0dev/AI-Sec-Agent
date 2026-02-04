# Quick Reference: AI Autonomous Commands

## How to Use

Simply describe what you want in natural language. The AI will automatically choose and execute the appropriate commands for your operating system.

## Common Tasks

### Process & System Monitoring

| What to Say | AI Will Execute |
|------------|-----------------|
| "show running processes" | `ps aux` (Linux) / `tasklist` (Windows) |
| "what's using CPU?" | `top -bn1 \| head -20` (Linux) / `wmic cpu get loadpercentage` (Windows) |
| "list services" | `systemctl list-units --type=service` (Linux) / `sc query` (Windows) |
| "check memory usage" | `free -h` (Linux) / `wmic OS get FreePhysicalMemory` (Windows) |

### Network Analysis

| What to Say | AI Will Execute |
|------------|-----------------|
| "show network connections" | `netstat -tuln` (Linux) / `netstat -ano` (Windows) |
| "list open ports" | `ss -tuln` (Linux) / `netstat -an \| findstr LISTEN` (Windows) |
| "show network interfaces" | `ifconfig -a` (Linux) / `ipconfig /all` (Windows) |
| "check firewall status" | `ufw status` (Linux) / `netsh advfirewall show allprofiles` (Windows) |

### File System & Security

| What to Say | AI Will Execute |
|------------|-----------------|
| "list files in directory" | `ls -la` (Linux) / `dir` (Windows) |
| "find suspicious executables" | `find / -name "*.exe" 2>/dev/null` (Linux) / `where /r C:\\ *.exe` (Windows) |
| "check file permissions" | `ls -l path` (Linux) / `icacls path` (Windows) |
| "show hidden files" | `ls -la` (Linux) / `dir /a:h` (Windows) |

### Log Analysis

| What to Say | AI Will Execute |
|------------|-----------------|
| "check system logs" | `tail -100 /var/log/syslog` (Linux) / `wevtutil qe System /c:50 /f:text` (Windows) |
| "show authentication logs" | `tail -100 /var/log/auth.log` (Linux) / `wevtutil qe Security /c:50 /f:text` (Windows) |
| "find failed login attempts" | `grep "Failed" /var/log/auth.log` (Linux) / `wevtutil qe Security /q:"*[EventID=4625]"` (Windows) |

### Startup & Scheduled Tasks

| What to Say | AI Will Execute |
|------------|-----------------|
| "show startup programs" | `systemctl list-unit-files --state=enabled` (Linux) / `wmic startup get caption,command` (Windows) |
| "list scheduled tasks" | `crontab -l` (Linux) / `schtasks /query /fo LIST` (Windows) |
| "check autostart entries" | `cat /etc/rc.local` (Linux) / `reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` (Windows) |

### User & Account Information

| What to Say | AI Will Execute |
|------------|-----------------|
| "who am I" | `whoami` (all OS) |
| "list all users" | `cat /etc/passwd` (Linux) / `net user` (Windows) |
| "show user groups" | `groups` (Linux) / `net localgroup` (Windows) |
| "check sudo privileges" | `sudo -l` (Linux) / `net user %USERNAME%` (Windows) |

## Tips for Best Results

### ✅ DO:
- Use natural language: "show me network connections"
- Be specific about your security goal: "find suspicious startup programs"
- Ask for analysis: "check for unusual processes"
- Request comprehensive checks: "audit the system for security issues"

### ❌ DON'T:
- Specify exact commands: ~~"run ps aux"~~
- Use OS-specific syntax unnecessarily: ~~"execute netstat -ano"~~
- Worry about OS differences: AI handles it automatically

## Example Conversations

### Security Investigation
```
You: "I think something suspicious is running on my system"
AI: Executes: ps aux (or tasklist)
    Analyzes processes for suspicious activity
    Provides security assessment
    
You: "check if there are any unknown network connections"
AI: Executes: netstat -tuln (or netstat -ano)
    Identifies established connections
    Flags any suspicious IPs or ports
```

### System Health Check
```
You: "is my system healthy?"
AI: Executes multiple commands:
    1. Process check
    2. Memory usage
    3. Network connections
    4. Startup programs
    Provides comprehensive health report
```

### Forensics
```
You: "find all recently modified files"
AI: Executes: find / -mtime -1 (or appropriate Windows command)
    Lists recently changed files
    Highlights security-relevant changes
```

## Advanced Usage

### Chaining Requests
The AI remembers context, so you can build on previous results:
```
You: "show running processes"
AI: [Executes and shows processes]

You: "focus on the ones using most CPU"
AI: [Filters results from previous command]

You: "tell me more about PID 1234"
AI: [Executes additional commands for that process]
```

### Multi-Step Analysis
Ask for comprehensive analysis:
```
You: "do a complete security audit"
AI: Autonomously runs:
    - Process enumeration
    - Network connection check
    - Startup program analysis
    - User account review
    - Log analysis
    Provides comprehensive security report
```

## Remember

🤖 The AI is in control - you just describe what you need
🌐 Works across all operating systems automatically
🔐 Security-focused with built-in best practices
📊 Provides analysis, not just raw command output

For more details, see [AUTONOMOUS_COMMANDS.md](AUTONOMOUS_COMMANDS.md)
