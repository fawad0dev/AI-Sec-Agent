#!/usr/bin/env python3
"""
AI-Sec-Agent: Security Automation Agent
A security automation agent with full terminal access for Linux, macOS, and Windows.
"""

import sys
import os
import argparse
import json
import platform
import shutil
import subprocess
import re
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import threading


# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

AGENT_VERSION = "AI-Sec-Agent v1.0"
MAX_OUTPUT_SIZE = 500000  # 500KB
DEFAULT_TIMEOUT = 300  # seconds
MAX_RETRIES = 3

# Dangerous command patterns that require explicit confirmation
DANGEROUS_PATTERNS = [
    r'rm\s+-rf\s+/',
    r'mkfs',
    r'dd\s+if=',
    r'format\s+',
    r'fdisk.*w',
    r'parted.*mkpart',
    r'shutdown',
    r'reboot',
    r'init\s+[06]',
    r'systemctl\s+(halt|poweroff|reboot)',
    r'del\s+/[fF]\s+/[sS]\s+/[qQ]',
    r'diskpart',
]

# Security tools that can be installed
SECURITY_TOOLS = {
    'nmap': {
        'apt': 'nmap',
        'yum': 'nmap',
        'dnf': 'nmap',
        'pacman': 'nmap',
        'brew': 'nmap',
        'choco': 'nmap',
    },
    'nikto': {
        'apt': 'nikto',
        'yum': 'nikto',
        'dnf': 'nikto',
        'brew': 'nikto',
    },
    'gobuster': {
        'apt': 'gobuster',
        'brew': 'gobuster',
    },
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def print_thinking(message: str):
    """Print a thinking/status message."""
    print(f"THINKING: {message}")


def print_result(cmd: str, exit_code: Optional[int], elapsed: float, attempts: int):
    """Print command result summary."""
    print(f"RESULT: cmd='{cmd}' exit={exit_code} time={elapsed:.1f}s attempts={attempts}")


def print_finding(severity: str, title: str, remediation: str):
    """Print a security finding."""
    print(f"FINDING: [{severity}] {title} — {remediation}")


def truncate_output(output: str, max_size: int = MAX_OUTPUT_SIZE) -> str:
    """Truncate output if too large."""
    if len(output) > max_size:
        return output[:max_size] + f"\n... (truncated, {len(output)} bytes total)"
    return output


# ============================================================================
# OS DETECTION AND ENVIRONMENT
# ============================================================================

class OSDetector:
    """Detect operating system and available tools."""
    
    def __init__(self):
        self.os_type = platform.system()
        self.os_version = platform.version()
        self.os_release = platform.release()
        self.distro = None
        self.package_manager = None
        self._detect_distro()
        self._detect_package_manager()
    
    def _detect_distro(self):
        """Detect Linux distribution."""
        if self.os_type != "Linux":
            return
        
        try:
            # Try using /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('ID='):
                            self.distro = line.split('=')[1].strip().strip('"')
                            break
        except Exception:
            pass
    
    def _detect_package_manager(self):
        """Detect available package manager."""
        managers = ['apt-get', 'yum', 'dnf', 'pacman', 'brew', 'choco']
        for mgr in managers:
            if shutil.which(mgr):
                self.package_manager = mgr.replace('-get', '')  # normalize apt-get to apt
                break
    
    def get_info(self) -> Dict[str, Any]:
        """Get OS information as dict."""
        return {
            "os": self.os_type,
            "version": self.os_version,
            "release": self.os_release,
            "distro": self.distro,
            "package_manager": self.package_manager,
            "platform": platform.platform(),
        }
    
    def __str__(self):
        info = self.get_info()
        if info['distro']:
            return f"{info['os']} ({info['distro']}) {info['release']}"
        return f"{info['os']} {info['release']}"


# ============================================================================
# COMMAND EXECUTION WITH STREAMING AND RETRIES
# ============================================================================

class CommandRunner:
    """Execute commands with streaming output, retries, and safety checks."""
    
    def __init__(self, allow_destructive: bool = False):
        self.allow_destructive = allow_destructive
        self.command_history = []
    
    def is_dangerous(self, command: str) -> bool:
        """Check if command matches dangerous patterns."""
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False
    
    def require_confirmation(self, message: str) -> bool:
        """Require explicit YES confirmation."""
        print(f"\n{message}")
        response = input("Type YES to proceed: ").strip()
        return response == "YES"
    
    def run_command(
        self,
        command: str,
        shell: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        cwd: Optional[str] = None,
        env: Optional[Dict] = None,
        stream: bool = True,
        retries: int = 0,
        retry_backoff: float = 2.0,
        require_confirmation: bool = True,
        allow_destructive: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a command with full tracking and safety.
        
        Returns:
            Dict with command execution details including stdout, stderr, exit_code, etc.
        """
        # Safety checks
        if self.is_dangerous(command):
            if not (allow_destructive or self.allow_destructive):
                result = {
                    "id": str(uuid.uuid4()),
                    "command": command,
                    "shell": shell,
                    "blocked": True,
                    "error": "Command blocked: matches dangerous pattern. Use --allow-destructive to override.",
                    "exit_code": None,
                }
                self.command_history.append(result)
                print(f"ERROR: {result['error']}")
                return result
            elif require_confirmation:
                if not self.require_confirmation(
                    f"⚠️  WARNING: This command may be destructive:\n  {command}\n"
                ):
                    result = {
                        "id": str(uuid.uuid4()),
                        "command": command,
                        "shell": shell,
                        "cancelled": True,
                        "exit_code": None,
                    }
                    self.command_history.append(result)
                    return result
        
        # Execute with retries
        attempt_num = 0
        max_attempts = retries + 1
        
        while attempt_num < max_attempts:
            attempt_num += 1
            
            cmd_id = str(uuid.uuid4())
            start_ts = datetime.now().isoformat()
            start_time = time.time()
            
            print_thinking(f"Attempt {attempt_num} running `{command}` (timeout={timeout}s)")
            
            try:
                if stream:
                    # Stream output in real-time
                    process = subprocess.Popen(
                        command,
                        shell=shell,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        cwd=cwd,
                        env=env,
                    )
                    
                    stdout_lines = []
                    stderr_lines = []
                    
                    # Read stdout and stderr
                    def read_stream(stream, prefix, lines_list):
                        for line in stream:
                            print(f"[{prefix}] {line.rstrip()}")
                            lines_list.append(line)
                    
                    # Start threads to read both streams
                    stdout_thread = threading.Thread(
                        target=read_stream, args=(process.stdout, "STDOUT", stdout_lines)
                    )
                    stderr_thread = threading.Thread(
                        target=read_stream, args=(process.stderr, "STDERR", stderr_lines)
                    )
                    
                    stdout_thread.start()
                    stderr_thread.start()
                    
                    # Wait with timeout
                    try:
                        exit_code = process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout_thread.join(timeout=1)
                        stderr_thread.join(timeout=1)
                        
                        elapsed = time.time() - start_time
                        result = {
                            "id": cmd_id,
                            "command": command,
                            "shell": shell,
                            "start_ts": start_ts,
                            "end_ts": datetime.now().isoformat(),
                            "elapsed_seconds": elapsed,
                            "exit_code": None,
                            "timeout": True,
                            "stdout": truncate_output(''.join(stdout_lines)),
                            "stderr": truncate_output(''.join(stderr_lines)),
                            "attempt_number": attempt_num,
                        }
                        self.command_history.append(result)
                        
                        if attempt_num < max_attempts:
                            wait_time = retry_backoff ** (attempt_num - 1)
                            print_thinking(f"Command timed out. Retrying in {wait_time:.1f}s...")
                            time.sleep(wait_time)
                            continue
                        
                        print_result(command, None, elapsed, attempt_num)
                        return result
                    
                    stdout_thread.join()
                    stderr_thread.join()
                    
                    stdout = ''.join(stdout_lines)
                    stderr = ''.join(stderr_lines)
                else:
                    # Non-streaming execution
                    result_obj = subprocess.run(
                        command,
                        shell=shell,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=timeout,
                        cwd=cwd,
                        env=env,
                    )
                    exit_code = result_obj.returncode
                    stdout = result_obj.stdout
                    stderr = result_obj.stderr
                
                elapsed = time.time() - start_time
                
                result = {
                    "id": cmd_id,
                    "command": command,
                    "shell": shell,
                    "start_ts": start_ts,
                    "end_ts": datetime.now().isoformat(),
                    "elapsed_seconds": elapsed,
                    "exit_code": exit_code,
                    "timeout": False,
                    "stdout": truncate_output(stdout),
                    "stderr": truncate_output(stderr),
                    "attempt_number": attempt_num,
                }
                
                self.command_history.append(result)
                print_result(command, exit_code, elapsed, attempt_num)
                
                # Success - no need to retry
                if exit_code == 0:
                    return result
                
                # Non-zero exit - retry if attempts remain
                if attempt_num < max_attempts:
                    wait_time = retry_backoff ** (attempt_num - 1)
                    print_thinking(f"Command failed with exit code {exit_code}. Retrying in {wait_time:.1f}s...")
                    time.sleep(wait_time)
                    continue
                
                return result
                
            except subprocess.TimeoutExpired:
                elapsed = time.time() - start_time
                result = {
                    "id": cmd_id,
                    "command": command,
                    "shell": shell,
                    "start_ts": start_ts,
                    "end_ts": datetime.now().isoformat(),
                    "elapsed_seconds": elapsed,
                    "exit_code": None,
                    "timeout": True,
                    "stdout": "",
                    "stderr": "Command timed out",
                    "attempt_number": attempt_num,
                }
                self.command_history.append(result)
                
                if attempt_num < max_attempts:
                    wait_time = retry_backoff ** (attempt_num - 1)
                    print_thinking(f"Command timed out. Retrying in {wait_time:.1f}s...")
                    time.sleep(wait_time)
                    continue
                
                print_result(command, None, elapsed, attempt_num)
                return result
                
            except Exception as e:
                elapsed = time.time() - start_time
                result = {
                    "id": cmd_id,
                    "command": command,
                    "shell": shell,
                    "start_ts": start_ts,
                    "end_ts": datetime.now().isoformat(),
                    "elapsed_seconds": elapsed,
                    "exit_code": None,
                    "timeout": False,
                    "stdout": "",
                    "stderr": "",
                    "exception": str(e),
                    "attempt_number": attempt_num,
                }
                self.command_history.append(result)
                print_result(command, None, elapsed, attempt_num)
                return result


# ============================================================================
# TOOL INSTALLER
# ============================================================================

class ToolInstaller:
    """Install security tools using appropriate package managers."""
    
    def __init__(self, os_detector: OSDetector, runner: CommandRunner):
        self.os_detector = os_detector
        self.runner = runner
        self.installed_tools = []
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH."""
        return shutil.which(tool_name) is not None
    
    def install_tool(self, tool_name: str, allow_install: bool = True) -> bool:
        """
        Install a security tool.
        
        Returns:
            True if tool is now available, False otherwise
        """
        # Check if already available
        if self.is_tool_available(tool_name):
            print_thinking(f"{tool_name} is already available")
            return True
        
        if not allow_install:
            print_thinking(f"{tool_name} not found and installation not allowed")
            return False
        
        # Get package manager
        pkg_mgr = self.os_detector.package_manager
        if not pkg_mgr:
            print_thinking(f"No package manager detected. Cannot install {tool_name}")
            return False
        
        # Get tool install info
        tool_info = SECURITY_TOOLS.get(tool_name, {})
        package_name = tool_info.get(pkg_mgr)
        
        if not package_name:
            print_thinking(f"{tool_name} not available via {pkg_mgr}")
            return False
        
        # Build install command
        if pkg_mgr == 'apt':
            install_cmd = f"sudo apt-get update && sudo apt-get install -y {package_name}"
        elif pkg_mgr in ['yum', 'dnf']:
            install_cmd = f"sudo {pkg_mgr} install -y {package_name}"
        elif pkg_mgr == 'pacman':
            install_cmd = f"sudo pacman -S --noconfirm {package_name}"
        elif pkg_mgr == 'brew':
            install_cmd = f"brew install {package_name}"
        elif pkg_mgr == 'choco':
            install_cmd = f"choco install {package_name} -y"
        else:
            print_thinking(f"Unknown package manager: {pkg_mgr}")
            return False
        
        print_thinking(f"Installing {tool_name} using {pkg_mgr}...")
        
        result = self.runner.run_command(
            install_cmd,
            timeout=300,
            require_confirmation=False,
            stream=True,
        )
        
        if result.get('exit_code') == 0:
            self.installed_tools.append({
                "tool": tool_name,
                "package_manager": pkg_mgr,
                "success": True,
            })
            print_thinking(f"Successfully installed {tool_name}")
            return True
        else:
            self.installed_tools.append({
                "tool": tool_name,
                "package_manager": pkg_mgr,
                "success": False,
                "error": result.get('stderr', 'Unknown error'),
            })
            print_thinking(f"Failed to install {tool_name}")
            return False


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate structured JSON reports and human summaries."""
    
    def __init__(self, agent_version: str, os_detector: OSDetector):
        self.agent_version = agent_version
        self.os_detector = os_detector
        self.findings = []
        self.actions = []
    
    def add_finding(
        self,
        finding_type: str,
        title: str,
        description: str,
        severity: str,
        evidence: str = "",
        location: str = "",
        suggested_fix: str = "",
        confidence: str = "medium",
    ):
        """Add a security finding."""
        finding = {
            "id": str(uuid.uuid4()),
            "type": finding_type,
            "title": title,
            "description": description,
            "severity": severity,
            "evidence": evidence,
            "location": location,
            "suggested_fix": suggested_fix,
            "confidence": confidence,
        }
        self.findings.append(finding)
        print_finding(severity, title, suggested_fix if suggested_fix else "Review manually")
    
    def add_action(self, action: str, details: str):
        """Add an action to the report."""
        self.actions.append({
            "action": action,
            "details": details,
        })
    
    def generate_report(
        self,
        command_history: List[Dict],
        args: Dict,
    ) -> Dict:
        """Generate complete JSON report."""
        successful = sum(1 for cmd in command_history if cmd.get('exit_code') == 0)
        failed = len(command_history) - successful
        
        report = {
            "metadata": {
                "agent_version": self.agent_version,
                "user": os.getenv('USER', os.getenv('USERNAME', 'unknown')),
                "timestamp": datetime.now().isoformat(),
                "os": self.os_detector.get_info(),
                "cwd": os.getcwd(),
                "args": args,
            },
            "command_history": command_history,
            "findings": self.findings,
            "actions": self.actions,
            "summary": {
                "total_commands": len(command_history),
                "successful_commands": successful,
                "failed_commands": failed,
                "findings_count": len(self.findings),
            },
        }
        
        return report
    
    def save_report(self, report: Dict, output_dir: str = ".") -> str:
        """Save report to JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"report-{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filepath
    
    def print_summary(self, report: Dict, report_path: str):
        """Print human-readable summary."""
        summary = report['summary']
        findings = report['findings']
        
        print("\n" + "=" * 70)
        print(f"REPORT: saved to {report_path}")
        print("=" * 70)
        print(f"\nSummary:")
        print(f"  Total Commands: {summary['total_commands']}")
        print(f"  Successful: {summary['successful_commands']}")
        print(f"  Failed: {summary['failed_commands']}")
        print(f"  Findings: {summary['findings_count']}")
        
        if findings:
            severity_counts = {}
            for finding in findings:
                sev = finding['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            print(f"\nFindings by Severity:")
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if sev in severity_counts:
                    print(f"  {sev.capitalize()}: {severity_counts[sev]}")
            
            print(f"\nTop Findings:")
            for i, finding in enumerate(findings[:5], 1):
                print(f"  {i}. [{finding['severity']}] {finding['title']}")
                if finding['suggested_fix']:
                    print(f"     Fix: {finding['suggested_fix'][:80]}")


# ============================================================================
# SECURITY SCANNERS
# ============================================================================

class LogScanner:
    """Scan system logs for security issues."""
    
    def __init__(self, runner: CommandRunner, report_gen: ReportGenerator, os_detector: OSDetector):
        self.runner = runner
        self.report_gen = report_gen
        self.os_detector = os_detector
    
    def get_log_paths(self) -> List[str]:
        """Get common log file paths based on OS."""
        os_type = self.os_detector.os_type
        
        if os_type == "Linux":
            return [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/secure",
                "/var/log/messages",
            ]
        elif os_type == "Darwin":  # macOS
            return [
                "/var/log/system.log",
                "/var/log/secure.log",
            ]
        elif os_type == "Windows":
            return [
                "C:\\Windows\\System32\\winevt\\Logs",
            ]
        else:
            return []
    
    def scan_logs(self, log_paths: Optional[List[str]] = None):
        """Scan logs for suspicious patterns."""
        print_thinking("Starting log scan...")
        
        if log_paths is None:
            log_paths = self.get_log_paths()
        
        # Patterns to look for
        patterns = {
            "failed_login": r"(failed|failure|invalid user|authentication failure)",
            "privilege_escalation": r"(sudo|su:|gained privileges|elevated)",
            "suspicious_commands": r"(curl.*\||wget.*\||chmod \+x|/tmp/)",
        }
        
        for log_path in log_paths:
            if not os.path.exists(log_path):
                continue
            
            print_thinking(f"Scanning {log_path}...")
            
            # Read last 500 lines
            if self.os_detector.os_type == "Windows":
                # Windows Event Logs need different handling
                continue
            
            try:
                with open(log_path, 'r', errors='ignore') as f:
                    lines = f.readlines()[-500:]
                
                content = ''.join(lines)
                
                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        self.report_gen.add_finding(
                            finding_type="suspicious",
                            title=f"Suspicious pattern in {log_path}: {pattern_name}",
                            description=f"Found {len(matches)} matches for pattern: {pattern_name}",
                            severity="medium",
                            evidence=str(matches[:5]),
                            location=log_path,
                            suggested_fix="Review log entries and investigate suspicious activity",
                        )
            except Exception as e:
                print_thinking(f"Error reading {log_path}: {e}")


class SystemAuditor:
    """Perform comprehensive system security audit."""
    
    def __init__(self, runner: CommandRunner, report_gen: ReportGenerator, os_detector: OSDetector):
        self.runner = runner
        self.report_gen = report_gen
        self.os_detector = os_detector
    
    def audit_system(self):
        """Run complete system audit."""
        print_thinking("Starting system audit...")
        
        self.check_startup_programs()
        self.check_scheduled_tasks()
        self.check_open_ports()
        self.check_user_accounts()
    
    def check_startup_programs(self):
        """Check startup programs/services."""
        print_thinking("Checking startup programs...")
        
        os_type = self.os_detector.os_type
        
        if os_type == "Linux":
            result = self.runner.run_command("systemctl list-unit-files --type=service --state=enabled", stream=False)
            if result.get('exit_code') == 0:
                # Parse and analyze
                output = result.get('stdout', '')
                if 'enabled' in output.lower():
                    self.report_gen.add_finding(
                        finding_type="info",
                        title="Startup services enumerated",
                        description="Successfully enumerated system startup services",
                        severity="info",
                        evidence=output[:500],
                        suggested_fix="Review enabled services for unnecessary or suspicious entries",
                    )
        
        elif os_type == "Darwin":
            result = self.runner.run_command("launchctl list", stream=False)
            if result.get('exit_code') == 0:
                self.report_gen.add_finding(
                    finding_type="info",
                    title="Launch agents/daemons enumerated",
                    description="Successfully enumerated launch agents and daemons",
                    severity="info",
                    evidence=result.get('stdout', '')[:500],
                    suggested_fix="Review launch agents for suspicious entries",
                )
        
        elif os_type == "Windows":
            result = self.runner.run_command("wmic startup get caption,command", stream=False)
            if result.get('exit_code') == 0:
                self.report_gen.add_finding(
                    finding_type="info",
                    title="Startup programs enumerated",
                    description="Successfully enumerated Windows startup programs",
                    severity="info",
                    evidence=result.get('stdout', '')[:500],
                    suggested_fix="Review startup programs for suspicious entries",
                )
    
    def check_scheduled_tasks(self):
        """Check scheduled tasks/cron jobs."""
        print_thinking("Checking scheduled tasks...")
        
        os_type = self.os_detector.os_type
        
        if os_type in ["Linux", "Darwin"]:
            result = self.runner.run_command("crontab -l", stream=False)
            if result.get('exit_code') == 0 and result.get('stdout'):
                self.report_gen.add_finding(
                    finding_type="info",
                    title="User cron jobs found",
                    description="Found cron jobs for current user",
                    severity="info",
                    evidence=result.get('stdout', '')[:500],
                    suggested_fix="Review cron jobs for suspicious commands",
                )
        
        elif os_type == "Windows":
            result = self.runner.run_command("schtasks /query /fo LIST /v", stream=False)
            if result.get('exit_code') == 0:
                self.report_gen.add_finding(
                    finding_type="info",
                    title="Scheduled tasks enumerated",
                    description="Successfully enumerated Windows scheduled tasks",
                    severity="info",
                    evidence=result.get('stdout', '')[:500],
                    suggested_fix="Review scheduled tasks for suspicious entries",
                )
    
    def check_open_ports(self):
        """Check open network ports."""
        print_thinking("Checking open network ports...")
        
        os_type = self.os_detector.os_type
        
        if os_type == "Linux":
            # Try ss first, fallback to netstat
            result = self.runner.run_command("ss -tuln", stream=False)
            if result.get('exit_code') != 0:
                result = self.runner.run_command("netstat -tuln", stream=False)
        elif os_type == "Darwin":
            result = self.runner.run_command("netstat -an | grep LISTEN", stream=False)
        elif os_type == "Windows":
            result = self.runner.run_command("netstat -ano", stream=False)
        else:
            return
        
        if result.get('exit_code') == 0:
            output = result.get('stdout', '')
            # Look for uncommon ports
            lines = output.split('\n')
            uncommon_ports = []
            for line in lines:
                if re.search(r':(\d{4,5})\s', line):
                    uncommon_ports.append(line.strip())
            
            if uncommon_ports:
                self.report_gen.add_finding(
                    finding_type="info",
                    title="Open network ports detected",
                    description=f"Found {len(uncommon_ports)} listening ports",
                    severity="info",
                    evidence='\n'.join(uncommon_ports[:10]),
                    suggested_fix="Review open ports and close unnecessary services",
                )
    
    def check_user_accounts(self):
        """Check user accounts."""
        print_thinking("Checking user accounts...")
        
        os_type = self.os_detector.os_type
        
        if os_type in ["Linux", "Darwin"]:
            result = self.runner.run_command("cat /etc/passwd", stream=False)
            if result.get('exit_code') == 0:
                users = result.get('stdout', '').split('\n')
                # Look for users with UID 0 (root privileges)
                root_users = [u for u in users if re.search(r':0:', u)]
                if len(root_users) > 1:
                    self.report_gen.add_finding(
                        finding_type="vulnerability",
                        title="Multiple users with UID 0 detected",
                        description="Found multiple users with root privileges (UID 0)",
                        severity="high",
                        evidence='\n'.join(root_users),
                        suggested_fix="Review users with UID 0 and remove unnecessary privileged accounts",
                    )
        
        elif os_type == "Windows":
            result = self.runner.run_command("net user", stream=False)
            if result.get('exit_code') == 0:
                self.report_gen.add_finding(
                    finding_type="info",
                    title="User accounts enumerated",
                    description="Successfully enumerated Windows user accounts",
                    severity="info",
                    evidence=result.get('stdout', '')[:500],
                    suggested_fix="Review user accounts and remove unnecessary or suspicious accounts",
                )


# ============================================================================
# MAIN AGENT CLASS
# ============================================================================

class AISecAgent:
    """Main AI Security Agent class."""
    
    def __init__(self, args):
        self.args = args
        self.os_detector = OSDetector()
        self.runner = CommandRunner(allow_destructive=args.allow_destructive)
        self.report_gen = ReportGenerator(AGENT_VERSION, self.os_detector)
        self.installer = ToolInstaller(self.os_detector, self.runner)
        
        # Print environment
        print("\n" + "=" * 70)
        print(f"AI-Sec-Agent {AGENT_VERSION}")
        print("=" * 70)
        print(f"Environment: {self.os_detector}")
        print(f"Package Manager: {self.os_detector.package_manager or 'None detected'}")
        print(f"Working Directory: {os.getcwd()}")
        print("=" * 70 + "\n")
    
    def run(self):
        """Main execution method."""
        try:
            # Execute based on mode
            if self.args.scan_logs:
                self.scan_logs()
            elif self.args.scan_website:
                self.scan_website()
            elif self.args.scan_directory:
                self.scan_directory()
            elif self.args.audit_system:
                self.audit_system()
            elif self.args.command:
                self.run_command()
            else:
                print("Error: No action specified. Use --help for usage.")
                return
            
            # Generate and save report
            report = self.report_gen.generate_report(
                self.runner.command_history,
                vars(self.args)
            )
            
            report_path = self.report_gen.save_report(report, output_dir=self.args.output_dir)
            self.report_gen.print_summary(report, report_path)
            
        except KeyboardInterrupt:
            print("\n\nInterrupted by user.")
            # Still generate report
            report = self.report_gen.generate_report(
                self.runner.command_history,
                vars(self.args)
            )
            report_path = self.report_gen.save_report(report, output_dir=self.args.output_dir)
            print(f"\nPartial report saved to {report_path}")
        except Exception as e:
            print(f"\nError: {e}")
            import traceback
            traceback.print_exc()
    
    def scan_logs(self):
        """Scan system logs."""
        log_paths = self.args.scan_logs if isinstance(self.args.scan_logs, list) else None
        scanner = LogScanner(self.runner, self.report_gen, self.os_detector)
        scanner.scan_logs(log_paths)
    
    def scan_website(self):
        """Scan a website for vulnerabilities."""
        url = self.args.scan_website
        
        # Confirm authorization
        if not self.args.yes:
            if not self.runner.require_confirmation(
                f"⚠️  Legal Notice: Only scan websites you own or have explicit permission to test.\n"
                f"Unauthorized scanning may be illegal.\n"
                f"About to scan: {url}"
            ):
                print("Scan cancelled.")
                return
        
        print_thinking(f"Starting website scan of {url}...")
        
        # Basic header check with curl
        result = self.runner.run_command(f"curl -I {url}", timeout=30, stream=False)
        if result.get('exit_code') == 0:
            headers = result.get('stdout', '')
            
            # Check for security headers
            if 'X-Frame-Options' not in headers:
                self.report_gen.add_finding(
                    finding_type="vulnerability",
                    title="Missing X-Frame-Options header",
                    description="The website does not set X-Frame-Options header",
                    severity="medium",
                    location=url,
                    suggested_fix="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header",
                )
            
            if 'X-Content-Type-Options' not in headers:
                self.report_gen.add_finding(
                    finding_type="vulnerability",
                    title="Missing X-Content-Type-Options header",
                    description="The website does not set X-Content-Type-Options header",
                    severity="low",
                    location=url,
                    suggested_fix="Add 'X-Content-Type-Options: nosniff' header",
                )
        
        # Try nikto if available
        if self.installer.is_tool_available('nikto'):
            print_thinking("Running nikto scan...")
            result = self.runner.run_command(f"nikto -h {url}", timeout=600, stream=True)
        else:
            print_thinking("nikto not available. Run with installation permissions to use more tools.")
    
    def scan_directory(self):
        """Scan a directory for suspicious files."""
        directory = self.args.scan_directory
        
        if not os.path.exists(directory):
            print(f"Error: Directory not found: {directory}")
            return
        
        print_thinking(f"Scanning directory: {directory}")
        
        # Look for suspicious files
        suspicious_patterns = [
            r'\.exe$',  # Executables in wrong places
            r'\.sh$',  # Shell scripts
            r'\.bat$',  # Batch files
            r'\.ps1$',  # PowerShell scripts
        ]
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                for pattern in suspicious_patterns:
                    if re.search(pattern, file, re.IGNORECASE):
                        self.report_gen.add_finding(
                            finding_type="suspicious",
                            title=f"Suspicious file detected: {file}",
                            description=f"Found potentially suspicious file matching pattern: {pattern}",
                            severity="low",
                            location=filepath,
                            suggested_fix="Review file contents and purpose",
                        )
                        break
    
    def audit_system(self):
        """Perform system security audit."""
        auditor = SystemAuditor(self.runner, self.report_gen, self.os_detector)
        auditor.audit_system()
    
    def run_command(self):
        """Run an arbitrary command."""
        command = self.args.command
        
        print_thinking(f"Preparing to run command: {command}")
        
        result = self.runner.run_command(
            command,
            timeout=self.args.timeout,
            stream=True,
            retries=self.args.retries,
            require_confirmation=not self.args.yes,
        )
        
        if result.get('stdout'):
            print("\nCommand output:")
            print(result['stdout'])


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AI-Sec-Agent: Security Automation Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan system logs
  %(prog)s --scan-logs
  
  # Scan a website (requires authorization)
  %(prog)s --scan-website https://example.com
  
  # Scan a directory
  %(prog)s --scan-directory /home/user/downloads
  
  # Audit system security
  %(prog)s --audit-system
  
  # Run arbitrary command
  %(prog)s --command "ps aux" --yes
  
  # Allow destructive operations (use with caution!)
  %(prog)s --command "rm /tmp/testfile" --allow-destructive --yes
        """
    )
    
    # Actions
    action_group = parser.add_argument_group('Actions')
    action_group.add_argument('--scan-logs', nargs='*', metavar='PATH',
                              help='Scan system logs for security issues (optionally specify paths)')
    action_group.add_argument('--scan-website', metavar='URL',
                              help='Scan website for vulnerabilities (requires authorization)')
    action_group.add_argument('--scan-directory', metavar='PATH',
                              help='Scan directory for suspicious files')
    action_group.add_argument('--audit-system', action='store_true',
                              help='Perform comprehensive system security audit')
    action_group.add_argument('--command', metavar='CMD',
                              help='Run arbitrary command')
    
    # Options
    parser.add_argument('--yes', '--non-interactive', action='store_true',
                        help='Skip confirmations (use with caution)')
    parser.add_argument('--allow-destructive', action='store_true',
                        help='Allow commands matching dangerous patterns')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'Command timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--retries', type=int, default=0,
                        help='Number of retries for failed commands (default: 0)')
    parser.add_argument('--output-dir', default='.',
                        help='Output directory for reports (default: current directory)')
    
    args = parser.parse_args()
    
    # Validate that at least one action is specified
    if not any([args.scan_logs is not None, args.scan_website, args.scan_directory, 
                args.audit_system, args.command]):
        parser.print_help()
        sys.exit(1)
    
    # Create and run agent
    agent = AISecAgent(args)
    agent.run()


if __name__ == "__main__":
    main()
