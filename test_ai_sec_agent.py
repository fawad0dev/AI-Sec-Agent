#!/usr/bin/env python3
"""
Test suite for AI-Sec-Agent CLI
Tests core functionality without requiring external tools or root privileges.
"""

import unittest
import sys
import os
import json
import tempfile
import time
from pathlib import Path

# Add parent directory to path to import ai_sec_agent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the agent modules
from ai_sec_agent import (
    OSDetector,
    CommandRunner,
    ToolInstaller,
    ReportGenerator,
    LogScanner,
    SystemAuditor,
    AISecAgent,
)


class TestOSDetector(unittest.TestCase):
    """Test OS detection functionality."""
    
    def test_os_detection(self):
        """Test that OS is detected correctly."""
        detector = OSDetector()
        self.assertIsNotNone(detector.os_type)
        self.assertIn(detector.os_type, ['Linux', 'Darwin', 'Windows'])
    
    def test_get_info(self):
        """Test getting OS information."""
        detector = OSDetector()
        info = detector.get_info()
        self.assertIsInstance(info, dict)
        self.assertIn('os', info)
        self.assertIn('version', info)
        self.assertIn('platform', info)
    
    def test_str_representation(self):
        """Test string representation of OS."""
        detector = OSDetector()
        os_str = str(detector)
        self.assertIsInstance(os_str, str)
        self.assertTrue(len(os_str) > 0)


class TestCommandRunner(unittest.TestCase):
    """Test command execution functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.runner = CommandRunner(allow_destructive=False)
    
    def test_simple_command_success(self):
        """Test executing a simple successful command."""
        result = self.runner.run_command(
            "echo 'test'",
            stream=False,
            require_confirmation=False
        )
        self.assertEqual(result['exit_code'], 0)
        self.assertIn('test', result['stdout'])
        self.assertEqual(result['attempt_number'], 1)
    
    def test_command_with_error(self):
        """Test executing a command that fails."""
        result = self.runner.run_command(
            "exit 1",
            stream=False,
            require_confirmation=False
        )
        self.assertEqual(result['exit_code'], 1)
        self.assertEqual(result['attempt_number'], 1)
    
    def test_dangerous_command_blocked(self):
        """Test that dangerous commands are blocked."""
        result = self.runner.run_command(
            "rm -rf /",
            require_confirmation=False
        )
        self.assertTrue(result.get('blocked', False))
        self.assertIn('blocked', result.get('error', '').lower())
    
    def test_command_with_retries(self):
        """Test command execution with retries."""
        result = self.runner.run_command(
            "exit 1",
            stream=False,
            retries=2,
            require_confirmation=False,
            retry_backoff=0.1  # Fast retries for testing
        )
        # Should have tried 3 times (initial + 2 retries)
        self.assertEqual(result['attempt_number'], 3)
    
    def test_command_timeout(self):
        """Test command timeout."""
        result = self.runner.run_command(
            "sleep 10",
            timeout=1,
            stream=False,
            require_confirmation=False
        )
        self.assertTrue(result.get('timeout', False))
    
    def test_command_history_tracking(self):
        """Test that command history is tracked."""
        self.runner.run_command("echo 'test1'", stream=False, require_confirmation=False)
        self.runner.run_command("echo 'test2'", stream=False, require_confirmation=False)
        self.assertEqual(len(self.runner.command_history), 2)
    
    def test_is_dangerous_patterns(self):
        """Test dangerous pattern detection."""
        self.assertTrue(self.runner.is_dangerous("rm -rf /"))
        self.assertTrue(self.runner.is_dangerous("mkfs.ext4 /dev/sda"))
        self.assertTrue(self.runner.is_dangerous("shutdown now"))
        self.assertFalse(self.runner.is_dangerous("ls -la"))
        self.assertFalse(self.runner.is_dangerous("ps aux"))


class TestToolInstaller(unittest.TestCase):
    """Test tool installation functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.os_detector = OSDetector()
        self.runner = CommandRunner(allow_destructive=False)
        self.installer = ToolInstaller(self.os_detector, self.runner)
    
    def test_is_tool_available(self):
        """Test checking if a tool is available."""
        # These should be available on most systems
        self.assertTrue(self.installer.is_tool_available('echo'))
        self.assertTrue(self.installer.is_tool_available('ls'))
        # This should not be available
        self.assertFalse(self.installer.is_tool_available('nonexistent_tool_xyz123'))


class TestReportGenerator(unittest.TestCase):
    """Test report generation functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.os_detector = OSDetector()
        self.report_gen = ReportGenerator("Test v1.0", self.os_detector)
    
    def test_add_finding(self):
        """Test adding a security finding."""
        self.report_gen.add_finding(
            finding_type="vulnerability",
            title="Test Vulnerability",
            description="Test description",
            severity="high",
            evidence="test evidence",
            location="/test/path",
            suggested_fix="Fix it",
        )
        self.assertEqual(len(self.report_gen.findings), 1)
        finding = self.report_gen.findings[0]
        self.assertEqual(finding['title'], "Test Vulnerability")
        self.assertEqual(finding['severity'], "high")
    
    def test_add_action(self):
        """Test adding an action."""
        self.report_gen.add_action("test_action", "test details")
        self.assertEqual(len(self.report_gen.actions), 1)
    
    def test_generate_report(self):
        """Test generating a complete report."""
        # Add some test data
        self.report_gen.add_finding(
            finding_type="info",
            title="Test Finding",
            description="Test",
            severity="low",
        )
        
        command_history = [
            {
                "id": "test-id",
                "command": "echo test",
                "exit_code": 0,
                "stdout": "test",
                "stderr": "",
            }
        ]
        
        report = self.report_gen.generate_report(
            command_history,
            {"test": "args"}
        )
        
        self.assertIn('metadata', report)
        self.assertIn('command_history', report)
        self.assertIn('findings', report)
        self.assertIn('actions', report)
        self.assertIn('summary', report)
        
        self.assertEqual(report['summary']['total_commands'], 1)
        self.assertEqual(report['summary']['findings_count'], 1)
    
    def test_save_report(self):
        """Test saving report to file."""
        report = self.report_gen.generate_report([], {})
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = self.report_gen.save_report(report, output_dir=tmpdir)
            self.assertTrue(os.path.exists(filepath))
            
            # Verify it's valid JSON
            with open(filepath, 'r') as f:
                loaded_report = json.load(f)
            self.assertIsInstance(loaded_report, dict)
            self.assertIn('metadata', loaded_report)


class TestLogScanner(unittest.TestCase):
    """Test log scanning functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.os_detector = OSDetector()
        self.runner = CommandRunner(allow_destructive=False)
        self.report_gen = ReportGenerator("Test v1.0", self.os_detector)
        self.scanner = LogScanner(self.runner, self.report_gen, self.os_detector)
    
    def test_get_log_paths(self):
        """Test getting log file paths."""
        log_paths = self.scanner.get_log_paths()
        self.assertIsInstance(log_paths, list)
        if self.os_detector.os_type == "Linux":
            self.assertTrue(any('/var/log' in path for path in log_paths))
    
    def test_scan_logs_with_test_file(self):
        """Test scanning a log file."""
        # Create a temporary log file with suspicious content
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("Jan 1 00:00:00 test sshd[1234]: Failed password for invalid user admin\n")
            f.write("Jan 1 00:00:01 test sshd[1234]: Failed password for invalid user root\n")
            f.write("Jan 1 00:00:02 test sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root\n")
            log_path = f.name
        
        try:
            initial_findings = len(self.report_gen.findings)
            self.scanner.scan_logs([log_path])
            # Should have found some suspicious patterns
            self.assertGreater(len(self.report_gen.findings), initial_findings)
        finally:
            os.unlink(log_path)


class TestSystemAuditor(unittest.TestCase):
    """Test system auditing functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.os_detector = OSDetector()
        self.runner = CommandRunner(allow_destructive=False)
        self.report_gen = ReportGenerator("Test v1.0", self.os_detector)
        self.auditor = SystemAuditor(self.runner, self.report_gen, self.os_detector)
    
    def test_check_startup_programs(self):
        """Test checking startup programs."""
        initial_findings = len(self.report_gen.findings)
        self.auditor.check_startup_programs()
        # Should have attempted to check startup programs
        self.assertGreater(len(self.runner.command_history), 0)
    
    def test_check_open_ports(self):
        """Test checking open network ports."""
        initial_history = len(self.runner.command_history)
        self.auditor.check_open_ports()
        # Should have attempted to check ports
        self.assertGreater(len(self.runner.command_history), initial_history)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows."""
    
    def test_simple_command_workflow(self):
        """Test a complete simple command workflow."""
        # Create a mock args object
        class Args:
            command = "echo 'integration test'"
            scan_logs = None
            scan_website = None
            scan_directory = None
            audit_system = False
            yes = True
            allow_destructive = False
            timeout = 10
            retries = 0
            output_dir = tempfile.gettempdir()
        
        agent = AISecAgent(Args())
        
        # Run the command
        agent.run_command()
        
        # Verify command was executed
        self.assertGreater(len(agent.runner.command_history), 0)
        self.assertEqual(agent.runner.command_history[0]['exit_code'], 0)
    
    def test_directory_scan_workflow(self):
        """Test directory scanning workflow."""
        # Create a temporary directory with test files
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            test_sh = os.path.join(tmpdir, "test.sh")
            test_txt = os.path.join(tmpdir, "test.txt")
            
            with open(test_sh, 'w') as f:
                f.write("#!/bin/bash\necho test\n")
            with open(test_txt, 'w') as f:
                f.write("normal text file\n")
            
            # Create mock args
            class Args:
                command = None
                scan_logs = None
                scan_website = None
                scan_directory = tmpdir
                audit_system = False
                yes = True
                allow_destructive = False
                timeout = 10
                retries = 0
                output_dir = tempfile.gettempdir()
            
            agent = AISecAgent(Args())
            agent.scan_directory()
            
            # Should have found the .sh file
            self.assertGreater(len(agent.report_gen.findings), 0)
            sh_findings = [f for f in agent.report_gen.findings if 'test.sh' in f.get('location', '')]
            self.assertGreater(len(sh_findings), 0)


class TestSafety(unittest.TestCase):
    """Test safety features."""
    
    def test_dangerous_patterns_comprehensive(self):
        """Test comprehensive dangerous pattern detection."""
        runner = CommandRunner(allow_destructive=False)
        
        dangerous_commands = [
            "rm -rf /",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            "format c:",
            "shutdown -h now",
            "reboot",
            "init 0",
        ]
        
        for cmd in dangerous_commands:
            result = runner.run_command(cmd, require_confirmation=False)
            self.assertTrue(
                result.get('blocked', False) or result.get('cancelled', False),
                f"Command should be blocked: {cmd}"
            )
    
    def test_safe_commands_allowed(self):
        """Test that safe commands are allowed."""
        runner = CommandRunner(allow_destructive=False)
        
        safe_commands = [
            "ls -la",
            "ps aux",
            "cat /etc/os-release",
            "echo 'test'",
        ]
        
        for cmd in safe_commands:
            result = runner.run_command(cmd, stream=False, require_confirmation=False)
            self.assertFalse(
                result.get('blocked', False),
                f"Command should not be blocked: {cmd}"
            )


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
