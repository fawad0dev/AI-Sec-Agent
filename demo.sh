#!/bin/bash
# Demo script for AI-Sec-Agent CLI

echo "=========================================="
echo "AI-Sec-Agent CLI Demo"
echo "=========================================="
echo ""

echo "1. Simple command execution:"
echo "   Command: ./ai_sec_agent.py --command 'echo Hello Security Agent' --yes"
echo ""
./ai_sec_agent.py --command 'echo Hello Security Agent' --yes
echo ""
echo "Press Enter to continue..."
read

echo "2. Dangerous command blocking:"
echo "   Command: ./ai_sec_agent.py --command 'rm -rf /' --yes"
echo ""
./ai_sec_agent.py --command 'rm -rf /' --yes
echo ""
echo "Press Enter to continue..."
read

echo "3. Directory scan:"
echo "   Creating test directory with suspicious files..."
mkdir -p /tmp/demo_scan
echo "test" > /tmp/demo_scan/suspicious.sh
echo "test" > /tmp/demo_scan/normal.txt
echo "   Command: ./ai_sec_agent.py --scan-directory /tmp/demo_scan --yes"
echo ""
./ai_sec_agent.py --scan-directory /tmp/demo_scan --yes
rm -rf /tmp/demo_scan
echo ""
echo "Press Enter to continue..."
read

echo "4. Command with retries:"
echo "   Command: ./ai_sec_agent.py --command 'false' --yes --retries 2"
echo ""
./ai_sec_agent.py --command 'false' --yes --retries 2
echo ""
echo "Press Enter to continue..."
read

echo "5. System audit (partial):"
echo "   Command: ./ai_sec_agent.py --audit-system --yes"
echo ""
./ai_sec_agent.py --audit-system --yes
echo ""

echo "=========================================="
echo "Demo complete!"
echo "Check the generated report-*.json files for detailed results"
echo "=========================================="
