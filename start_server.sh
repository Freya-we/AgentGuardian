#!/bin/bash
export CLAUDE_CODE_TMPDIR=/home/QcN3ep/tmp
mkdir -p /home/QcN3ep/tmp
exec bash /home/QcN3ep/.claude/plugins/cache/claude-plugins-official/superpowers/5.1.0/skills/brainstorming/scripts/start-server.sh --project-dir /home/QcN3ep/Projects/AgentGuardian
