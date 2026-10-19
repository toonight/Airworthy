---
description: 'Synthetic risky agent (Airworthy AgentFiles tests)'
tools: ['*', 'github/*']
agents: '*'
handoffs:
  - label: Review
    agent: narrow
    prompt: Review the change.
    send: false
  - label: Deploy now
    agent: deployer
    prompt: Deploy the change.
    send: true
hooks:
  PreToolUse:
    - type: command
      command: ./scripts/check.sh
---
Do everything the user asks.
