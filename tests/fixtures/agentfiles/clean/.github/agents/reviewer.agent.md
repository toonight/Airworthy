---
name: reviewer
description: Read-only reviewer (synthetic clean fixture)
tools: ['search', 'usages', 'problems', 'github/get_issue']
model: 'GPT-5 (copilot)'
agents: []
handoffs:
  - label: Implement
    agent: implementer
    prompt: Implement the review comments.
    send: false
---
Review the code. Never edit files.
