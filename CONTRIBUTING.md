<div align="center">

# 🛠️ Contributing

*Contributions are welcome — here's everything you need to know.*

</div>

---

## 🚀 Ways to Contribute

| Type | How |
|------|-----|
| 🐛 **Bug Report** | Open an issue with reproduction steps |
| 💡 **Feature Request** | Open an issue describing the idea |
| 🔧 **Pull Request** | Fork → branch → code → PR |
| 📖 **Documentation** | Fix typos, improve clarity, add examples |

---

## 🐛 Bug Reports

Open an issue and include:

- **Which skill and script** is affected
- **Steps to reproduce** the issue
- **Expected vs actual** behavior
- **Your environment** — OS, Python version, Claude Code version

---

## 💡 Feature Requests

Open an issue describing:

- **What** you want to add
- **Why** it's useful for offensive security testing
- **Which skill** it belongs to (or if it needs a new one)

---

## 🔀 Pull Requests

```
1. Fork the repository
2. Create a feature branch
   git checkout -b feature/my-feature
3. Follow the code standards below
4. Test your changes thoroughly
5. Submit a PR with a clear description
```

---

## 📐 Code Standards

### Python Scripts

- **Python 3.8+** compatible
- **Standard library only** — no pip dependencies
- Follow the existing helper pattern:

```python
#!/usr/bin/env python3
"""
Skill: skill-name
Description: What this script does.
Author: maeitsec
"""

def log(msg):    ...   # General info
def success(msg): ...  # Positive result
def warn(msg):   ...   # Warning
def vuln(msg):   ...   # Vulnerability found

def http_request(url, ...): ...  # Shared HTTP helper
```

- **CLI conventions:** `--target`, `--output`, `--cookie`, `--header`, `--delay`
- **JSON output format:**
```json
{
  "meta": { "target": "...", "timestamp": "..." },
  "findings": [ { "type": "...", "severity": "...", "detail": "..." } ]
}
```
- Print a **summary banner** to stdout at the end

### SKILL.md Files

- Follow the [Claude Skills Guide](https://docs.anthropic.com) format
- YAML frontmatter with `name`, `description`, `metadata`

```yaml
---
name: skill-name          # kebab-case
description: "..."        # under 1024 characters
metadata:
  author: maeitsec
  version: 1.0.0
---
```

- Include an **authorization warning** in the Important section
- Use **progressive disclosure**: basic → intermediate → advanced usage

### Naming Conventions

| Item | Convention |
|------|-----------|
| Skill folders | `kebab-case` |
| Python scripts | `snake_case.py` |
| JSON output keys | `snake_case` |

---

## 🎯 Priority Areas

We especially welcome contributions in these areas:

- 🔍 Additional vulnerability test patterns and payloads
- 🧱 Support for more technology stacks
- 🛡️ Better WAF bypass techniques
- ☁️ Additional cloud provider support
- 📄 Improved report templates
- ⚡ Performance optimizations
- 📖 Documentation improvements

---

## ⚖️ Legal

By contributing, you agree that your contributions will be licensed under the **MIT License**.

### Do NOT contribute

- ❌ Exploit code for 0-day vulnerabilities
- ❌ Stolen credentials or leaked data
- ❌ Code that targets specific organizations
- ❌ Content that violates any law

---

## 📜 Code of Conduct

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

---

<div align="center">

*Every contribution — big or small — makes this framework better for everyone.*

</div>
