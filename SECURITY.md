# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in MASS, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to: [security@example.com] (update with actual address)
3. Or use GitHub's private vulnerability reporting feature

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution Timeline**: Depends on severity
  - Critical: ASAP (target 7 days)
  - High: 30 days
  - Medium: 60 days
  - Low: 90 days

### Disclosure Policy

- We follow coordinated disclosure
- We will credit reporters (unless anonymity is requested)
- We aim to fix issues before public disclosure
- We will notify affected users when appropriate

## Security Best Practices for Users

### API Keys

- Never commit API keys to version control
- Use environment variables or secret management
- Rotate keys regularly
- Use scoped keys with minimal permissions

### Deployment

- Run MASS behind a reverse proxy (nginx, Traefik)
- Enable TLS/HTTPS
- Use network isolation for workers
- Regularly update dependencies

### Configuration

```yaml
# Example secure configuration
api:
  rate_limit: 100  # requests per minute
  auth:
    require_https: true
    token_expiry: 3600  # 1 hour
  cors:
    allowed_origins:
      - "https://your-domain.com"
```

### Database

- Use strong passwords
- Enable encryption at rest
- Restrict network access
- Regular backups

### Docker

```dockerfile
# Run as non-root user
USER mass:mass

# Read-only filesystem where possible
--read-only

# Drop capabilities
--cap-drop=ALL
```

## Known Security Considerations

### Model Interrogation

MASS sends prompts to AI models as part of security testing. Be aware:

- Test prompts may trigger model safety filters
- Some tests probe for harmful capabilities
- Ensure you have authorization to test target models
- Results may contain sensitive information

### MCP Analysis

When analyzing MCP servers:

- MASS may execute tool calls
- Use sandboxed environments for untrusted servers
- Review tool permissions before scanning

### Report Data

Security reports may contain:

- Vulnerability details
- Proof-of-concept payloads
- Sensitive system information

Handle reports with appropriate confidentiality.

## Dependency Security

We monitor dependencies for vulnerabilities using:

- GitHub Dependabot
- Safety (Python security checker)
- CodeQL analysis

## Bug Bounty

We do not currently have a formal bug bounty program, but we recognize and appreciate security researchers who report issues responsibly.

## Contact

For security concerns: [security@example.com]

For general questions: Open a GitHub Discussion
