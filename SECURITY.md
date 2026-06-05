# Security Policy

## Supported versions

systop is pre-1.0. Security fixes are applied to the latest released version.

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅        |
| < 0.2   | ❌        |

## Reporting a vulnerability

If you believe you have found a security vulnerability in systop, please report
it privately. **Do not open a public issue for security problems.**

- Email: **azizbektopilboyev7@gmail.com** with the subject line `systop security`.
- Or, on GitHub, use **Security → Report a vulnerability** (private advisory) if
  it is enabled on the repository.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (the exact command, OS, and Python version).
- Any relevant output or proof-of-concept.

## What to expect

- We aim to acknowledge a report within a few days.
- We will work with you to understand and validate the issue, fix it, and
  coordinate a disclosure timeline.
- Please give us a reasonable window to release a fix before any public
  disclosure.

## Scope notes

systop performs network operations (ping, traceroute, port scanning, DNS,
TLS/HTTP checks). Only scan, probe, or test hosts and networks you own or are
explicitly authorized to assess. Misuse against third-party systems is your
responsibility, not a vulnerability in systop.

Thank you for helping keep systop and its users safe.
