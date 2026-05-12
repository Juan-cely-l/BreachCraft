# Recon Report: 127.0.0.1

- Mode: ip
- Timestamp: 2026-05-11T18:26:14

## Summary
| Tool | Status | Finding |
| --- | --- | --- |
| nmap | ok | 3 open ports |
| reverse_dns | ok | localhost., kubernetes.docker.internal. |
| whois | error | organization not found |

## Open Ports
| IP | Port | Service | Version |
| --- | ---: | --- | --- |
| 127.0.0.1 | 25 | smtp | Postfix smtpd |
| 127.0.0.1 | 631 | ipp | CUPS 2.4 |
| 127.0.0.1 | 7070 | realserver |  |

## Missing Security Headers
Not applicable in IP mode; HTTP headers are only checked in domain mode.

## Tool Errors
- whois: command not found: whois

## Ethical Note
Run this tool only against systems you own or are explicitly authorized to test.
