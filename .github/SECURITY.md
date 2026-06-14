# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in IoTSentinel, please **do not open a public GitHub issue**.

Instead, email the maintainer directly at **sahritik908@gmail.com** with:

- A description of the vulnerability
- Steps to reproduce it
- The potential impact

You can expect an acknowledgement within 48 hours and a resolution timeline within 14 days for critical issues.

## Supported Versions

| Version | Supported |
|---|---|
| v1.0.x (latest) | Yes |
| < v1.0.0 | No |

## Security Design Notes

IoTSentinel is designed to run **entirely on-device**. No network traffic data, alerts, or device information is ever sent to external servers. The only outbound connections are optional API calls to services you explicitly configure (AbuseIPDB, Groq, etc.).
