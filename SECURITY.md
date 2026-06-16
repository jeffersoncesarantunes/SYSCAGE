# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅       |

## Reporting a Vulnerability

This is a behavioral syscall profiler and seccomp-bpf policy generator. If you discover a security vulnerability, please do NOT open a public issue.

Contact the maintainer directly at jefferson.antunes@gmail.com with details about the issue.

We commit to acknowledging receipt within 48 hours and providing a fix timeline within 7 days.

## Known Limitations

- **Untrusted file parsing**: The tool parses user-supplied .trace and .syscage files. Input validation is applied (bounds checks, sscanf return validation), but crafted files could cause denial of service via memory exhaustion.
- **Root requirement**: seccomp-bpf operations require root privileges. The tool does not drop privileges after setup.
