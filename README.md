# React2Shell NSE Script

This repository contains an Nmap Scripting Engine (NSE) script for detecting CVE-2025-55182 and CVE-2025-66478 (React2Shell) vulnerabilities in Next.js and React Server Components (RSC) applications.

This is based on the POC work done by liyander (CyberGhost05), which can be found [here](https://github.com/liyander/React2shell-poc).

## Features
- Safe, non-exploitative side-channel detection
- Works against any HTTP service (custom ports supported)
- Verbose mode for reporting non-vulnerable hosts
- Does not perform any exploitation, only detection
- **Currently only validated against a limited set of Next.js applications. I believe it will work against most applications where the vulnerability is discoverable on the root path, which includes the affected Next.js 15 versions in their default configuration. In my experimentation with react-router, a vulnerable configuration is more dependent on how the specific app is built.**
- Test results and sample output in the [TEST_REPORT.md](./TEST_REPORT.md)

## Usage

1. **Run the NSE script against a target:**
   ```bash
   nmap --script ./nse/detect_react2shell.nse -p <port> <target>
   ```
   Example:
   ```bash
   nmap --script ./nse/detect_react2shell.nse -p 3000,3001 localhost
   ```

2. **Enable verbose output for all hosts:**
   ```bash
   nmap --script ./nse/detect_react2shell.nse --script-args detect_react2shell.verbose=true -p 3000,3001 localhost
   ```

## Test Apps

The `test/nextjs` directory contains sample Next.js applications on various versions and ports for validating the NSE script against known vulnerable and non-vulnerable setups.

## Script Details
- Location: `nse/detect_react2shell.nse`
- No external dependencies required (uses Nmap's built-in libraries)
- Only safe detection logic is implemented; no exploitation

## References
- [CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [CVE-2025-66478](https://nvd.nist.gov/vuln/detail/CVE-2025-66478)

## Author
Mic Whitehorn (mgillam)

---
For questions or improvements, feel free to open an issue or pull request.
