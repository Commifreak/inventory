# Security policy

Please do **not** open public issues for security problems.

Report vulnerabilities privately via GitHub: **Security → Report a vulnerability**
(private vulnerability reporting) in this repository. Include the affected
version (server and/or agent), steps to reproduce and the impact you expect.

Only the latest release and the current `main` (`:edge`) receive fixes.

## Scope notes

- Agents only install updates signed with the publisher key compiled into
  them; a report that bypasses this check is critical.
- The server never executes commands on clients by design (read-only
  monitoring); anything that makes a client run attacker-controlled code via
  the server or the agent API is in scope.
- Enrollment tokens and device credentials are secrets; leaks through logs,
  the UI or the API are in scope.
