# Anteumbra Memory-Shell Incident Response References

[中文](README_cn.md)

This directory preserves third-party JSP/ASPX memory-shell scanners for manual
incident response and research. They are not imported, deployed, or executed by
the Anteumbra runtime, and no current plugin automatically orchestrates them.

## Contents

```text
tools/memory-shell/
|-- README.md
|-- README_cn.md
|-- java/
|   |-- tomcat-memshell-scanner.jsp
|   `-- README_upstream.md
`-- aspnet/
    |-- aspx-memshell-scanner.aspx
    `-- README_upstream.md
```

| Tool | Upstream author | Repository |
|------|-----------------|------------|
| `tomcat-memshell-scanner.jsp` | c0ny1 | [java-memshell-scanner](https://github.com/c0ny1/java-memshell-scanner) |
| `aspx-memshell-scanner.aspx` | yzddmr6 | [As-Exploits](https://github.com/yzddmr6/As-Exploits) |

The original Chinese documentation and attribution are retained in each
`README_upstream.md`.

## Operational Safety

These are executable diagnostic pages. Uploading one changes the web root and
creates a powerful administrative endpoint. Before use:

1. Review the exact source and upstream revision.
2. Test against an isolated copy of the affected server whenever possible.
3. Restrict access by network ACL and authentication controls.
4. Record hashes, deployment time, operator, and target as incident evidence.
5. Remove the page immediately after collection and verify that removal.
6. Do not treat a clean result as proof that the host is uncompromised.

Anteumbra's normal file monitor may detect the diagnostic page itself. Use an
explicit, time-bounded maintenance procedure; do not add a permanent broad
allowlist for these files.

## Additional Tools

The following projects are not bundled:

| Tool | Scope |
|------|-------|
| [private-xss/memory-shell-detector](https://github.com/private-xss/memory-shell-detector) | Java GUI/CLI detector for Tomcat, Jetty, WebLogic, and Spring |
| [4ra1n/shell-analyzer](https://github.com/4ra1n/shell-analyzer) | JVM monitor with decompile and removal workflows |
| [y1shiny1shin/KMBA](https://github.com/y1shiny1shin/KMBA) | Arthas-based memory-shell analysis and removal |

## License And Attribution

The scanner files remain under their upstream terms. Anteumbra does not claim
authorship. Review each upstream repository and `README_upstream.md` before
redistribution or production use.
