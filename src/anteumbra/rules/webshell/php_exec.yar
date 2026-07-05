rule Custom_WebShell_PhpExec {
  meta:
    description = "Custom rule for php_exec (extracted from samples)"
    author = "AutoGenerator"
    date = "1767711105"
    severity = "high"

  strings:
    $1 = "exec\\s*\\("

  condition:
    any of them
}
