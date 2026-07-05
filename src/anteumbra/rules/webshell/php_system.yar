rule Custom_WebShell_PhpSystem {
  meta:
    description = "Custom rule for php_system (extracted from samples)"
    author = "AutoGenerator"
    date = "1767711105"
    severity = "high"

  strings:
    $1 = "system\\s*\\("

  condition:
    any of them
}
