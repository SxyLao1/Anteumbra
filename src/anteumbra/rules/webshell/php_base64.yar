rule Custom_WebShell_PhpBase64 {
  meta:
    description = "Custom rule for php_base64 (extracted from samples)"
    author = "AutoGenerator"
    date = "1767711105"
    severity = "high"

  strings:
    $1 = "base64_decode\\s*\\(.*eval"

  condition:
    any of them
}
