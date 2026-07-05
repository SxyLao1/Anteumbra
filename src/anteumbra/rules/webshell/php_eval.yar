rule Custom_WebShell_PhpEval {
  meta:
    description = "Custom rule for php_eval (extracted from samples)"
    author = "AutoGenerator"
    date = "1767711105"
    severity = "high"

  strings:
    $1 = "eval\\s*\\("

  condition:
    any of them
}
