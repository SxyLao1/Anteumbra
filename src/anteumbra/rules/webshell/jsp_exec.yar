rule Custom_WebShell_Jsp_Exec {
  meta:
    description = "Custom rule for jsp_exec (extracted from Tennc samples)"
    author = "AutoGenerator"
    date = "1767709224"
    severity = "high"

  strings:
    $1 = "Runtime.getRuntime().exec(request.getParameter(\"cm"
    $2 = "Runtime.getRuntime().exec(request.getParameter(\"i\""

  condition:
    any of them
}
