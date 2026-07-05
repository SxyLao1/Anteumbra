rule Custom_WebShell_Asp_Exec {
  meta:
    description = "Custom rule for asp_exec (extracted from Tennc samples)"
    author = "AutoGenerator"
    date = "1767709224"
    severity = "high"

  strings:
    $1 = "Server.CreateObject(\"Shell.Application\")"

  condition:
    any of them
}
