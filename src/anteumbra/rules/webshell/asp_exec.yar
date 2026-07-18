rule ASP_Request_Dynamic_Execution {
  meta:
    description = "Classic ASP request data reaches Eval or Execute"
    author = "Anteumbra"
    severity = "critical"

  strings:
    $asp = "<%" ascii
    $request = /\bRequest\s*(\(\s*[\"']|\.\s*(Form|QueryString)\s*\()/ nocase ascii
    $execute = /\b(Eval|Execute|ExecuteGlobal)\b/ nocase ascii

  condition:
    filesize < 2MB and all of them
}

rule ASP_Request_Command_Object {
  meta:
    description = "Classic ASP request handler creates a command-capable COM object"
    author = "Anteumbra"
    severity = "high"

  strings:
    $asp = "<%" ascii
    $request = /\bRequest\s*(\(\s*[\"']|\.\s*(Form|QueryString)\s*\()/ nocase ascii
    $object = /(WScript\.Shell|Shell\.Application)/ nocase ascii
    $create = /(Server\.)?CreateObject\s*\(/ nocase ascii
    $run = /\.(Run|Exec|ShellExecute)\s*\(?/ nocase ascii

  condition:
    filesize < 2MB and $asp and $request and $object and
    ($create or $run)
}
