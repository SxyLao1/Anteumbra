rule ASPX_Command_Process_Behavior {
  meta:
    description = "ASPX server code accepts input and starts an operating-system command"
    author = "Anteumbra"
    severity = "high"

  strings:
    $page1 = /<%@\s*Page\b/ nocase ascii
    $page2 = /<script\s+runat\s*=\s*[\"']server[\"']/ nocase ascii
    $process1 = "System.Diagnostics" nocase ascii
    $process2 = /ProcessStartInfo\s*\(/ nocase ascii
    $process3 = /Process\.Start\s*\(/ nocase ascii
    $command = /(cmd\.exe|powershell(\.exe)?|\/bin\/(ba)?sh)/ nocase ascii
    $input1 = /Request\s*[\.\[]/ nocase ascii
    $input2 = /\.Text\b/ nocase ascii

  condition:
    filesize < 2MB and any of ($page*) and 2 of ($process*) and
    $command and any of ($input*)
}

rule ASPX_Request_Dynamic_Assembly {
  meta:
    description = "ASPX request data is decoded and loaded as a dynamic assembly"
    author = "Anteumbra"
    severity = "critical"

  strings:
    $page1 = /<%@\s*Page\b/ nocase ascii
    $page2 = /<script\s+runat\s*=\s*[\"']server[\"']/ nocase ascii
    $request = /Request\s*[\.\[]/ nocase ascii
    $assembly = /Assembly\.Load\s*\(/ nocase ascii
    $decode = /(FromBase64String|Convert\.FromBase64String)/ nocase ascii
    $invoke = /\.Invoke\s*\(/ nocase ascii

  condition:
    filesize < 2MB and any of ($page*) and $request and $assembly and
    ($decode or $invoke)
}
