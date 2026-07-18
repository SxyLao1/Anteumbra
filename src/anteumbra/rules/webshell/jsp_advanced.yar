rule JSP_Direct_Command_Execution {
  meta:
    description = "JSP request data is combined with Runtime or ProcessBuilder execution"
    author = "Anteumbra"
    severity = "critical"

  strings:
    $jsp = /<%@?\s*(page|include)/ nocase ascii
    $request = /request\.getParameter\s*\(/ nocase ascii
    $runtime = /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/ nocase ascii
    $process = /new\s+ProcessBuilder\s*\(/ nocase ascii

  condition:
    filesize < 2MB and $jsp and $request and ($runtime or $process)
}

rule JSP_Reflective_Command_Execution {
  meta:
    description = "JSP request handler reflectively resolves and invokes process APIs"
    author = "Anteumbra"
    severity = "high"

  strings:
    $jsp = /<%@?\s*(page|include)/ nocase ascii
    $request = /request\.getParameter\s*\(/ nocase ascii
    $class = /Class\.forName\s*\(/ nocase ascii
    $method = /getMethod\s*\(/ nocase ascii
    $invoke = /\.invoke\s*\(/ nocase ascii
    $obfuscated1 = /decode(Buffer)?\s*\(/ nocase ascii
    $obfuscated2 = /new\s+byte\s*\[\s*\]\s*\{/ nocase ascii

  condition:
    filesize < 2MB and $jsp and $request and $class and $method and
    $invoke and any of ($obfuscated*)
}

rule JSP_Encoded_Classloader_Shell {
  meta:
    description = "JSP request data feeds encoded bytecode into a class loader"
    author = "Anteumbra"
    severity = "critical"

  strings:
    $jsp = /<%@?\s*(page|include)/ nocase ascii
    $request = /request\.(getParameter|getInputStream)\s*\(/ nocase ascii
    $loader = /(defineClass|getClassLoader)\s*\(/ nocase ascii
    $decode = /(Base64|BASE64Decoder|decodeBuffer)/ nocase ascii

  condition:
    filesize < 2MB and all of them
}
