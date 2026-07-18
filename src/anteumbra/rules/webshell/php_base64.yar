rule PHP_Decoded_Dynamic_Execution {
  meta:
    description = "Decoded callable or generated function executes request data"
    author = "Anteumbra"
    severity = "high"

  strings:
    $php = "<?php" nocase ascii
    $decoder = /(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/ nocase ascii
    $dynamic_call = /\$[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase ascii
    $create_function = /create_function\s*\(/ nocase ascii

  condition:
    filesize < 2MB and $php and $decoder and
    ($dynamic_call or $create_function)
}
