rule Custom_Eval_Generic {
  meta:
    description = "PHP eval with user input or obfuscation context"
    author = "Anteumbra"
    severity = "high"

  strings:
    $php = "<?php" nocase ascii
    $eval_call = /eval\s*\(/ nocase ascii
    $eval_variable = /eval\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*/ nocase ascii
    $user_input = /\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase ascii
    $obfuscation = /(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/ nocase ascii

  condition:
    filesize < 2MB and $php and (
      ($eval_variable and $user_input) or
      ($eval_call and $obfuscation)
    )
}
