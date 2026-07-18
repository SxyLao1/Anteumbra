rule PHP_User_Input_Indirect_Dispatch {
  meta:
    description = "Variable-variable request import followed by indirect dispatch"
    author = "Anteumbra"
    severity = "high"

  strings:
    $php = "<?php" nocase ascii
    $superglobal_name = /array\s*\(\s*[\"']_(POST|GET|REQUEST)[\"']\s*\)/ nocase ascii
    $variable_variable = /\$\$[A-Za-z_][A-Za-z0-9_]*/ ascii
    $dispatch1 = /\$[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)/ ascii
    $dispatch2 = /(\$[A-Za-z_][A-Za-z0-9_]*|->[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*\$[A-Za-z_][A-Za-z0-9_]*/ ascii

  condition:
    filesize < 2MB and $php and $superglobal_name and
    $variable_variable and any of ($dispatch*)
}
