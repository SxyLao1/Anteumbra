rule PHP_Direct_Superglobal_Eval {
  meta:
    description = "PHP eval or assert directly consumes request data"
    author = "Anteumbra"
    severity = "critical"

  strings:
    $php = "<?php" nocase ascii
    $direct = /(eval|assert)\s*\(\s*@?\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase ascii

  condition:
    filesize < 2MB and all of them
}
