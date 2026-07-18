rule PHP_User_Input_Command_Execution {
  meta:
    description = "PHP command execution combines a process sink with request data"
    author = "Anteumbra"
    severity = "high"

  strings:
    $php = "<?php" nocase ascii
    $sink = /(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/ nocase ascii
    $user_input = /\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase ascii

  condition:
    filesize < 2MB and all of them
}
