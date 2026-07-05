rule Custom_Eval_Generic {
  meta:
    description = "Generic PHP eval detection - matches any eval( call"
    author = "EmergencyRule"
    severity = "critical"

  strings:
    $eval1 = "eval($_POST[" ascii wide
    $eval2 = "eval($_GET[" ascii wide
    $eval3 = "eval($_REQUEST[" ascii wide
    $eval4 = "eval($" ascii wide  // 匹配 eval($var)
    $eval5 = "eval(" ascii wide   // 匹配所有 eval(
    
    // 排除合法用途（减少误报）
    $exclude_eval_function = "function eval(" ascii wide
    
  condition:
    any of ($eval*) and not $exclude_eval_function
}