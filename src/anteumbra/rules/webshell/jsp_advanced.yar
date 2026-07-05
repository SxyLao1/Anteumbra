rule JSP_Webshell_Detection {
    meta:
        description = "Detect advanced JSP webshell patterns"
        severity = "critical"
    strings:
        $exec1 = "Runtime.getRuntime().exec("
        $exec2 = "new ProcessBuilder("
        $script1 = "<%%@ page import=\"java.io.*\"%%>"
        $script2 = "<%%@ page import=\"java.util.*\"%%>"
        $backdoor1 = "request.getParameter(\"cmd\")"
        $backdoor2 = "request.getParameter(\"pass\")"
        $backdoor3 = "request.getParameter(\"code\")"
        $decode1 = "Base64.getDecoder().decode("
        $decode2 = "new String(Base64"
    condition:
        filesize < 50KB and (
            any of ($exec*) or
            (any of ($script*) and any of ($backdoor*)) or
            (any of ($backdoor*) and any of ($decode*))
        )
}