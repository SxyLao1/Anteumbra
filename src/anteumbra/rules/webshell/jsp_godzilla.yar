rule JSP_Shell_Generic {
    meta:
        description = "Detect JSP shells (Behinder/Godzilla/Other)"
        severity = "critical"
    strings:
        // ClassLoader动态加载
        $loader1 = "extends ClassLoader"
        $loader2 = "super.defineClass"
        $loader3 = "defineClass"
        
        // 加密相关（AES/DES/XOR）
        $crypto1 = "javax.crypto.Cipher"
        $crypto2 = "javax.crypto.spec.SecretKeySpec"
        $crypto3 = "AES"
        $crypto4 = "DES"
        
        // Base64编解码
        $b64_new1 = "java.util.Base64.getEncoder"
        $b64_new2 = "java.util.Base64.getDecoder"
        $b64_old1 = "sun.misc.BASE64Encoder"
        $b64_old2 = "sun.misc.BASE64Decoder"
        
        // 内存存储（session/request）
        $store1 = "session.setAttribute"
        $store2 = "session.getAttribute"
        
        // 反射调用
        $reflect1 = ".getMethod("
        $reflect2 = ".invoke("
        $reflect3 = ".newInstance("
        
        // 密码参数
        $pass1 = "request.getParameter(\"pass\")"
        $pass2 = "request.getParameter(\"pwd\")"
        $pass3 = "request.getParameter(\"key\")"
        
        // v1.7.6-Patch20: 删除未使用的$bytes变量

        // 动态执行（v1.7.6-Patch21: 添加到condition）
        $exec1 = "Runtime.getRuntime().exec"
        $exec2 = "ProcessBuilder"
    condition:
        filesize < 30KB and (
            (2 of ($loader*) and 1 of ($crypto*)) or
            (1 of ($b64_*) and 1 of ($store*)) or
            (2 of ($store*) and 2 of ($reflect*)) or
            (1 of ($pass*) and 1 of ($loader*)) or
            (1 of ($exec*))  // v1.7.6-Patch21: 新增执行命令特征检测
        )
}