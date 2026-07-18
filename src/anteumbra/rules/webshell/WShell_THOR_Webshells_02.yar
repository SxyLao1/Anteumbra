/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*

   THOR APT Scanner - Web Shells Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner

   We will frequently update this file with new rules rated TLP:WHITE

   Florian Roth
   BSK Consulting GmbH
   Web: bsk-consulting.de

   revision: 20150122

*/

/* Generated from WShell_THOR_Webshells.yar; shard 2. Do not edit generated shards independently. */

rule webshell_PHP_Shell_x3 {
	meta:
		description = "Web Shell - file PHP Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
	strings:
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
		$s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("
	condition:
		2 of them
}

rule webshell_PHP_g00nv13 {
	meta:
		description = "Web Shell - file g00nv13.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "35ad2533192fe8a1a76c3276140db820"
	strings:
		$s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
		$s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
	condition:
		all of them
}

rule webshell_php_h6ss {
	meta:
		description = "Web Shell - file h6ss.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "272dde9a4a7265d6c139287560328cd5"
	strings:
		$s0 = "<?php eval(gzuncompress(base64_decode(\""
	condition:
		all of them
}

rule webshell_jsp_zx {
	meta:
		description = "Web Shell - file zx.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "67627c264db1e54a4720bd6a64721674"
	strings:
		$s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"
	condition:
		all of them
}

rule webshell_Ani_Shell {
	meta:
		description = "Web Shell - file Ani-Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "889bfc9fbb8ee7832044fc575324d01a"
	strings:
		$s0 = "$Python_CODE = \"I"
		$s6 = "$passwordPrompt = \"\\n================================================="
		$s7 = "fputs ($sockfd ,\"\\n==============================================="
	condition:
		1 of them
}

rule webshell_jsp_k8cmd {
	meta:
		description = "Web Shell - file k8cmd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b39544415e692a567455ff033a97a682"
	strings:
		$s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
	condition:
		all of them
}

rule webshell_jsp_cmd {
	meta:
		description = "Web Shell - file cmd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5391c4a8af1ede757ba9d28865e75853"
	strings:
		$s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
	condition:
		all of them
}

rule webshell_jsp_k81 {
	meta:
		description = "Web Shell - file k81.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "41efc5c71b6885add9c1d516371bd6af"
	strings:
		$s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
		$s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
	condition:
		1 of them
}

rule webshell_ASP_zehir {
	meta:
		description = "Web Shell - file zehir.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0061d800aee63ccaf41d2d62ec15985d"
	strings:
		$s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
	condition:
		all of them
}

rule webshell_Worse_Linux_Shell {
	meta:
		description = "Web Shell - file Worse Linux Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"
	strings:
		$s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"
	condition:
		all of them
}

rule webshell_zacosmall {
	meta:
		description = "Web Shell - file zacosmall.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
	strings:
		$s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
	condition:
		all of them
}

rule webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit {
	meta:
		description = "Web Shell - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"
	strings:
		$s1 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
	condition:
		all of them
}

rule webshell_redirect {
	meta:
		description = "Web Shell - file redirect.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "97da83c6e3efbba98df270cc70beb8f8"
	strings:
		$s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "
	condition:
		all of them
}

rule webshell_jsp_cmdjsp {
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b815611cc39f17f05a73444d699341d4"
	strings:
		$s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
	condition:
		all of them
}

rule webshell_Java_Shell {
	meta:
		description = "Web Shell - file Java Shell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"
	strings:
		$s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
		$s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
	condition:
		1 of them
}

rule webshell_asp_1d {
	meta:
		description = "Web Shell - file 1d.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fad7504ca8a55d4453e552621f81563c"
	strings:
		$s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
	condition:
		all of them
}

rule webshell_jsp_IXRbE {
	meta:
		description = "Web Shell - file IXRbE.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e26e7e0ebc6e7662e1123452a939e2cd"
	strings:
		$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
	condition:
		all of them
}

rule webshell_PHP_G5 {
	meta:
		description = "Web Shell - file G5.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "95b4a56140a650c74ed2ec36f08d757f"
	strings:
		$s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"
	condition:
		all of them
}

rule webshell_PHP_r57142 {
	meta:
		description = "Web Shell - file r57142.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"
	strings:
		$s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
	condition:
		all of them
}

rule webshell_jsp_tree {
	meta:
		description = "Web Shell - file tree.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"
	strings:
		$s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
		$s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
	condition:
		all of them
}

rule webshell_C99madShell_v_3_0_smowu {
	meta:
		description = "Web Shell - file smowu.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "74e1e7c7a6798f1663efb42882b85bee"
	strings:
		$s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for"
		$s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty"
	condition:
		1 of them
}

rule webshell_simple_backdoor {
	meta:
		description = "Web Shell - file simple-backdoor.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "f091d1b9274c881f8e41b2f96e6b9936"
	strings:
		$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
		$s1 = "if(isset($_REQUEST['cmd'])){" fullword
		$s4 = "system($cmd);" fullword
	condition:
		2 of them
}

rule webshell_PHP_404 {
	meta:
		description = "Web Shell - file 404.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "078c55ac475ab9e028f94f879f548bca"
	strings:
		$s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"
	condition:
		all of them
}

rule webshell_Macker_s_Private_PHPShell {
	meta:
		description = "Web Shell - file Macker's Private PHPShell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e24cbf0e294da9ac2117dc660d890bb9"
	strings:
		$s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n"
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
	condition:
		all of them
}

rule webshell_Antichat_Shell_v1_3_2 {
	meta:
		description = "Web Shell - file Antichat Shell v1.3.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "40d0abceba125868be7f3f990f031521"
	strings:
		$s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"
	condition:
		all of them
}

rule webshell_Safe_mode_breaker {
	meta:
		description = "Web Shell - file Safe mode breaker.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5bd07ccb1111950a5b47327946bfa194"
	strings:
		$s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
		$s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
	condition:
		1 of them
}

rule webshell_Sst_Sheller {
	meta:
		description = "Web Shell - file Sst-Sheller.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d93c62a0a042252f7531d8632511ca56"
	strings:
		$s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
		$s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"
	condition:
		all of them
}

rule webshell_jsp_list {
	meta:
		description = "Web Shell - file list.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1ea290ff4259dcaeb680cec992738eda"
	strings:
		$s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
		$s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn"
		$s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
	condition:
		all of them
}

rule webshell_PHPJackal_v1_5 {
	meta:
		description = "Web Shell - file PHPJackal v1.5.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d76dc20a4017191216a0315b7286056f"
	strings:
		$s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
		$s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"
	condition:
		all of them
}

rule webshell_customize {
	meta:
		description = "Web Shell - file customize.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d55578eccad090f30f5d735b8ec530b1"
	strings:
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
	condition:
		all of them
}

rule webshell_s72_Shell_v1_1_Coding {
	meta:
		description = "Web Shell - file s72 Shell v1.1 Coding.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c2e8346a5515c81797af36e7e4a3828e"
	strings:
		$s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "
	condition:
		all of them
}

rule webshell_jsp_sys3 {
	meta:
		description = "Web Shell - file sys3.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b3028a854d07674f4d8a9cf2fb6137ec"
	strings:
		$s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
		$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
		$s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
	condition:
		all of them
}

rule webshell_jsp_guige02 {
	meta:
		description = "Web Shell - file guige02.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a3b8b2280c56eaab777d633535baf21d"
	strings:
		$s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
		$s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"
	condition:
		all of them
}

rule webshell_php_ghost {
	meta:
		description = "Web Shell - file ghost.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "38dc8383da0859dca82cf0c943dbf16d"
	strings:
		$s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'"
		$s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***"
		$s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
	condition:
		all of them
}

rule webshell_WinX_Shell {
	meta:
		description = "Web Shell - file WinX Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "17ab5086aef89d4951fe9b7c7a561dda"
	strings:
		$s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam"
		$s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </"
	condition:
		all of them
}

rule webshell_Crystal_Crystal {
	meta:
		description = "Web Shell - file Crystal.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fdbf54d5bf3264eb1c4bff1fac548879"
	strings:
		$s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
		$s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"
	condition:
		all of them
}

rule webshell_r57_1_4_0 {
	meta:
		description = "Web Shell - file r57.1.4.0.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "574f3303e131242568b0caf3de42f325"
	strings:
		$s4 = "@ini_set('error_log',NULL);" fullword
		$s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s7 = "@ini_restore(\"disable_functions\");" fullword
		$s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
	condition:
		all of them
}

rule webshell_jsp_hsxa1 {
	meta:
		description = "Web Shell - file hsxa1.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5686d5a38c6f5b8c55095af95c2b0244"
	strings:
		$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
	condition:
		all of them
}

rule webshell_asp_ajn {
	meta:
		description = "Web Shell - file ajn.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aaafafc5d286f0bff827a931f6378d04"
	strings:
		$s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
		$s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"
	condition:
		all of them
}

rule webshell_php_cmd {
	meta:
		description = "Web Shell - file cmd.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c38ae5ba61fd84f6bbbab98d89d8a346"
	strings:
		$s0 = "if($_GET['cmd']) {" fullword
		$s1 = "// cmd.php = Command Execution" fullword
		$s7 = "  system($_GET['cmd']);" fullword
	condition:
		all of them
}

rule webshell_asp_list {
	meta:
		description = "Web Shell - file list.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1cfa493a165eb4b43e6d4cc0f2eab575"
	strings:
		$s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
		$s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
	condition:
		all of them
}

rule webshell_PHP_co {
	meta:
		description = "Web Shell - file co.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "62199f5ac721a0cb9b28f465a513874c"
	strings:
		$s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
		$s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
	condition:
		all of them
}

rule webshell_PHP_150 {
	meta:
		description = "Web Shell - file 150.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "400c4b0bed5c90f048398e1d268ce4dc"
	strings:
		$s0 = "HJ3HjqxclkZfp"
		$s1 = "<? eval(gzinflate(base64_decode('" fullword
	condition:
		all of them
}

rule webshell_jsp_cmdjsp_2 {
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1b5ae3649f03784e2a5073fa4d160c8b"
	strings:
		$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
		$s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
	condition:
		all of them
}

rule webshell_PHP_c37 {
	meta:
		description = "Web Shell - file c37.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d01144c04e7a46870a8dd823eb2fe5c8"
	strings:
		$s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
		$s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"
	condition:
		all of them
}

rule webshell_PHP_b37 {
	meta:
		description = "Web Shell - file b37.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0421445303cfd0ec6bc20b3846e30ff0"
	strings:
		$s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc"
	condition:
		all of them
}

rule webshell_php_backdoor {
	meta:
		description = "Web Shell - file php-backdoor.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
	strings:
		$s1 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))" fullword
		$s2 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
	condition:
		all of them
}

rule webshell_asp_dabao {
	meta:
		description = "Web Shell - file dabao.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3919b959e3fa7e86d52c2b0a91588d5d"
	strings:
		$s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
		$s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
	condition:
		all of them
}

rule webshell_php_2 {
	meta:
		description = "Web Shell - file 2.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "267c37c3a285a84f541066fc5b3c1747"
	strings:
		$s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
	condition:
		all of them
}

rule webshell_asp_cmdasp {
	meta:
		description = "Web Shell - file cmdasp.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "57b51418a799d2d016be546f399c2e9b"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		all of them
}

rule webshell_spjspshell {
	meta:
		description = "Web Shell - file spjspshell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d39d51154aaad4ba89947c459a729971"
	strings:
		$s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"
	condition:
		all of them
}

rule webshell_jsp_action {
	meta:
		description = "Web Shell - file action.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"
	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
		$s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
	condition:
		all of them
}

rule webshell_Inderxer {
	meta:
		description = "Web Shell - file Inderxer.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9ea82afb8c7070817d4cdf686abe0300"
	strings:
		$s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
	condition:
		all of them
}

rule webshell_asp_Rader {
	meta:
		description = "Web Shell - file Rader.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ad1a362e0a24c4475335e3e891a01731"
	strings:
		$s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
		$s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
	condition:
		all of them
}

rule webshell_c99_madnet_smowu {
	meta:
		description = "Web Shell - file smowu.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3aaa8cad47055ba53190020311b0fb83"
	strings:
		$s0 = "//Authentication" fullword
		$s1 = "$login = \"" fullword
		$s2 = "eval(gzinflate(base64_decode('"
		$s4 = "//Pass"
		$s5 = "$md5_pass = \""
		$s6 = "//If no pass then hash"
	condition:
		all of them
}

rule webshell_php_moon {
	meta:
		description = "Web Shell - file moon.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2a2b1b783d3a2fa9a50b1496afa6e356"
	strings:
		$s2 = "echo '<option value=\"create function backshell returns string soname"
		$s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
		$s8 = "echo '<option value=\"select cmdshell(\\'net user "
	condition:
		2 of them
}

rule webshell_jsp_jdbc {
	meta:
		description = "Web Shell - file jdbc.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "23b0e6f91a8f0d93b9c51a2a442119ce"
	strings:
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
	condition:
		all of them
}

rule webshell_minupload {
	meta:
		description = "Web Shell - file minupload.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ec905a1395d176c27f388d202375bdf9"
	strings:
		$s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
		$s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
	condition:
		all of them
}

rule webshell_ELMALISEKER_Backd00r {
	meta:
		description = "Web Shell - file ELMALISEKER Backd00r.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3aa403e0a42badb2c23d4a54ef43e2f4"
	strings:
		$s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
		$s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"
	condition:
		all of them
}

rule webshell_PHP_bug_1_ {
	meta:
		description = "Web Shell - file bug (1).php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "91c5fae02ab16d51fc5af9354ac2f015"
	strings:
		$s0 = "@include($_GET['bug']);" fullword
	condition:
		all of them
}

rule webshell_caidao_shell_hkmjj {
	meta:
		description = "Web Shell - file hkmjj.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e7b994fe9f878154ca18b7cde91ad2d0"
	strings:
		$s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
	condition:
		all of them
}

rule webshell_jsp_asd {
	meta:
		description = "Web Shell - file asd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a042c2ca64176410236fcc97484ec599"
	strings:
		$s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
		$s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"
	condition:
		all of them
}

rule webshell_jsp_inback3 {
	meta:
		description = "Web Shell - file inback3.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ea5612492780a26b8aa7e5cedd9b8f4e"
	strings:
		$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
	condition:
		all of them
}

rule webshell_metaslsoft {
	meta:
		description = "Web Shell - file metaslsoft.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aa328ed1476f4a10c0bcc2dde4461789"
	strings:
		$s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
	condition:
		all of them
}

rule webshell_asp_Ajan {
	meta:
		description = "Web Shell - file Ajan.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b6f468252407efc2318639da22b08af0"
	strings:
		$s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"
	condition:
		all of them
}

rule webshell_config_myxx_zend {
	meta:
		description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash1 = "e0354099bee243702eb11df8d0e046df"
		hash2 = "591ca89a25f06cf01e4345f98a22845c"
	strings:
		$s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');"
	condition:
		all of them
}

rule webshell_browser_201_3_ma_download {
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "fa87bbd7201021c1aefee6fcc5b8e25a"
	strings:
		$s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a"
		$s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith"
	condition:
		all of them
}

rule webshell_itsec_itsecteam_shell_jHn {
	meta:
		description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash2 = "40c6ecf77253e805ace85f119fe1cebb"
	strings:
		$s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b"
		$s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'"
	condition:
		all of them
}

rule webshell_ghost_source_icesword_silic {
	meta:
		description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "cbf64a56306c1b5d98898468fc1fdbd8"
		hash1 = "6e20b41c040efb453d57780025a292ae"
		hash2 = "437d30c94f8eef92dc2f064de4998695"
	strings:
		$s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $"
		$s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST["
	condition:
		all of them
}

rule webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash6 = "14e9688c86b454ed48171a9d4f48ace8"
		hash7 = "b330a6c2d49124ef0729539761d6ef0b"
		hash8 = "d71716df5042880ef84427acee8b121e"
		hash9 = "341298482cf90febebb8616426080d1d"
		hash10 = "29aebe333d6332f0ebc2258def94d57e"
		hash11 = "42654af68e5d4ea217e6ece5389eb302"
		hash12 = "88fc87e7c58249a398efd5ceae636073"
		hash13 = "4a812678308475c64132a9b56254edbc"
		hash14 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash15 = "344f9073576a066142b2023629539ebd"
		hash16 = "32dea47d9c13f9000c4c807561341bee"
		hash17 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash18 = "655722eaa6c646437c8ae93daac46ae0"
		hash19 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash20 = "9c94637f76e68487fa33f7b0030dd932"
		hash21 = "6acc82544be056580c3a1caaa4999956"
		hash22 = "6aa32a6392840e161a018f3907a86968"
		hash23 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash24 = "3ea688e3439a1f56b16694667938316d"
		hash25 = "ab77e4d1006259d7cbc15884416ca88c"
		hash26 = "71097537a91fac6b01f46f66ee2d7749"
		hash27 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash28 = "7a4b090619ecce6f7bd838fe5c58554b"
	strings:
		$s8 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype="
		$s9 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T"
	condition:
		all of them
}

rule webshell_2_520_job_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "56c005690da2558690c4aa305a31ad37"
		hash3 = "532b93e02cddfbb548ce5938fe2f5559"
		hash4 = "6e0fa491d620d4af4b67bae9162844ae"
		hash5 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
	strings:
		$s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" "
		$s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR"
	condition:
		all of them
}

rule webshell_000_403_807_a_c5_config_css_dm_he1p_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_xxx {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
		hash9 = "d71716df5042880ef84427acee8b121e"
		hash10 = "341298482cf90febebb8616426080d1d"
		hash11 = "29aebe333d6332f0ebc2258def94d57e"
		hash12 = "42654af68e5d4ea217e6ece5389eb302"
		hash13 = "88fc87e7c58249a398efd5ceae636073"
		hash14 = "4a812678308475c64132a9b56254edbc"
		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash16 = "e0354099bee243702eb11df8d0e046df"
		hash17 = "344f9073576a066142b2023629539ebd"
		hash18 = "32dea47d9c13f9000c4c807561341bee"
		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash20 = "655722eaa6c646437c8ae93daac46ae0"
		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash22 = "9c94637f76e68487fa33f7b0030dd932"
		hash23 = "6acc82544be056580c3a1caaa4999956"
		hash24 = "6aa32a6392840e161a018f3907a86968"
		hash25 = "591ca89a25f06cf01e4345f98a22845c"
		hash26 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash27 = "3ea688e3439a1f56b16694667938316d"
		hash28 = "ab77e4d1006259d7cbc15884416ca88c"
		hash29 = "71097537a91fac6b01f46f66ee2d7749"
		hash30 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash31 = "7a4b090619ecce6f7bd838fe5c58554b"
	strings:
		$s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";" fullword
		$s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {" fullword
	condition:
		all of them
}

rule webshell_wso2_5_1_wso2_5_wso2 {
	meta:
		description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "dbeecd555a2ef80615f0894027ad75dc"
		hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
		hash2 = "cbc44fb78220958f81b739b493024688"
	strings:
		$s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec"
		$s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na"
	condition:
		all of them
}

rule webshell_000_403_c5_queryDong_spyjsp2010_t00ls {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"
		hash5 = "9c94637f76e68487fa33f7b0030dd932"
	strings:
		$s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')"
		$s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\""
	condition:
		all of them
}

rule webshell_404_data_suiyue {
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
	strings:
		$s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"
	condition:
		all of them
}
