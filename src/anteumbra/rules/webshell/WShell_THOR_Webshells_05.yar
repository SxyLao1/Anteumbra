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

/* Generated from WShell_THOR_Webshells.yar; shard 5. Do not edit generated shards independently. */

rule sql_php_php {
	meta:
		description = "Semi-Auto-generated  - file sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8334249cbb969f2d33d678fec2b680c5"
	strings:
		$s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
		$s2 = "http://rst.void.ru"
		$s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
	condition:
		1 of them
}

rule cgi_python_py {
	meta:
		description = "Semi-Auto-generated  - file cgi-python.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0a15f473e2232b89dae1075e1afdac97"
	strings:
		$s0 = "a CGI by Fuzzyman"
		$s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + "
		$s2 = "values = map(lambda x: x.value, theform[field])     # allows for"
	condition:
		1 of them
}

rule ru24_post_sh_php_php {
	meta:
		description = "Semi-Auto-generated  - file ru24_post_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5b334d494564393f419af745dc1eeec7"
	strings:
		$s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
		$s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
		$s4 = "Writed by DreAmeRz" fullword
	condition:
		1 of them
}

rule DTool_Pro_php {
	meta:
		description = "Semi-Auto-generated  - file DTool Pro.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "366ad973a3f327dfbfb915b0faaea5a6"
	strings:
		$s0 = "r3v3ng4ns\\nDigite"
		$s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi"
		$s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n"
	condition:
		1 of them
}

rule telnetd_pl {
	meta:
		description = "Semi-Auto-generated  - file telnetd.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5f61136afd17eb025109304bd8d6d414"
	strings:
		$s0 = "0ldW0lf" fullword
		$s1 = "However you are lucky :P"
		$s2 = "I'm FuCKeD"
		$s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#"
		$s4 = "atrix@irc.brasnet.org"
	condition:
		1 of them
}

rule php_include_w_shell_php {
	meta:
		description = "Semi-Auto-generated  - file php-include-w-shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "4e913f159e33867be729631a7ca46850"
	strings:
		$s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd"
		$s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB"
	condition:
		1 of them
}

rule Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_php {
	meta:
		description = "Semi-Auto-generated  - file Safe0ver Shell -Safe Mod Bypass By Evilc0der.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "6163b30600f1e80d2bb5afaa753490b6"
	strings:
		$s0 = "Safe0ver" fullword
		$s1 = "Script Gecisi Tamamlayamadi!"
		$s2 = "document.write(unescape('%3C%68%74%6D%6C%3E%3C%62%6F%64%79%3E%3C%53%43%52%49%50%"
	condition:
		1 of them
}

rule shell_php_php {
	meta:
		description = "Semi-Auto-generated  - file shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1a95f0163b6dea771da1694de13a3d8d"
	strings:
		$s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
		$s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
		$s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
	condition:
		1 of them
}

rule telnet_cgi {
	meta:
		description = "Semi-Auto-generated  - file telnet.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dee697481383052980c20c48de1598d1"
	strings:
		$s0 = "www.rohitab.com"
		$s1 = "W A R N I N G: Private Server"
		$s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
		$s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
	condition:
		1 of them
}

rule ironshell_php {
	meta:
		description = "Semi-Auto-generated  - file ironshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8bfa2eeb8a3ff6afc619258e39fded56"
	strings:
		$s0 = "www.ironwarez.info"
		$s1 = "$cookiename = \"wieeeee\";"
		$s2 = "~ Shell I"
		$s3 = "www.rootshell-team.info"
		$s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);"
	condition:
		1 of them
}

rule backdoorfr_php {
	meta:
		description = "Semi-Auto-generated  - file backdoorfr.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "91e4afc7444ed258640e85bcaf0fecfc"
	strings:
		$s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
		$s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"
	condition:
		1 of them
}

rule aspydrv_asp {
	meta:
		description = "Semi-Auto-generated  - file aspydrv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1c01f8a88baee39aa1cebec644bbcb99"
		score = 60
	strings:
		$s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
		$s1 = "password"
		$s2 = "session(\"shagman\")="
	condition:
		2 of them
}

rule cmdjsp_jsp {
	meta:
		description = "Semi-Auto-generated  - file cmdjsp.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b815611cc39f17f05a73444d699341d4"
	strings:
		$s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword
		$s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
		$s2 = "cmdjsp.jsp"
		$s3 = "michaeldaw.org" fullword
	condition:
		2 of them
}

rule h4ntu_shell__powered_by_tsoi_ {
	meta:
		description = "Semi-Auto-generated  - file h4ntu shell [powered by tsoi].txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "06ed0b2398f8096f1bebf092d0526137"
	strings:
		$s0 = "h4ntu shell"
		$s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"
	condition:
		1 of them
}

rule Ajan_asp {
	meta:
		description = "Semi-Auto-generated  - file Ajan.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b6f468252407efc2318639da22b08af0"
	strings:
		$s1 = "c:\\downloaded.zip"
		$s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
		$s3 = "http://www35.websamba.com/cybervurgun/"
	condition:
		1 of them
}

rule PHANTASMA_php {
	meta:
		description = "Semi-Auto-generated  - file PHANTASMA.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "52779a27fa377ae404761a7ce76a5da7"
	strings:
		$s0 = ">[*] Safemode Mode Run</DIV>"
		$s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>"
		$s2 = "[*] Spawning Shell"
		$s3 = "Cha0s"
	condition:
		2 of them
}

rule MySQL_Web_Interface_Version_0_8_php {
	meta:
		description = "Semi-Auto-generated  - file MySQL Web Interface Version 0.8.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36d4f34d0a22080f47bb1cb94107c60f"
	strings:
		$s0 = "SooMin Kim"
		$s1 = "http://popeye.snu.ac.kr/~smkim/mysql"
		$s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename"
		$s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi"
	condition:
		2 of them
}

rule simple_cmd_html {
	meta:
		description = "Semi-Auto-generated  - file simple_cmd.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6381412df74dbf3bcd5a2b31522b544"
	strings:
		$s1 = "<title>G-Security Webshell</title>" fullword
		$s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
	condition:
		all of them
}

rule multiple_webshells_0001 {
	meta:
		description = "Semi-Auto-generated  - from files 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_1_c2007_php_php_c100_php"
		hash0 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash1 = "d089e7168373a0634e1ac18c0ee00085"
		hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"
	strings:
		$s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\""
		$s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
	condition:
		1 of them
}

rule multiple_webshells_0002 {
	meta:
		description = "Semi-Auto-generated  - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_nst_php_php_img_php_php_nstview_php_php"
		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
		hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
		hash2 = "4745d510fed4378e4b1730f56f25e569"
	strings:
		$s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i"
		$s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v"
		$s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input"
	condition:
		1 of them
}

rule multiple_webshells_0003 {
	meta:
		description = "Semi-Auto-generated  - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_network_php_php_xinfo_php_php_nfm_php_php"
		hash0 = "acdbba993a5a4186fd864c5e4ea0ba4f"
		hash1 = "2601b6fc1579f263d2f3960ce775df70"
		hash2 = "401fbae5f10283051c39e640b77e4c26"
	strings:
		$s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa"
		$s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''"
	condition:
		all of them
}

rule multiple_webshells_0004 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s2 = "echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft"
		$s3 = "$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r"
	condition:
		1 of them
}

rule multiple_webshells_0005 {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash3 = "8023394542cddf8aee5dec6072ed02b5"
		hash4 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash5 = "817671e1bdc85e04cc3440bbd9288800"
	strings:
		$s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o"
		$s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult"
	condition:
		1 of them
}

rule multiple_webshells_0006 {
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, ctt_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_c99shell_v1_0_php_php_c99php_SsEs_php_php_ctt_sh_php_php"
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash3 = "671cad517edd254352fe7e0c7c981c39"
	strings:
		$s0 = "\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\""
		$s2 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\""
		$s4 = "\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\""
	condition:
		2 of them
}

rule multiple_webshells_0007 {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash2 = "817671e1bdc85e04cc3440bbd9288800"
	strings:
		$s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['"
		$s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>"
	condition:
		1 of them
}

rule multiple_webshells_0008 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php_ctt_sh_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "09609851caa129e40b0d56e90dfc476c"
		hash6 = "671cad517edd254352fe7e0c7c981c39"
	strings:
		$s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\""
		$s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile"
		$s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr"
		$s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m"
	condition:
		all of them
}

rule multiple_webshells_0009 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = "$sess_data[\"cut\"] = array(); c99_s"
		$s3 = "if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))"
	condition:
		1 of them
}

rule multiple_webshells_0010 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_wacking_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
		$s2 = "c99sh_sqlquery"
	condition:
		1 of them
}

rule multiple_webshells_0011 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA"
		$s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec"
	condition:
		1 of them
}

rule multiple_webshells_0012 {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash4 = "817671e1bdc85e04cc3440bbd9288800"
	strings:
		$s0 = "echo sr(15,\"<b>\".$lang[$language.'_text"
		$s1 = ".$arrow.\"</b>\",in('text','"
	condition:
		2 of them
}

rule multiple_webshells_0013 {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
	strings:
		$s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword
		$s1 = "$name='ec371748dc2da624b35a4f8f685dd122'"
		$s2 = "rst.void.ru"
	condition:
		3 of them
}

rule multiple_webshells_0014 {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "8023394542cddf8aee5dec6072ed02b5"
		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash3 = "817671e1bdc85e04cc3440bbd9288800"
	strings:
		$s0 = "echo ws(2).$lb.\" <a"
		$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']"
		$s3 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l"
	condition:
		2 of them
}

rule multiple_webshells_0015 {
	meta:
		description = "Semi-Auto-generated  - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_wacking_php_php_1_SpecialShell_99_php_php_c100_php"
		hash0 = "9c5bb5e3a46ec28039e8986324e42792"
		hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash2 = "09609851caa129e40b0d56e90dfc476c"
		hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"
	strings:
		$s0 = "if(eregi(\"./shbd $por\",$scan))"
		$s1 = "$_POST['backconnectip']"
		$s2 = "$_POST['backcconnmsg']"
	condition:
		1 of them
}

rule multiple_webshells_0016 {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "8023394542cddf8aee5dec6072ed02b5"
		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash4 = "817671e1bdc85e04cc3440bbd9288800"
	strings:
		$s1 = "if(rmdir($_POST['mk_name']))"
		$s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>"
		$s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell"
	condition:
		2 of them
}

rule multiple_webshells_0017 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash3 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = "\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi"
		$s1 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu"
		$s2 = "\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd"
	condition:
		1 of them
}

rule multiple_webshells_0018 {
	meta:
		description = "Semi-Auto-generated  - from files webadmin.php.php.txt, iMHaPFtp.php.php.txt, Private-i3lue.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_webadmin_php_php_iMHaPFtp_php_php_Private_i3lue_php"
		hash0 = "b268e6fa3bf3fe496cffb4ea574ec4c7"
		hash1 = "12911b73bc6a5d313b494102abcf5c57"
		hash2 = "13f5c7a035ecce5f9f380967cf9d4e92"
	strings:
		$s0 = "return $type . $owner . $group . $other;" fullword
		$s1 = "$owner  = ($mode & 00400) ? 'r' : '-';" fullword
	condition:
		all of them
}

rule multiple_php_webshells {
	meta:
		description = "Semi-Auto-generated  - from files multiple_php_webshells"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "be0f67f3e995517d18859ed57b4b4389"
		hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash4 = "8023394542cddf8aee5dec6072ed02b5"
		hash5 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash6 = "817671e1bdc85e04cc3440bbd9288800"
		hash7 = "7101fe72421402029e2629f3aaed6de7"
		hash8 = "f618f41f7ebeb5e5076986a66593afd1"
	strings:
		$s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
		$s2 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0"
		$s4 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg"
	condition:
		2 of them
}

rule multiple_webshells_0019 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
	strings:
		$s0 = "<b>Dumped! Dump has been writed to "
		$s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st"
		$s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive"
	condition:
		1 of them
}

rule multiple_webshells_0020 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
	strings:
		$s0 = "@ini_set(\"highlight" fullword
		$s1 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";" fullword
		$s2 = "{$row[] = \"<b>Owner/Group</b>\";}" fullword
	condition:
		2 of them
}

rule multiple_webshells_0021 {
	meta:
		description = "Semi-Auto-generated  - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_GFS_web_shell_ver_3_1_7___PRiV8_php_nshell_php_php_gfs_sh_php_php"
		hash0 = "be0f67f3e995517d18859ed57b4b4389"
		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
		hash2 = "f618f41f7ebeb5e5076986a66593afd1"
	strings:
		$s2 = "echo $uname.\"</font><br><b>\";" fullword
		$s3 = "while(!feof($f)) { $res.=fread($f,1024); }" fullword
		$s4 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()"
	condition:
		2 of them
}

rule multiple_webshells_0022 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = "c99ftpbrutecheck"
		$s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
		$s2 = "$fqb_lenght = $nixpwdperpage;" fullword
		$s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword
	condition:
		2 of them
}

rule multiple_webshells_0023 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = "$sqlquicklaunch[] = array(\""
		$s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<"
	condition:
		all of them
}

rule multiple_webshells_0024 {
	meta:
		description = "Semi-Auto-generated  - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_antichat_php_php_Fatalshell_php_php_a_gedit_php_php"
		hash0 = "128e90b5e2df97e21e96d8e268cde7e3"
		hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
		hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"
	strings:
		$s0 = "if(@$_POST['save'])writef($file,$_POST['data']);" fullword
		$s1 = "if($action==\"phpeval\"){" fullword
		$s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];" fullword
		$s3 = "$dir=getcwd().\"/\";" fullword
	condition:
		2 of them
}

rule multiple_webshells_0025 {
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_c99shell_v1_0_php_php_c99php_SsEs_php_php"
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
	strings:
		$s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword
	condition:
		1 of them
}

rule multiple_webshells_0026 {
	meta:
		description = "Semi-Auto-generated  - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_Crystal_php_nshell_php_php_load_shell_php_php"
		hash0 = "fdbf54d5bf3264eb1c4bff1fac548879"
		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
		hash2 = "0c5d227f4aa76785e4760cdcff78a661"
	strings:
		$s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
		$s1 = "$dires = $dires . $directory;" fullword
		$s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword
	condition:
		2 of them
}

rule multiple_webshells_0027 {
	meta:
		description = "Semi-Auto-generated  - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_nst_php_php_cybershell_php_php_img_php_php_nstview_php_php"
		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
		hash1 = "ef8828e0bc0641a655de3932199c0527"
		hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
		hash3 = "4745d510fed4378e4b1730f56f25e569"
	strings:
		$s0 = "@$rto=$_POST['rto'];" fullword
		$s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
		$s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword
	condition:
		2 of them
}

rule multiple_webshells_0028 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, dC3 Security Crew Shell PRiV.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_dC3_Security_Crew_Shell_PRiV_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "433706fdc539238803fd47c4394b5109"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = " if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":"
		$s1 = " $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";" fullword
	condition:
		all of them
}

rule multiple_webshells_0029 {
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_c99shell_v1_0_php_php_c99php_1_c2007_php_php_c100_php"
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash3 = "d089e7168373a0634e1ac18c0ee00085"
		hash4 = "38fd7e45f9c11a37463c3ded1c76af4c"
	strings:
		$s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword
	condition:
		all of them
}

rule multiple_php_webshells_2 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash6 = "09609851caa129e40b0d56e90dfc476c"
		hash7 = "671cad517edd254352fe7e0c7c981c39"
	strings:
		$s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I"
		$s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma"
		$s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword
	condition:
		all of them
}

rule multiple_webshells_0030 {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_1_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
	strings:
		$s0 = "if ($total === FALSE) {$total = 0;}" fullword
		$s1 = "$free_percent = round(100/($total/$free),2);" fullword
		$s2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}" fullword
		$s3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);" fullword
	condition:
		2 of them
}

rule multiple_webshells_0031 {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_r57_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash3 = "817671e1bdc85e04cc3440bbd9288800"
	strings:
		$s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
		$s2 = "'eng_text30'=>'Cat file'," fullword
		$s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword
	condition:
		1 of them
}

rule multiple_webshells_0032 {
	meta:
		description = "Semi-Auto-generated  - from files nixrem.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_nixrem_php_php_c99shell_v1_0_php_php_c99php_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_php"
		hash0 = "40a3e86a63d3d7f063a86aab5b5f92c6"
		hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash3 = "f3ca29b7999643507081caab926e2e74"
	strings:
		$s0 = "$num = $nixpasswd + $nixpwdperpage;" fullword
		$s1 = "$ret = posix_kill($pid,$sig);" fullword
		$s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}" fullword
		$s3 = "$i = $nixpasswd;" fullword
	condition:
		2 of them
}

/* GIF Header webshell */

rule DarkSecurityTeam_Webshell {
	meta:
		description = "Dark Security Team Webshell"
		author = "Florian Roth"
		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
		score = 50
	strings:
		$s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
	condition:
		1 of them
}

rule PHP_Cloaked_Webshell_SuperFetchExec {
	meta:
		description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
		reference = "http://goo.gl/xFvioC"
		author = "Florian Roth"
		score = 50
	strings:
		$s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
	condition:
		$s0
}

/* PHP Webshell Update - August 2014 - deducted from https://github.com/JohnTroony/php-webshells */

rule WebShell_RemExp_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
		author = "Florian Roth"
		hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"
	strings:
		$s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
		$s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
		$s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
		$s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
		$s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
	condition:
		all of them
}

rule WebShell_dC3_Security_Crew_Shell_PRiV {
	meta:
		description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
		author = "Florian Roth"
		hash = "1b2a4a7174ca170b4e3a8cdf4814c92695134c8a"
	strings:
		$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
		$s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
		$s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
		$s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
		$s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
		$s20 = "if (isset($_GET['rename_all'])) {" fullword
	condition:
		3 of them
}

rule WebShell_simattacker {
	meta:
		description = "PHP Webshells Github Archive - file simattacker.php"
		author = "Florian Roth"
		hash = "258297b62aeaf4650ce04642ad5f19be25ec29c9"
	strings:
		$s1 = "$from = rand (71,1020000000).\"@\".\"Attacker.com\";" fullword
		$s4 = "&nbsp;Turkish Hackers : WWW.ALTURKS.COM <br>" fullword
		$s5 = "&nbsp;Programer : SimAttacker - Edited By KingDefacer<br>" fullword
		$s6 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
		$s10 = "&nbsp;e-mail : kingdefacer@msn.com<br>" fullword
		$s17 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
		$s18 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
		$s20 = "$Comments=$_POST['Comments'];" fullword
	condition:
		2 of them
}

rule WebShell_DTool_Pro {
	meta:
		description = "PHP Webshells Github Archive - file DTool Pro.php"
		author = "Florian Roth"
		hash = "e2ee1c7ba7b05994f65710b7bbf935954f2c3353"
	strings:
		$s1 = "function PHPget(){inclVar(); if(confirm(\"O PHPget agora oferece uma lista pront"
		$s2 = "<font size=3>by r3v3ng4ns - revengans@gmail.com </font>" fullword
		$s3 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDig"
		$s11 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell" fullword
		$s13 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";" fullword
		$s14 = "//To keep the changes in the url, when using the 'GET' way to send php variables" fullword
		$s16 = "function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite "
		$s18 = "if(empty($fu)) $fu = @$_GET['fu'];" fullword
	condition:
		3 of them
}

rule WebShell_ironshell {
	meta:
		description = "PHP Webshells Github Archive - file ironshell.php"
		author = "Florian Roth"
		hash = "d47b8ba98ea8061404defc6b3a30839c4444a262"
	strings:
		$s0 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>" fullword
		$s2 = "$link = mysql_connect($_POST['host'], $_POST['username'], $_POST"
		$s4 = "error_reporting(0); //If there is an error, we'll show it, k?" fullword
		$s8 = "print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d"
		$s15 = "if(!is_numeric($_POST['timelimit']))" fullword
		$s16 = "if($_POST['chars'] == \"9999\")" fullword
		$s17 = "<option value=\\\"az\\\">a - zzzzz</option>" fullword
		$s18 = "print shell_exec($command);" fullword
	condition:
		3 of them
}

rule WebShell_indexer_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
		author = "Florian Roth"
		hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"
	strings:
		$s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
		$s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
		$s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
		$s4 = "<form action=\"?oku\" method=\"post\">" fullword
		$s7 = "var message=\"SaNaLTeRoR - " fullword
		$s8 = "nDexEr - Reader\"" fullword
	condition:
		3 of them
}

rule WebShell_toolaspshell {
	meta:
		description = "PHP Webshells Github Archive - file toolaspshell.php"
		author = "Florian Roth"
		hash = "11d236b0d1c2da30828ffd2f393dd4c6a1022e3f"
	strings:
		$s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef"
		$s12 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
		$s20 = "destino3 = folderItem.path & \"\\index.asp\"" fullword
	condition:
		2 of them
}

rule WebShell_b374k_mini_shell_php_php {
	meta:
		description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
		author = "Florian Roth"
		hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"
	strings:
		$s0 = "@error_reporting(0);" fullword
		$s2 = "@eval(gzinflate(base64_decode($code)));" fullword
		$s3 = "@set_time_limit(0); " fullword
	condition:
		all of them
}

rule WebShell_Sincap_1_0 {
	meta:
		description = "PHP Webshells Github Archive - file Sincap 1.0.php"
		author = "Florian Roth"
		hash = "9b72635ff1410fa40c4e15513ae3a496d54f971c"
	strings:
		$s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
		$s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
		$s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
		$s12 = "while (($ekinci=readdir ($sedat))){" fullword
		$s19 = "$deger2= \"$ich[$tampon4]\";" fullword
	condition:
		2 of them
}

rule WebShell_b374k_php {
	meta:
		description = "PHP Webshells Github Archive - file b374k.php.php"
		author = "Florian Roth"
		hash = "04c99efd187cf29dc4e5603c51be44170987bce2"
	strings:
		$s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
		$s6 = "// password (default is: b374k)"
		$s8 = "//******************************************************************************"
		$s9 = "// b374k 2.2" fullword
		$s10 = "eval(\"?>\".gzinflate(base64_decode("
	condition:
		3 of them
}

rule WebShell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend {
	meta:
		description = "PHP Webshells Github Archive - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		author = "Florian Roth"
		hash = "6454cc5ab73143d72cf0025a81bd1fe710351b44"
	strings:
		$s4 = "&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>" fullword
		$s5 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
		$s10 = "<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">" fullword
		$s16 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
		$s17 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
		$s19 = "$Comments=$_POST['Comments'];" fullword
		$s20 = "Victim Mail :<br><input type='text' name='to' ><br>" fullword
	condition:
		3 of them
}

rule WebShell_h4ntu_shell__powered_by_tsoi_ {
	meta:
		description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
		author = "Florian Roth"
		hash = "cbca8cd000e705357e2a7e0cf8262678706f18f9"
	strings:
		$s11 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
		$s13 = "$cmd = $_POST['cmd'];" fullword
		$s16 = "$uname = posix_uname( );" fullword
		$s17 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
		$s18 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>"
		$s20 = "ob_end_clean();" fullword
	condition:
		3 of them
}

rule WebShell_php_webshells_MyShell {
	meta:
		description = "PHP Webshells Github Archive - file MyShell.php"
		author = "Florian Roth"
		hash = "42e283c594c4d061f80a18f5ade0717d3fb2f76d"
	strings:
		$s3 = "<title>MyShell error - Access Denied</title>" fullword
		$s4 = "$adminEmail = \"youremail@yourserver.com\";" fullword
		$s5 = "//A workdir has been asked for - we chdir to that dir." fullword
		$s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
		$s13 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword
		$s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */" fullword
		$s19 = "#every command you excecute." fullword
		$s20 = "<form name=\"shell\" method=\"post\">" fullword
	condition:
		3 of them
}

rule WebShell_php_webshells_pws {
	meta:
		description = "PHP Webshells Github Archive - file pws.php"
		author = "Florian Roth"
		hash = "7a405f1c179a84ff8ac09a42177a2bcd8a1a481b"
	strings:
		$s6 = "if ($_POST['cmd']){" fullword
		$s7 = "$cmd = $_POST['cmd'];" fullword
		$s10 = "echo \"FILE UPLOADED TO $dez\";" fullword
		$s11 = "if (file_exists($uploaded)) {" fullword
		$s12 = "copy($uploaded, $dez);" fullword
		$s17 = "passthru($cmd);" fullword
	condition:
		4 of them
}

rule WebShell_reader_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file reader.asp.php.txt"
		author = "Florian Roth"
		hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"
	strings:
		$s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
		$s12 = " HACKING " fullword
		$s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
		$s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"
	condition:
		3 of them
}

rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2 {
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode_Bypass_PHP_4.4.2_and_PHP_5.1.2.php"
		author = "Florian Roth"
		hash = "db076b7c80d2a5279cab2578aa19cb18aea92832"
	strings:
		$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
		$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
		$s9 = "\".htmlspecialchars($file).\" has been already loaded. PHP Emperor <xb5@hotmail."
		$s11 = "die(\"<FONT COLOR=\\\"RED\\\"><CENTER>Sorry... File" fullword
		$s15 = "if(empty($_GET['file'])){" fullword
		$s16 = "echo \"<head><title>Safe Mode Shell</title></head>\"; " fullword
	condition:
		3 of them
}

rule WebShell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit {
	meta:
		description = "PHP Webshells Github Archive - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		author = "Florian Roth"
		hash = "b2b797707e09c12ff5e632af84b394ad41a46fa4"
	strings:
		$s4 = "$liz0zim=shell_exec($_POST[liz0]); " fullword
		$s6 = "$liz0=shell_exec($_POST[baba]); " fullword
		$s9 = "echo \"<b><font color=blue>Liz0ziM Private Safe Mode Command Execuriton Bypass E"
		$s12 = " :=) :</font><select size=\"1\" name=\"liz0\">" fullword
		$s13 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
	condition:
		1 of them
}

rule WebShell_php_backdoor {
	meta:
		description = "PHP Webshells Github Archive - file php-backdoor.php"
		author = "Florian Roth"
		hash = "b190c03af4f3fb52adc20eb0f5d4d151020c74fe"
	strings:
		$s5 = "http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=/etc on *nix" fullword
		$s6 = "// a simple php backdoor | coded by z0mbie [30.08.03] | http://freenet.am/~zombi"
		$s11 = "if(!isset($_REQUEST['dir'])) die('hey,specify directory!');" fullword
		$s13 = "else echo \"<a href='$PHP_SELF?f=$d/$dir'><font color=black>\";" fullword
		$s15 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
	condition:
		1 of them
}

rule WebShell_Worse_Linux_Shell {
	meta:
		description = "PHP Webshells Github Archive - file Worse Linux Shell.php"
		author = "Florian Roth"
		hash = "64623ab1246bc8f7d256b25f244eb2b41f543e96"
	strings:
		$s4 = "if( $_POST['_act'] == \"Upload!\" ) {" fullword
		$s5 = "print \"<center><h1>#worst @dal.net</h1></center>\";" fullword
		$s7 = "print \"<center><h1>Linux Shells</h1></center>\";" fullword
		$s8 = "$currentCMD = \"ls -la\";" fullword
		$s14 = "print \"<tr><td><b>System type:</b></td><td>$UName</td></tr>\";" fullword
		$s19 = "$currentCMD = str_replace(\"\\\\\\\\\",\"\\\\\",$_POST['_cmd']);" fullword
	condition:
		2 of them
}

rule WebShell_php_webshells_pHpINJ {
	meta:
		description = "PHP Webshells Github Archive - file pHpINJ.php"
		author = "Florian Roth"
		hash = "75116bee1ab122861b155cc1ce45a112c28b9596"
	strings:
		$s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
		$s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
		$s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN"
		$s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
		$s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
		$s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
		$s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
	condition:
		1 of them
}

rule WebShell_php_webshells_NGH {
	meta:
		description = "PHP Webshells Github Archive - file NGH.php"
		author = "Florian Roth"
		hash = "c05b5deecfc6de972aa4652cb66da89cfb3e1645"
	strings:
		$s0 = "<title>Webcommander at <?=$_SERVER[\"HTTP_HOST\"]?></title>" fullword
		$s2 = "/* Webcommander by Cr4sh_aka_RKL v0.3.9 NGH edition :p */" fullword
		$s5 = "<form action=<?=$script?>?act=bindshell method=POST>" fullword
		$s9 = "<form action=<?=$script?>?act=backconnect method=POST>" fullword
		$s11 = "<form action=<?=$script?>?act=mkdir method=POST>" fullword
		$s16 = "die(\"<font color=#DF0000>Login error</font>\");" fullword
		$s20 = "<b>Bind /bin/bash at port: </b><input type=text name=port size=8>" fullword
	condition:
		2 of them
}
