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

/* Generated from WShell_THOR_Webshells.yar; shard 6. Do not edit generated shards independently. */

rule WebShell_php_webshells_matamu {
	meta:
		description = "PHP Webshells Github Archive - file matamu.php"
		author = "Florian Roth"
		hash = "d477aae6bd2f288b578dbf05c1c46b3aaa474733"
	strings:
		$s2 = "$command .= ' -F';" fullword
		$s3 = "/* We try and match a cd command. */" fullword
		$s4 = "directory... Trust me - it works :-) */" fullword
		$s5 = "$command .= \" 1> $tmpfile 2>&1; \" ." fullword
		$s10 = "$new_dir = $regs[1]; // 'cd /something/...'" fullword
		$s16 = "/* The last / in work_dir were the first charecter." fullword
	condition:
		2 of them
}

rule WebShell_ru24_post_sh {
	meta:
		description = "PHP Webshells Github Archive - file ru24_post_sh.php"
		author = "Florian Roth"
		hash = "d2c18766a1cd4dda928c12ff7b519578ccec0769"
	strings:
		$s1 = "http://www.ru24-team.net" fullword
		$s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
		$s6 = "Ru24PostWebShell"
		$s7 = "Writed by DreAmeRz" fullword
		$s9 = "$function=passthru; // system, exec, cmd" fullword
	condition:
		1 of them
}

rule WebShell_hiddens_shell_v1 {
	meta:
		description = "PHP Webshells Github Archive - file hiddens shell v1.php"
		author = "Florian Roth"
		hash = "1674bd40eb98b48427c547bf9143aa7fbe2f4a59"
	strings:
		$s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
	condition:
		all of them
}

rule WebShell_c99_madnet {
	meta:
		description = "PHP Webshells Github Archive - file c99_madnet.php"
		author = "Florian Roth"
		hash = "17613df393d0a99fd5bea18b2d4707f566cff219"
	strings:
		$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
		$s1 = "eval(gzinflate(base64_decode('"
		$s2 = "$pass = \"pass\";  //Pass" fullword
		$s3 = "$login = \"user\"; //Login" fullword
		$s4 = "             //Authentication" fullword
	condition:
		all of them
}

rule WebShell_c99_locus7s {
	meta:
		description = "PHP Webshells Github Archive - file c99_locus7s.php"
		author = "Florian Roth"
		hash = "d413d4700daed07561c9f95e1468fb80238fbf3c"
	strings:
		$s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
		$s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y"
		$s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq"
		$s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
		$s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
	condition:
		2 of them
}

rule WebShell_JspWebshell_1_2 {
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
		author = "Florian Roth"
		hash = "0bed4a1966117dd872ac9e8dceceb54024a030fa"
	strings:
		$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
		$s1 = "String password=request.getParameter(\"password\");" fullword
		$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
		$s7 = "String editfile=request.getParameter(\"editfile\");" fullword
		$s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
		$s12 = "password = (String)session.getAttribute(\"password\");" fullword
	condition:
		3 of them
}

rule WebShell_safe0ver {
	meta:
		description = "PHP Webshells Github Archive - file safe0ver.php"
		author = "Florian Roth"
		hash = "366639526d92bd38ff7218b8539ac0f154190eb8"
	strings:
		$s3 = "$scriptident = \"$scriptTitle By Evilc0der.com\";" fullword
		$s4 = "while (file_exists(\"$lastdir/newfile$i.txt\"))" fullword
		$s5 = "else { /* <!-- Then it must be a File... --> */" fullword
		$s7 = "$contents .= htmlentities( $line ) ;" fullword
		$s8 = "<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">" fullword
		$s14 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
		$s20 = "/* <!-- End of Actions --> */" fullword
	condition:
		3 of them
}

rule WebShell_Uploader {
	meta:
		description = "PHP Webshells Github Archive - file Uploader.php"
		author = "Florian Roth"
		hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"
	strings:
		$s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
	condition:
		all of them
}

rule WebShell_php_webshells_kral {
	meta:
		description = "PHP Webshells Github Archive - file kral.php"
		author = "Florian Roth"
		hash = "4cd1d1a2fd448cecc605970e3a89f3c2e5c80dfc"
	strings:
		$s1 = "$adres=gethostbyname($ip);" fullword
		$s3 = "curl_setopt($ch,CURLOPT_POSTFIELDS,\"domain=\".$site);" fullword
		$s4 = "$ekle=\"/index.php?option=com_user&view=reset&layout=confirm\";" fullword
		$s16 = "echo $son.' <br> <font color=\"green\">Access</font><br>';" fullword
		$s17 = "<p>kodlama by <a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a><br /"
		$s20 = "<p><strong>Server listeleyici</strong><br />" fullword
	condition:
		2 of them
}

rule WebShell_cgitelnet {
	meta:
		description = "PHP Webshells Github Archive - file cgitelnet.php"
		author = "Florian Roth"
		hash = "72e5f0e4cd438e47b6454de297267770a36cbeb3"
	strings:
		$s9 = "# Author Homepage: http://www.rohitab.com/" fullword
		$s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
		$s18 = "# in a command line on Windows NT." fullword
		$s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword
	condition:
		2 of them
}

rule WebShell_simple_backdoor {
	meta:
		description = "PHP Webshells Github Archive - file simple-backdoor.php"
		author = "Florian Roth"
		hash = "edcd5157a68fa00723a506ca86d6cbb8884ef512"
	strings:
		$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
		$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
		$s3 = "        echo \"</pre>\";" fullword
		$s4 = "        $cmd = ($_REQUEST['cmd']);" fullword
		$s5 = "        echo \"<pre>\";" fullword
		$s6 = "if(isset($_REQUEST['cmd'])){" fullword
		$s7 = "        die;" fullword
		$s8 = "        system($cmd);" fullword
	condition:
		all of them
}

rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_2 {
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		author = "Florian Roth"
		hash = "8fdd4e0e87c044177e9e1c97084eb5b18e2f1c25"
	strings:
		$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
		$s3 = "xb5@hotmail.com</FONT></CENTER></B>\");" fullword
		$s4 = "$v = @ini_get(\"open_basedir\");" fullword
		$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
	condition:
		2 of them
}

rule WebShell_NTDaddy_v1_9 {
	meta:
		description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
		author = "Florian Roth"
		hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"
	strings:
		$s2 = "|     -obzerve : mr_o@ihateclowns.com |" fullword
		$s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s13 = "<form action=ntdaddy.asp method=post>" fullword
		$s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")" fullword
	condition:
		2 of them
}

rule WebShell_lamashell {
	meta:
		description = "PHP Webshells Github Archive - file lamashell.php"
		author = "Florian Roth"
		hash = "b71181e0d899b2b07bc55aebb27da6706ea1b560"
	strings:
		$s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
		$s8 = "$curcmd = $_POST['king'];" fullword
		$s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
		$s18 = "<title>lama's'hell v. 3.0</title>" fullword
		$s19 = "_|_  O    _    O  _|_" fullword
		$s20 = "$curcmd = \"ls -lah\";" fullword
	condition:
		2 of them
}

rule WebShell_Simple_PHP_backdoor_by_DK {
	meta:
		description = "PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php"
		author = "Florian Roth"
		hash = "03f6215548ed370bec0332199be7c4f68105274e"
	strings:
		$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
		$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
		$s6 = "if(isset($_REQUEST['cmd'])){" fullword
		$s8 = "system($cmd);" fullword
	condition:
		2 of them
}

rule WebShell_Moroccan_Spamers_Ma_EditioN_By_GhOsT {
	meta:
		description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
		author = "Florian Roth"
		hash = "31e5473920a2cc445d246bc5820037d8fe383201"
	strings:
		$s4 = "$content = chunk_split(base64_encode($content)); " fullword
		$s12 = "print \"Sending mail to $to....... \"; " fullword
		$s16 = "if (!$from && !$subject && !$message && !$emaillist){ " fullword
	condition:
		all of them
}

rule WebShell_C99madShell_v__2_0_madnet_edition {
	meta:
		description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
		author = "Florian Roth"
		hash = "f99f8228eb12746847f54bad45084f19d1a7e111"
	strings:
		$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
		$s1 = "eval(gzinflate(base64_decode('"
		$s2 = "$pass = \"\";  //Pass" fullword
		$s3 = "$login = \"\"; //Login" fullword
		$s4 = "//Authentication" fullword
	condition:
		all of them
}

rule WebShell_CmdAsp_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file CmdAsp.asp.php.txt"
		author = "Florian Roth"
		hash = "cb18e1ac11e37e236e244b96c2af2d313feda696"
	strings:
		$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s4 = "' Author: Maceo <maceo @ dogmile.com>" fullword
		$s5 = "' -- Use a poor man's pipe ... a temp file -- '" fullword
		$s6 = "' --------------------o0o--------------------" fullword
		$s8 = "' File: CmdAsp.asp" fullword
		$s11 = "<-- CmdAsp.asp -->" fullword
		$s14 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
		$s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
		$s19 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	condition:
		4 of them
}

rule WebShell_NCC_Shell {
	meta:
		description = "PHP Webshells Github Archive - file NCC-Shell.php"
		author = "Florian Roth"
		hash = "64d4495875a809b2730bd93bec2e33902ea80a53"
	strings:
		$s0 = " if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {" fullword
		$s1 = "<b>--Coded by Silver" fullword
		$s2 = "<title>Upload - Shell/Datei</title>" fullword
		$s8 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b><"
		$s14 = "~|_Team .:National Cracker Crew:._|~<br>" fullword
		$s18 = "printf(\"Sie ist %u Bytes gro" fullword
	condition:
		3 of them
}

rule WebShell_php_webshells_README {
	meta:
		description = "PHP Webshells Github Archive - file README.md"
		author = "Florian Roth"
		hash = "ef2c567b4782c994db48de0168deb29c812f7204"
	strings:
		$s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
		$s1 = "php-webshells" fullword
	condition:
		all of them
}

rule WebShell_backupsql {
	meta:
		description = "PHP Webshells Github Archive - file backupsql.php"
		author = "Florian Roth"
		hash = "863e017545ec8e16a0df5f420f2d708631020dd4"
	strings:
		$s0 = "$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" ."
		$s1 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
		$s2 = "* as email attachment, or send to a remote ftp server by" fullword
		$s16 = "* Neagu Mihai<neagumihai@hotmail.com>" fullword
		$s17 = "$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may "
	condition:
		2 of them
}

rule WebShell_AK_74_Security_Team_Web_Shell_Beta_Version {
	meta:
		description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
		author = "Florian Roth"
		hash = "c90b0ba575f432ecc08f8f292f3013b5532fe2c4"
	strings:
		$s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
		$s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'."
		$s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword
	condition:
		1 of them
}

rule WebShell_php_webshells_cpanel {
	meta:
		description = "PHP Webshells Github Archive - file cpanel.php"
		author = "Florian Roth"
		hash = "433dab17106b175c7cf73f4f094e835d453c0874"
	strings:
		$s0 = "function ftp_check($host,$user,$pass,$timeout){" fullword
		$s3 = "curl_setopt($ch, CURLOPT_URL, \"http://$host:2082\");" fullword
		$s4 = "[ user@alturks.com ]# info<b><br><font face=tahoma><br>" fullword
		$s12 = "curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);" fullword
		$s13 = "Powerful tool , ftp and cPanel brute forcer , php 5.2.9 safe_mode & open_basedir"
		$s20 = "<br><b>Please enter your USERNAME and PASSWORD to logon<br>" fullword
	condition:
		2 of them
}

rule WebShell_accept_language {
	meta:
		description = "PHP Webshells Github Archive - file accept_language.php"
		author = "Florian Roth"
		hash = "180b13576f8a5407ab3325671b63750adbcb62c9"
	strings:
		$s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword
	condition:
		all of them
}

rule WebShell_php_webshells_529 {
	meta:
		description = "PHP Webshells Github Archive - file 529.php"
		author = "Florian Roth"
		hash = "ba3fb2995528307487dff7d5b624d9f4c94c75d3"
	strings:
		$s0 = "<p>More: <a href=\"/\">Md5Cracking.Com Crew</a> " fullword
		$s7 = "href=\"/\" title=\"Securityhouse\">Security House - Shell Center - Edited By Kin"
		$s9 = "echo '<PRE><P>This is exploit from <a " fullword
		$s10 = "This Exploit Was Edited By KingDefacer" fullword
		$s13 = "safe_mode and open_basedir Bypass PHP 5.2.9 " fullword
		$s14 = "$hardstyle = explode(\"/\", $file); " fullword
		$s20 = "while($level--) chdir(\"..\"); " fullword
	condition:
		2 of them
}

rule WebShell_STNC_WebShell_v0_8 {
	meta:
		description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
		author = "Florian Roth"
		hash = "52068c9dff65f1caae8f4c60d0225708612bb8bc"
	strings:
		$s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
		$s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
		$s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"
	condition:
		2 of them
}

rule WebShell_php_webshells_tryag {
	meta:
		description = "PHP Webshells Github Archive - file tryag.php"
		author = "Florian Roth"
		hash = "42d837e9ab764e95ed11b8bd6c29699d13fe4c41"
	strings:
		$s1 = "<title>TrYaG Team - TrYaG.php - Edited By KingDefacer</title>" fullword
		$s3 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\"; " fullword
		$s6 = "$string = !empty($_POST['string']) ? $_POST['string'] : 0; " fullword
		$s7 = "$tabledump .= \"CREATE TABLE $table (\\n\"; " fullword
		$s14 = "echo \"<center><div id=logostrip>Edit file: $editfile </div><form action='$REQUE"
	condition:
		3 of them
}

rule WebShell_dC3_Security_Crew_Shell_PRiV_2 {
	meta:
		description = "PHP Webshells Github Archive - file dC3 Security Crew Shell PRiV.php"
		author = "Florian Roth"
		hash = "9077eb05f4ce19c31c93c2421430dd3068a37f17"
	strings:
		$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
		$s9 = "header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));" fullword
		$s13 = "header(\"Content-type: image/gif\");" fullword
		$s14 = "@copy($file,$to) or die (\"[-]Error copying file!\");" fullword
		$s20 = "if (isset($_GET['rename_all'])) {" fullword
	condition:
		3 of them
}

rule WebShell_qsd_php_backdoor {
	meta:
		description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
		author = "Florian Roth"
		hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"
	strings:
		$s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
		$s2 = "if(isset($_POST[\"newcontent\"]))" fullword
		$s3 = "foreach($parts as $val)//Assemble the path back together" fullword
		$s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));" fullword
	condition:
		2 of them
}

rule WebShell_php_webshells_spygrup {
	meta:
		description = "PHP Webshells Github Archive - file spygrup.php"
		author = "Florian Roth"
		hash = "12f9105332f5dc5d6360a26706cd79afa07fe004"
	strings:
		$s2 = "kingdefacer@msn.com</FONT></CENTER></B>\");" fullword
		$s6 = "if($_POST['root']) $root = $_POST['root'];" fullword
		$s12 = "\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>" fullword
		$s18 = "By KingDefacer From Spygrup.org>" fullword
	condition:
		3 of them
}

rule WebShell_Web_shell__c_ShAnKaR {
	meta:
		description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
		author = "Florian Roth"
		hash = "3dd4f25bd132beb59d2ae0c813373c9ea20e1b7a"
	strings:
		$s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
		$s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump"
		$s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
		$s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
	condition:
		2 of them
}

rule WebShell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz {
	meta:
		description = "PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php"
		author = "Florian Roth"
		hash = "5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68"
	strings:
		$s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">" fullword
		$s11 = "directory... Trust me - it works :-) */" fullword
		$s15 = "/* ls looks much better with ' -F', IMHO. */" fullword
		$s16 = "} else if ($command == 'ls') {" fullword
	condition:
		3 of them
}

rule WebShell_Gamma_Web_Shell {
	meta:
		description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
		author = "Florian Roth"
		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"
	strings:
		$s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
		$s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
		$s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
		$s20 = "my $command = $self->query('command');" fullword
	condition:
		2 of them
}

rule WebShell_php_webshells_aspydrv {
	meta:
		description = "PHP Webshells Github Archive - file aspydrv.php"
		author = "Florian Roth"
		hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"
	strings:
		$s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
		$s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
		$s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
		$s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
		$s20 = "' ---Copy Too Folder routine Start" fullword
	condition:
		3 of them
}

rule WebShell_JspWebshell_1_2_2 {
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
		author = "Florian Roth"
		hash = "184fc72b51d1429c44a4c8de43081e00967cf86b"
	strings:
		$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
		$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
		$s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
		$s15 = "endPoint=random1.getFilePointer();" fullword
		$s20 = "if (request.getParameter(\"command\") != null) {" fullword
	condition:
		3 of them
}

rule WebShell_g00nshell_v1_3 {
	meta:
		description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
		author = "Florian Roth"
		hash = "70fe072e120249c9e2f0a8e9019f984aea84a504"
	strings:
		$s10 = "#To execute commands, simply include ?cmd=___ in the url. #" fullword
		$s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];" fullword
		$s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent" fullword
		$s17 = "echo(\"<form method='GET' name='shell'>\");" fullword
		$s18 = "echo(\"<form method='post' action='?act=sql'>\");" fullword
	condition:
		2 of them
}

rule WebShell_WinX_Shell {
	meta:
		description = "PHP Webshells Github Archive - file WinX Shell.php"
		author = "Florian Roth"
		hash = "a94d65c168344ad9fa406d219bdf60150c02010e"
	strings:
		$s4 = "// It's simple shell for all Win OS." fullword
		$s5 = "//------- [netstat -an] and [ipconfig] and [tasklist] ------------" fullword
		$s6 = "<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>" fullword
		$s13 = "// Created by greenwood from n57" fullword
		$s20 = " if (is_uploaded_file($userfile)) {" fullword
	condition:
		3 of them
}

rule WebShell_PHANTASMA {
	meta:
		description = "PHP Webshells Github Archive - file PHANTASMA.php"
		author = "Florian Roth"
		hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"
	strings:
		$s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword
		$s15 = "if ($portscan != \"\") {" fullword
		$s16 = "echo \"<br>Banner: $get <br><br>\";" fullword
		$s20 = "$dono = get_current_user( );" fullword
	condition:
		3 of them
}

rule WebShell_php_webshells_cw {
	meta:
		description = "PHP Webshells Github Archive - file cw.php"
		author = "Florian Roth"
		hash = "e65e0670ef6edf0a3581be6fe5ddeeffd22014bf"
	strings:
		$s1 = "// Dump Database [pacucci.com]" fullword
		$s2 = "$dump = \"-- Database: \".$_POST['db'] .\" \\n\";" fullword
		$s7 = "$aids = passthru(\"perl cbs.pl \".$_POST['connhost'].\" \".$_POST['connport']);" fullword
		$s8 = "<b>IP:</b> <u>\" . $_SERVER['REMOTE_ADDR'] .\"</u> - Server IP:</b> <a href='htt"
		$s14 = "$dump .= \"-- Cyber-Warrior.Org\\n\";" fullword
		$s20 = "if(isset($_POST['doedit']) && $_POST['editfile'] != $dir)" fullword
	condition:
		3 of them
}

rule WebShell_php_include_w_shell {
	meta:
		description = "PHP Webshells Github Archive - file php-include-w-shell.php"
		author = "Florian Roth"
		hash = "1a7f4868691410830ad954360950e37c582b0292"
	strings:
		$s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
		$s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
		$s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
	condition:
		1 of them
}

rule WebShell_mysql_tool {
	meta:
		description = "PHP Webshells Github Archive - file mysql_tool.php"
		author = "Florian Roth"
		hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"
	strings:
		$s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
		$s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
	condition:
		2 of them
}

rule WebShell_PhpSpy_Ver_2006 {
	meta:
		description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
		author = "Florian Roth"
		hash = "34a89e0ab896c3518d9a474b71ee636ca595625d"
	strings:
		$s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
		$s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
		$s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32"
		$s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'"
	condition:
		1 of them
}

rule WebShell_ZyklonShell {
	meta:
		description = "PHP Webshells Github Archive - file ZyklonShell.php"
		author = "Florian Roth"
		hash = "3fa7e6f3566427196ac47551392e2386a038d61c"
	strings:
		$s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
		$s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
		$s2 = "<TITLE>404 Not Found</TITLE>" fullword
		$s3 = "<H1>Not Found</H1>" fullword
	condition:
		all of them
}

rule WebShell_php_webshells_myshell {
	meta:
		description = "PHP Webshells Github Archive - file myshell.php"
		author = "Florian Roth"
		hash = "5bd52749872d1083e7be076a5e65ffcde210e524"
	strings:
		$s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu"
		$s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
		$s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
		$s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT"
	condition:
		1 of them
}

rule WebShell_php_webshells_lolipop {
	meta:
		description = "PHP Webshells Github Archive - file lolipop.php"
		author = "Florian Roth"
		hash = "86f23baabb90c93465e6851e40104ded5a5164cb"
	strings:
		$s3 = "$commander = $_POST['commander']; " fullword
		$s9 = "$sourcego = $_POST['sourcego']; " fullword
		$s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
	condition:
		all of them
}

rule WebShell_simple_cmd {
	meta:
		description = "PHP Webshells Github Archive - file simple_cmd.php"
		author = "Florian Roth"
		hash = "466a8caf03cdebe07aa16ad490e54744f82e32c2"
	strings:
		$s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s2 = "<title>G-Security Webshell</title>" fullword
		$s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
	condition:
		1 of them
}

rule WebShell_go_shell {
	meta:
		description = "PHP Webshells Github Archive - file go-shell.php"
		author = "Florian Roth"
		hash = "3dd85981bec33de42c04c53d081c230b5fc0e94f"
	strings:
		$s0 = "#change this password; for power security - delete this file =)" fullword
		$s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword
		$s11 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword
		$s12 = "print << \"[kalabanga]\";" fullword
		$s13 = "<title>GO.cgi</title>" fullword
	condition:
		1 of them
}

rule WebShell_aZRaiLPhp_v1_0 {
	meta:
		description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
		author = "Florian Roth"
		hash = "a2c609d1a8c8ba3d706d1d70bef69e63f239782b"
	strings:
		$s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED"
		$s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
		$s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
		$s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword
	condition:
		2 of them
}

rule WebShell_webshells_zehir4 {
	meta:
		description = "Webshells Github Archive - file zehir4"
		author = "Florian Roth"
		hash = "788928ae87551f286d189e163e55410acbb90a64"
		score = 55
	strings:
		$s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
		$s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"
	condition:
		1 of them
}

rule WebShell_zehir4_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
		author = "Florian Roth"
		hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"
	strings:
		$s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
		$s11 = "frames.byZehir.document.execCommand("
		$s15 = "frames.byZehir.document.execCommand(co"
	condition:
		2 of them
}

rule WebShell_php_webshells_lostDC {
	meta:
		description = "PHP Webshells Github Archive - file lostDC.php"
		author = "Florian Roth"
		hash = "d54fe07ea53a8929620c50e3a3f8fb69fdeb1cde"
	strings:
		$s0 = "$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';" fullword
		$s4 = "header ( \"Content-Description: Download manager\" );" fullword
		$s5 = "print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second"
		$s9 = "if (mkdir($_POST['dir'], 0777) == false) {" fullword
		$s12 = "$ret = shellexec($command);" fullword
	condition:
		2 of them
}

rule WebShell_CasuS_1_5 {
	meta:
		description = "PHP Webshells Github Archive - file CasuS 1.5.php"
		author = "Florian Roth"
		hash = "7eee8882ad9b940407acc0146db018c302696341"
	strings:
		$s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
		$s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");" fullword
		$s18 = "if (file_exists(\"F:\\\\\")){" fullword
	condition:
		1 of them
}

rule WebShell_ftpsearch {
	meta:
		description = "PHP Webshells Github Archive - file ftpsearch.php"
		author = "Florian Roth"
		hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"
	strings:
		$s0 = "echo \"[-] Error : coudn't read /etc/passwd\";" fullword
		$s9 = "@$ftp=ftp_connect('127.0.0.1');" fullword
		$s12 = "echo \"<title>Edited By KingDefacer</title><body>\";" fullword
		$s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";" fullword
	condition:
		2 of them
}

rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0_ {
	meta:
		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
	strings:
		$s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</"
		$s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh"
		$s11 = " *   Coded by Pixcher" fullword
		$s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword
	condition:
		2 of them
}

rule WebShell__Ajax_PHP_Command_Shell_Ajax_PHP_Command_Shell_soldierofallah {
	meta:
		description = "PHP Webshells Github Archive - from files Ajax_PHP Command Shell.php, Ajax_PHP_Command_Shell.php, soldierofallah.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "fa11deaee821ca3de7ad1caafa2a585ee1bc8d82"
		hash1 = "c0a4ba3e834fb63e0a220a43caaf55c654f97429"
		hash2 = "16fa789b20409c1f2ffec74484a30d0491904064"
	strings:
		$s1 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\"," fullword
		$s2 = "'Running processes' => \"runcommand('ps -aux','GET')\"," fullword
		$s3 = "$dt = $_POST['filecontent'];" fullword
		$s4 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\"," fullword
		$s6 = "print \"Sorry, none of the command functions works.\";" fullword
		$s11 = "document.cmdform.command.value='';" fullword
		$s12 = "elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST"
	condition:
		3 of them
}

rule WebShell_Generic_PHP_7 {
	meta:
		description = "PHP Webshells Github Archive - from files Mysql interface v1.0.php, MySQL Web Interface Version 0.8.php, Mysql_interface_v1.0.php, MySQL_Web_Interface_Version_0.8.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "de98f890790756f226f597489844eb3e53a867a9"
		hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
		hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
		hash3 = "715f17e286416724e90113feab914c707a26d456"
	strings:
		$s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
		$s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
		$s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
		$s4 = "if( $action == \"dumpTable\" )" fullword
	condition:
		2 of them
}

rule WebShell__Small_Web_Shell_by_ZaCo_small_zaco_zacosmall {
	meta:
		description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "b148ead15d34a55771894424ace2a92983351dda"
		hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
		hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
		hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"
	strings:
		$s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword
		$s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword
		$s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword
		$s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);" fullword
	condition:
		2 of them
}

rule WebShell_Generic_PHP_8 {
	meta:
		description = "PHP Webshells Github Archive - from files Macker's Private PHPShell.php, PHP Shell.php, Safe0ver Shell -Safe Mod Bypass By Evilc0der.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "fc1ae242b926d70e32cdb08bbe92628bc5bd7f99"
		hash1 = "9ad55629c4576e5a31dd845012d13a08f1c1f14e"
		hash2 = "c4aa2cf665c784553740c3702c3bfcb5d7af65a3"
	strings:
		$s1 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword
		$s2 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
		$s3 = "/* I added this to ensure the script will run correctly..." fullword
		$s14 = "<!--    </form>   -->" fullword
		$s15 = "<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\">" fullword
		$s20 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword
	condition:
		3 of them
}

rule WebShell__PH_Vayv_PHVayv_PH_Vayv_klasvayv_asp_php {
	meta:
		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php, klasvayv.asp.php.txt"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
		hash3 = "4f83bc2836601225a115b5ad54496428a507a361"
	strings:
		$s1 = "<font color=\"#000000\">Sil</font></a></font></td>" fullword
		$s5 = "<td width=\"122\" height=\"17\" bgcolor=\"#9F9F9F\">" fullword
		$s6 = "onfocus=\"if (this.value == 'Kullan" fullword
		$s16 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\">"
	condition:
		2 of them
}

rule WebShell_Generic_PHP_9 {
	meta:
		description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "89f2a7007a2cd411e0a7abd2ff5218d212b84d18"
		hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
		hash2 = "0daed818cac548324ad0c5905476deef9523ad73"
	strings:
		$s2 = ":<b>\" .base64_decode($_POST['tot']). \"</b>\";" fullword
		$s6 = "if (isset($_POST['wq']) && $_POST['wq']<>\"\") {" fullword
		$s12 = "if (!empty($_POST['c'])){" fullword
		$s13 = "passthru($_POST['c']);" fullword
		$s16 = "<input type=\"radio\" name=\"tac\" value=\"1\">B64 Decode<br>" fullword
		$s20 = "<input type=\"radio\" name=\"tac\" value=\"3\">md5 Hash" fullword
	condition:
		3 of them
}

rule WebShell__PH_Vayv_PHVayv_PH_Vayv {
	meta:
		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
	strings:
		$s4 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle"
		$s12 = "<? if ($ekinci==\".\" or  $ekinci==\"..\") {" fullword
		$s17 = "name=\"duzenx2\" value=\"Klas" fullword
	condition:
		2 of them
}

rule WebShell_Generic_PHP_1 {
	meta:
		description = "PHP Webshells Github Archive - from files Dive Shell 1.0 - Emperor Hacking Team.php, Dive_Shell_1.0_Emperor_Hacking_Team.php, SimShell 1.0 - Simorgh Security MGZ.php, SimShell_1.0_-_Simorgh_Security_MGZ.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "3b086b9b53cf9d25ff0d30b1d41bb2f45c7cda2b"
		hash1 = "2558e728184b8efcdb57cfab918d95b06d45de04"
		hash2 = "203a8021192531d454efbc98a3bbb8cabe09c85c"
		hash3 = "b79709eb7801a28d02919c41cc75ac695884db27"
	strings:
		$s1 = "$token = substr($_REQUEST['command'], 0, $length);" fullword
		$s4 = "var command_hist = new Array(<?php echo $js_command_hist ?>);" fullword
		$s7 = "$_SESSION['output'] .= htmlspecialchars(fgets($io[1])," fullword
		$s9 = "document.shell.command.value = command_hist[current_line];" fullword
		$s16 = "$_REQUEST['command'] = $aliases[$token] . substr($_REQUEST['command'], $"
		$s19 = "if (empty($_SESSION['cwd']) || !empty($_REQUEST['reset'])) {" fullword
		$s20 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword
	condition:
		5 of them
}

rule WebShell_Generic_PHP_2 {
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash2 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash3 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
	strings:
		$s3 = "if((isset($_POST['fileto']))||(isset($_POST['filefrom'])))" fullword
		$s4 = "\\$port = {$_POST['port']};" fullword
		$s5 = "$_POST['installpath'] = \"temp.pl\";}" fullword
		$s14 = "if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"u"
		$s16 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"]"
	condition:
		4 of them
}

rule WebShell__CrystalShell_v_1_erne_stres {
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, erne.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "6eb4ab630bd25bec577b39fb8a657350bf425687"
		hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
	strings:
		$s1 = "<input type='submit' value='  open (shill.txt) '>" fullword
		$s4 = "var_dump(curl_exec($ch));" fullword
		$s7 = "if(empty($_POST['Mohajer22'])){" fullword
		$s10 = "$m=$_POST['curl'];" fullword
		$s13 = "$u1p=$_POST['copy'];" fullword
		$s14 = "if(empty(\\$_POST['cmd'])){" fullword
		$s15 = "$string = explode(\"|\",$string);" fullword
		$s16 = "$stream = imap_open(\"/etc/passwd\", \"\", \"\");" fullword
	condition:
		5 of them
}

rule WebShell_Generic_PHP_3 {
	meta:
		description = "PHP Webshells Github Archive - from files Antichat Shell v1.3.php, Antichat Shell. Modified by Go0o$E.php, Antichat Shell.php, fatal.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "d829e87b3ce34460088c7775a60bded64e530cd4"
		hash1 = "d710c95d9f18ec7c76d9349a28dd59c3605c02be"
		hash2 = "f044d44e559af22a1a7f9db72de1206f392b8976"
		hash3 = "41780a3e8c0dc3cbcaa7b4d3c066ae09fb74a289"
	strings:
		$s0 = "header('Content-Length:'.filesize($file).'');" fullword
		$s4 = "<textarea name=\\\"command\\\" rows=\\\"5\\\" cols=\\\"150\\\">\".@$_POST['comma"
		$s7 = "if(filetype($dir . $file)==\"file\")$files[]=$file;" fullword
		$s14 = "elseif (($perms & 0x6000) == 0x6000) {$info = 'b';} " fullword
		$s20 = "$info .= (($perms & 0x0004) ? 'r' : '-');" fullword
	condition:
		all of them
}

rule WebShell_Generic_PHP_4 {
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, nshell.php, Loaderz WEB Shell.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash2 = "86bc40772de71b1e7234d23cab355e1ff80c474d"
		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
	strings:
		$s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
		$s2 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-';" fullword
		$s5 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword
		$s6 = "$world[\"write\"] = ($mode & 00002) ? 'w' : '-';" fullword
		$s7 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword
		$s10 = "foreach ($arr as $filename) {" fullword
		$s19 = "else if( $mode & 0x6000 ) { $type='b'; }" fullword
	condition:
		all of them
}
/*
rule WebShell_Generic_PHP_5 {
	meta:
		description = "PHP Webshells Github Archive - from files ex0shell.php, megabor.php, GRP WebShell 2.0 release build 2018 (C)2006,Great.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "64461ad8d8f23ea078201a31d747157f701a4e00"
		hash1 = "3df1afbcfa718da6fc8af27554834ff6d1a86562"
		hash2 = "ad86ef7f24f75081318146edc788e5466722a629"
	strings:
		$s0 = "(($perms & 0x0400) ? 'S' : '-'));" fullword
		$s10 = "} elseif (($perms & 0x8000) == 0x8000) {" fullword
		$s11 = "if (($perms & 0xC000) == 0xC000) {" fullword
		$s12 = "$info .= (($perms & 0x0008) ?" fullword
		$s16 = "// Block special" fullword
		$s18 = "$info = 's';" fullword
	condition:
		all of them
}
*/

rule WebShell_GFS {
	meta:
		description = "PHP Webshells Github Archive - from files GFS web-shell ver 3.1.7 - PRiV8.php, Predator.php, GFS_web-shell_ver_3.1.7_-_PRiV8.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "c2f1ef6b11aaec255d4dd31efad18a3869a2a42c"
		hash1 = "34f6640985b07009dbd06cd70983451aa4fe9822"
		hash2 = "d25ef72bdae3b3cb0fc0fdd81cfa58b215812a50"
	strings:
		$s0 = "OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==\";" fullword
		$s1 = "lIENPTk47DQpleGl0IDA7DQp9DQp9\";" fullword
		$s2 = "Ow0KIGR1cDIoZmQsIDIpOw0KIGV4ZWNsKCIvYmluL3NoIiwic2ggLWkiLCBOVUxMKTsNCiBjbG9zZShm"
	condition:
		all of them
}

rule WebShell__CrystalShell_v_1_sosyete_stres {
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, sosyete.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "e32405e776e87e45735c187c577d3a4f98a64059"
		hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
	strings:
		$s1 = "A:visited { COLOR:blue; TEXT-DECORATION: none}" fullword
		$s4 = "A:active {COLOR:blue; TEXT-DECORATION: none}" fullword
		$s11 = "scrollbar-darkshadow-color: #101842;" fullword
		$s15 = "<a bookmark=\"minipanel\">" fullword
		$s16 = "background-color: #EBEAEA;" fullword
		$s18 = "color: #D5ECF9;" fullword
		$s19 = "<center><TABLE style=\"BORDER-COLLAPSE: collapse\" height=1 cellSpacing=0 border"
	condition:
		all of them
}

rule WebShell_Generic_PHP_10 {
	meta:
		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php, PHPRemoteView.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
		hash3 = "7d5b54c7cab6b82fb7d131d7bbb989fd53cb1b57"
	strings:
		$s2 = "$world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T'; " fullword
		$s6 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-'; " fullword
		$s11 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-'; " fullword
		$s12 = "else if( $mode & 0xA000 ) " fullword
		$s17 = "$s=sprintf(\"%1s\", $type); " fullword
		$s20 = "font-size: 8pt;" fullword
	condition:
		all of them
}

rule WebShell_Generic_PHP_11 {
	meta:
		description = "PHP Webshells Github Archive - from files rootshell.php, Rootshell.v.1.0.php, s72 Shell v1.1 Coding.php, s72_Shell_v1.1_Coding.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "31a82cbee8dffaf8eb7b73841f3f3e8e9b3e78cf"
		hash1 = "838c7191cb10d5bb0fc7460b4ad0c18c326764c6"
		hash2 = "8dfcd919d8ddc89335307a7b2d5d467b1fd67351"
		hash3 = "80aba3348434c66ac471daab949871ab16c50042"
	strings:
		$s5 = "$filename = $backupstring.\"$filename\";" fullword
		$s6 = "while ($file = readdir($folder)) {" fullword
		$s7 = "if($file != \".\" && $file != \"..\")" fullword
		$s9 = "$backupstring = \"copy_of_\";" fullword
		$s10 = "if( file_exists($file_name))" fullword
		$s13 = "global $file_name, $filename;" fullword
		$s16 = "copy($file,\"$filename\");" fullword
		$s18 = "<td width=\"49%\" height=\"142\">" fullword
	condition:
		all of them
}

rule WebShell__findsock_php_findsock_shell_php_reverse_shell {
	meta:
		description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "5622c9841d76617bfc3cd4cab1932d8349b7044f"
		hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
		hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"
	strings:
		$s1 = "// me at pentestmonkey@pentestmonkey.net" fullword
	condition:
		all of them
}

rule WebShell_Generic_PHP_6 {
	meta:
		description = "PHP Webshells Github Archive - from files c0derz shell [csh] v. 0.1.1 release.php, CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "1a08f5260c4a2614636dfc108091927799776b13"
		hash1 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash2 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
	strings:
		$s2 = "@eval(stripslashes($_POST['phpcode']));" fullword
		$s5 = "echo shell_exec($com);" fullword
		$s7 = "if($sertype == \"winda\"){" fullword
		$s8 = "function execute($com)" fullword
		$s12 = "echo decode(execute($cmd));" fullword
		$s15 = "echo system($com);" fullword
	condition:
		4 of them
}

rule Unpack_Injectt {
	meta:
		description = "Webshells Auto-generated - file Injectt.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8a5d2158a566c87edc999771e12d42c5"
	strings:
		$s2 = "%s -Run                              -->To Install And Run The Service"
		$s3 = "%s -Uninstall                        -->To Uninstall The Service"
		$s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN"
	condition:
		all of them
}

rule HYTop_DevPack_fso {
	meta:
		description = "Webshells Auto-generated - file fso.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b37f3cde1a08890bd822a182c3a881f6"
	strings:
		$s0 = "<!-- PageFSO Below -->"
		$s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"
	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_ssh {
	meta:
		description = "Webshells Auto-generated - file ssh.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1aa5307790d72941589079989b4f900e"
	strings:
		$s0 = "eval(gzinflate(str_rot13(base64_decode('"
	condition:
		all of them
}
