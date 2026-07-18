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

/* Generated from WShell_THOR_Webshells.yar; shard 7. Do not edit generated shards independently. */

rule Debug_BDoor {
	meta:
		description = "Webshells Auto-generated - file BDoor.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "e4e8e31dd44beb9320922c5f49739955"
	strings:
		$s1 = "\\BDoor\\"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
	condition:
		all of them
}

rule bin_Client {
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f91a5b46d155cacf0cc6673a2a5461b"
	strings:
		$s0 = "Recieved respond from server!!"
		$s4 = "packet door client"
		$s5 = "input source port(whatever you want):"
		$s7 = "Packet sent,waiting for reply..."
	condition:
		all of them
}

rule ZXshell2_0_rar_Folder_ZXshell {
	meta:
		description = "Webshells Auto-generated - file ZXshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "246ce44502d2f6002d720d350e26c288"
	strings:
		$s0 = "WPreviewPagesn"
		$s1 = "DA!OLUTELY N"
	condition:
		all of them
}

rule RkNTLoad {
	meta:
		description = "Webshells Auto-generated - file RkNTLoad.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "262317c95ced56224f136ba532b8b34f"
	strings:
		$s1 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s2 = "5pur+virtu!"
		$s3 = "ugh spac#n"
		$s4 = "xcEx3WriL4"
		$s5 = "runtime error"
		$s6 = "loseHWait.Sr."
		$s7 = "essageBoxAw"
		$s8 = "$Id: UPX 1.07 Copyright (C) 1996-2001 the UPX Team. All Rights Reserved. $"
	condition:
		all of them
}

rule binder2_binder2 {
	meta:
		description = "Webshells Auto-generated - file binder2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d594e90ad23ae0bc0b65b59189c12f11"
	strings:
		$s0 = "IsCharAlphaNumericA"
		$s2 = "WideCharToM"
		$s4 = "g 5pur+virtu!"
		$s5 = "\\syslog.en"
		$s6 = "heap7'7oqk?not="
		$s8 = "- Kablto in"
	condition:
		all of them
}

rule thelast_orice2 {
	meta:
		description = "Webshells Auto-generated - file orice2.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aa63ffb27bde8d03d00dda04421237ae"
	strings:
		$s0 = " $aa = $_GET['aa'];"
		$s1 = "echo $aa;"
	condition:
		all of them
}

rule FSO_s_sincap {
	meta:
		description = "Webshells Auto-generated - file sincap.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dc5c2c2392b84a1529abd92e98e9aa5b"
	strings:
		$s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">"
		$s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin="
	condition:
		all of them
}

rule PhpShell {
	meta:
		description = "Webshells Auto-generated - file PhpShell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "539baa0d39a9cf3c64d65ee7a8738620"
	strings:
		$s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>."
	condition:
		all of them
}

rule HYTop_DevPack_config {
	meta:
		description = "Webshells Auto-generated - file config.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b41d0e64e64a685178a3155195921d61"
	strings:
		$s0 = "const adminPassword=\""
		$s2 = "const userPassword=\""
		$s3 = "const mVersion="
	condition:
		all of them
}

rule sendmail {
	meta:
		description = "Webshells Auto-generated - file sendmail.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "75b86f4a21d8adefaf34b3a94629bd17"
	strings:
		$s3 = "_NextPyC808"
		$s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"
	condition:
		all of them
}

rule FSO_s_zehir4 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5b496a61363d304532bcf52ee21f5d55"
	strings:
		$s5 = " byMesaj "
	condition:
		all of them
}

rule hkshell_hkshell {
	meta:
		description = "Webshells Auto-generated - file hkshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "168cab58cee59dc4706b3be988312580"
	strings:
		$s1 = "PrSessKERNELU"
		$s2 = "Cur3ntV7sion"
		$s3 = "Explorer8"
	condition:
		all of them
}

rule iMHaPFtp {
	meta:
		description = "Webshells Auto-generated - file iMHaPFtp.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "12911b73bc6a5d313b494102abcf5c57"
	strings:
		$s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
	condition:
		all of them
}

rule Unpack_TBack {
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a9d1007823bf96fb163ab38726b48464"
	strings:
		$s5 = "\\final\\new\\lcc\\public.dll"
	condition:
		all of them
}

rule DarkSpy105 {
	meta:
		description = "Webshells Auto-generated - file DarkSpy105.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f0b85e7bec90dba829a3ede1ab7d8722"
	strings:
		$s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"
	condition:
		all of them
}

rule EditServer_Webshell {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f945de25e0eba3bdaf1455b3a62b9832"
	strings:
		$s2 = "Server %s Have Been Configured"
		$s5 = "The Server Password Exceeds 32 Characters"
		$s8 = "9--Set Procecess Name To Inject DLL"
	condition:
		all of them
}

rule FSO_s_reader {
	meta:
		description = "Webshells Auto-generated - file reader.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"
	strings:
		$s2 = "mailto:mailbomb@hotmail."
	condition:
		all of them
}

rule ASP_CmdAsp {
	meta:
		description = "Webshells Auto-generated - file CmdAsp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "79d4f3425f7a89befb0ef3bafe5e332f"
	strings:
		$s2 = "' -- Read the output from our command and remove the temp file -- '"
		$s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
		$s9 = "' -- create the COM objects that we will be using -- '"
	condition:
		all of them
}

rule KA_uShell {
	meta:
		description = "Webshells Auto-generated - file KA_uShell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "685f5d4f7f6751eaefc2695071569aab"
	strings:
		$s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
		$s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
	condition:
		all of them
}

rule PHP_Backdoor_v1 {
	meta:
		description = "Webshells Auto-generated - file PHP Backdoor v1.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0506ba90759d11d78befd21cabf41f3d"
	strings:

		$s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
		$s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"
	condition:
		all of them
}

rule svchostdll {
	meta:
		description = "Webshells Auto-generated - file svchostdll.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0f6756c8cb0b454c452055f189e4c3f4"
	strings:
		$s0 = "InstallService"
		$s1 = "RundllInstallA"
		$s2 = "UninstallService"
		$s3 = "&G3 Users In RegistryD"
		$s4 = "OL_SHUTDOWN;I"
		$s5 = "SvcHostDLL.dll"
		$s6 = "RundllUninstallA"
		$s7 = "InternetOpenA"
		$s8 = "Check Cloneomplete"
	condition:
		all of them
}

rule HYTop_DevPack_server {
	meta:
		description = "Webshells Auto-generated - file server.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1d38526a215df13c7373da4635541b43"
	strings:
		$s0 = "<!-- PageServer Below -->"
	condition:
		all of them
}

rule vanquish {
	meta:
		description = "Webshells Auto-generated - file vanquish.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "684450adde37a93e8bb362994efc898c"
	strings:
		$s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged"
		$s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU"
		$s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z"
	condition:
		all of them
}

rule winshell {
	meta:
		description = "Webshells Auto-generated - file winshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3144410a37dd4c29d004a814a294ea26"
	strings:
		$s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
		$s1 = "WinShell Service"
		$s2 = "__GLOBAL_HEAP_SELECTED"
		$s3 = "__MSVCRT_HEAP_SELECT"
		$s4 = "Provide Windows CmdShell Service"
		$s5 = "URLDownloadToFileA"
		$s6 = "RegisterServiceProcess"
		$s7 = "GetModuleBaseNameA"
		$s8 = "WinShell v5.0 (C)2002 janker.org"
	condition:
		all of them
}

rule FSO_s_remview {
	meta:
		description = "Webshells Auto-generated - file remview.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b4a09911a5b23e00b55abe546ded691c"
	strings:
		$s2 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\""
		$s3 = "         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\""
		$s4 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<"
	condition:
		all of them
}

rule saphpshell {
	meta:
		description = "Webshells Auto-generated - file saphpshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d7bba8def713512ddda14baf9cd6889a"
	strings:
		$s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"
	condition:
		all of them
}

rule HYTop2006_rar_Folder_2006Z {
	meta:
		description = "Webshells Auto-generated - file 2006Z.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "fd1b6129abd4ab177fed135e3b665488"
	strings:
		$s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
		$s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
	condition:
		all of them
}

rule admin_ad {
	meta:
		description = "Webshells Auto-generated - file admin-ad.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "e6819b8f8ff2f1073f7d46a0b192f43b"
	strings:
		$s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
		$s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"
	condition:
		all of them
}

rule FSO_s_casus15 {
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8d155b4239d922367af5d0a1b89533a3"
	strings:
		$s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"
	condition:
		all of them
}

rule BIN_Client {
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "9f0a74ec81bc2f26f16c5c172b80eca7"
	strings:
		$s0 = "=====Remote Shell Closed====="
		$s2 = "All Files(*.*)|*.*||"
		$s6 = "WSAStartup Error!"
		$s7 = "SHGetFileInfoA"
		$s8 = "CreateThread False!"
		$s9 = "Port Number Error"
	condition:
		4 of them
}

rule shelltools_g0t_root_uptime {
	meta:
		description = "Webshells Auto-generated - file uptime.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d1f56102bc5d3e2e37ab3ffa392073b9"
	strings:
		$s0 = "JDiamondCSlC~"
		$s1 = "CharactQA"
		$s2 = "$Info: This file is packed with the UPX executable packer $"
		$s5 = "HandlereateConso"
		$s7 = "ION\\System\\FloatingPo"
	condition:
		all of them
}

rule Simple_PHP_BackDooR {
	meta:
		description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a401132363eecc3a1040774bec9cb24f"
	strings:
		$s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
		$s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
		$s9 = "// a simple php backdoor"
	condition:
		1 of them
}

rule sig_2005Gray {
	meta:
		description = "Webshells Auto-generated - file 2005Gray.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "75dbe3d3b70a5678225d3e2d78b604cc"
	strings:
		$s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
		$s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
		$s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"
	condition:
		all of them
}

rule DllInjection {
	meta:
		description = "Webshells Auto-generated - file DllInjection.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a7b92283a5102886ab8aee2bc5c8d718"
	strings:
		$s0 = "\\BDoor\\DllInjecti"
	condition:
		all of them
}

rule Mithril_v1_45_Mithril {
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f1484f882dc381dde6eaa0b80ef64a07"
	strings:
		$s2 = "cress.exe"
		$s7 = "\\Debug\\Mithril."
	condition:
		all of them
}

rule hkshell_hkrmv {
	meta:
		description = "Webshells Auto-generated - file hkrmv.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "bd3a0b7a6b5536f8d96f50956560e9bf"
	strings:
		$s5 = "/THUMBPOSITION7"
		$s6 = "\\EvilBlade\\"
	condition:
		all of them
}

rule phpshell {
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1dccb1ea9f24ffbd085571c88585517b"
	strings:
		$s1 = "echo \"<input size=\\\"100\\\" type=\\\"text\\\" name=\\\"newfile\\\" value=\\\"$inputfile\\\"><b"
		$s2 = "$img[$id] = \"<img height=\\\"16\\\" width=\\\"16\\\" border=\\\"0\\\" src=\\\"$REMOTE_IMAGE_UR"
		$s3 = "$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", "
	condition:
		all of them
}

rule FSO_s_cmd {
	meta:
		description = "Webshells Auto-generated - file cmd.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cbe8e365d41dd3cd8e462ca434cf385f"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
		$s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_phpft {
	meta:
		description = "Webshells Auto-generated - file phpft.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "60ef80175fcc6a879ca57c54226646b1"
	strings:
		$s6 = "PHP Files Thief"
		$s11 = "http://www.4ngel.net"
	condition:
		all of them
}

rule FSO_s_indexer {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "135fc50f85228691b401848caef3be9e"
	strings:
		$s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
	condition:
		all of them
}

rule r57shell {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8023394542cddf8aee5dec6072ed02b5"
	strings:
		$s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"
	condition:
		all of them
}

rule bdcli100 {
	meta:
		description = "Webshells Auto-generated - file bdcli100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b12163ac53789fb4f62e4f17a8c2e028"
	strings:
		$s5 = "unable to connect to "
		$s8 = "backdoor is corrupted on "
	condition:
		all of them
}

rule HYTop_DevPack_2005Red {
	meta:
		description = "Webshells Auto-generated - file 2005Red.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d8ccda2214b3f6eabd4502a050eb8fe8"
	strings:
		$s0 = "scrollbar-darkshadow-color:#FF9DBB;"
		$s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
	condition:
		all of them
}

rule HYTop2006_rar_Folder_2006X2 {
	meta:
		description = "Webshells Auto-generated - file 2006X2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cc5bf9fc56d404ebbc492855393d7620"
	strings:
		$s2 = "Powered By "
		$s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."
	condition:
		all of them
}

rule rdrbs084 {
	meta:
		description = "Webshells Auto-generated - file rdrbs084.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ed30327b255816bdd7590bf891aa0020"
	strings:
		$s0 = "Create mapped port. You have to specify domain when using HTTP type."
		$s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
	condition:
		all of them
}

rule HYTop_CaseSwitch_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8bf667ee9e21366bc0bd3491cb614f41"
	strings:
		$s1 = "MSComDlg.CommonDialog"
		$s2 = "CommonDialog1"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s5 = "EVENT_SINK_AddRef"
		$s6 = "By Marcos"
		$s7 = "EVENT_SINK_QueryInterface"
		$s8 = "MethCallEngine"
	condition:
		all of them
}

rule eBayId_index3 {
	meta:
		description = "Webshells Auto-generated - file index3.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0412b1e37f41ea0d002e4ed11608905f"
	strings:
		$s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"
	condition:
		all of them
}

rule FSO_s_phvayv {
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "205ecda66c443083403efb1e5c7f7878"
	strings:
		$s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"
	condition:
		all of them
}

rule byshell063_ntboot {
	meta:
		description = "Webshells Auto-generated - file ntboot.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "Dumping Description to Registry..."
		$s3 = "Opening Service .... Failure !"
	condition:
		all of them
}

rule FSO_s_casus15_2 {
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8d155b4239d922367af5d0a1b89533a3"
	strings:
		$s0 = "copy ( $dosya_gonder"
	condition:
		all of them
}

rule installer {
	meta:
		description = "Webshells Auto-generated - file installer.cmd"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a507919ae701cf7e42fa441d3ad95f8f"
	strings:
		$s0 = "Restore Old Vanquish"
		$s4 = "ReInstall Vanquish"
	condition:
		all of them
}

rule uploader {
	meta:
		description = "Webshells Auto-generated - file uploader.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b9a9aab319964351b46bd5fc9d6246a8"
	strings:
		$s0 = "move_uploaded_file($userfile, \"entrika.php\"); "
	condition:
		all of them
}

rule FSO_s_remview_2 {
	meta:
		description = "Webshells Auto-generated - file remview.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b4a09911a5b23e00b55abe546ded691c"
	strings:
		$s0 = "<xmp>$out</"
		$s1 = ".mm(\"Eval PHP code\")."
	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_r57 {
	meta:
		description = "Webshells Auto-generated - file r57.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "903908b77a266b855262cdbce81c3f72"
	strings:
		$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
	condition:
		all of them
}

rule HYTop2006_rar_Folder_2006X {
	meta:
		description = "Webshells Auto-generated - file 2006X.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cf3ee0d869dd36e775dfcaa788db8e4b"
	strings:
		$s1 = "<input name=\"password\" type=\"password\" id=\"password\""
		$s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""
	condition:
		all of them
}

rule FSO_s_phvayv_2 {
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "205ecda66c443083403efb1e5c7f7878"
	strings:
		$s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"
	condition:
		all of them
}

rule elmaliseker {
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"
	strings:
		$s0 = "javascript:Command('Download'"
		$s5 = "zombie_array=array("
	condition:
		all of them
}

rule shelltools_g0t_root_resolve {
	meta:
		description = "Webshells Auto-generated - file resolve.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "69bf9aa296238610a0e05f99b5540297"
	strings:
		$s0 = "3^n6B(Ed3"
		$s1 = "^uldn'Vt(x"
		$s2 = "\\= uPKfp"
		$s3 = "'r.axV<ad"
		$s4 = "p,modoi$=sr("
		$s5 = "DiamondC8S t"
		$s6 = "`lQ9fX<ZvJW"
	condition:
		all of them
}

rule FSO_s_RemExp {
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b69670ecdbb40012c73686cd22696eeb"
	strings:
		$s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
		$s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
		$s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"
	condition:
		all of them
}

rule FSO_s_tool {
	meta:
		description = "Webshells Auto-generated - file tool.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a1e1e889fdd974a130a6a767b42655b"
	strings:
		$s7 = "\"\"%windir%\\\\calc.exe\"\")"
	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "97f2552c2fafc0b2eb467ee29cc803c8"
	strings:
		$s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp"
		$s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">"
	condition:
		all of them
}

rule byloader {
	meta:
		description = "Webshells Auto-generated - file byloader.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0f0d6dc26055653f5844ded906ce52df"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "NTFS Disk Driver Checking Service"
		$s3 = "Dumping Description to Registry..."
		$s4 = "Opening Service .... Failure !"
	condition:
		all of them
}

rule shelltools_g0t_root_Fport {
	meta:
		description = "Webshells Auto-generated - file Fport.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dbb75488aa2fa22ba6950aead1ef30d5"
	strings:
		$s4 = "Copyright 2000 by Foundstone, Inc."
		$s5 = "You must have administrator privileges to run fport - exiting..."
	condition:
		all of them
}

rule BackDooR__fr_ {
	meta:
		description = "Webshells Auto-generated - file BackDooR (fr).php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a79cac2cf86e073a832aaf29a664f4be"
	strings:
		$s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
	condition:
		all of them
}

rule FSO_s_ntdaddy {
	meta:
		description = "Webshells Auto-generated - file ntdaddy.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"
	strings:
		$s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
	condition:
		all of them
}

rule nstview_nstview {
	meta:
		description = "Webshells Auto-generated - file nstview.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3871888a0c1ac4270104918231029a56"
	strings:
		$s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"
	condition:
		all of them
}

rule HYTop_DevPack_upload {
	meta:
		description = "Webshells Auto-generated - file upload.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b09852bda534627949f0259828c967de"
	strings:
		$s0 = "<!-- PageUpload Below -->"
	condition:
		all of them
}

rule PasswordReminder {
	meta:
		description = "Webshells Auto-generated - file PasswordReminder.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"
	strings:
		$s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."
	condition:
		all of them
}

rule Pack_InjectT {
	meta:
		description = "Webshells Auto-generated - file InjectT.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "983b74ccd57f6195a0584cdfb27d55e8"
	strings:
		$s3 = "ail To Open Registry"
		$s4 = "32fDssignim"
		$s5 = "vide Internet S"
		$s6 = "d]Software\\M"
		$s7 = "TInject.Dll"
	condition:
		all of them
}

rule FSO_s_RemExp_2 {
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b69670ecdbb40012c73686cd22696eeb"
	strings:
		$s2 = " Then Response.Write \""
		$s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
	condition:
		all of them
}

rule FSO_s_c99 {
	meta:
		description = "Webshells Auto-generated - file c99.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f9ba02eb081bba2b2434c603af454d0"
	strings:
		$s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"
	condition:
		all of them
}

rule rknt_zip_Folder_RkNT {
	meta:
		description = "Webshells Auto-generated - file RkNT.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f97386dfde148942b7584aeb6512b85"
	strings:
		$s0 = "PathStripPathA"
		$s1 = "`cLGet!Addr%"
		$s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s3 = "oQToOemBuff* <="
		$s4 = "ionCdunAsw[Us'"
		$s6 = "CreateProcessW: %S"
		$s7 = "ImageDirectoryEntryToData"
	condition:
		all of them
}

rule dbgntboot {
	meta:
		description = "Webshells Auto-generated - file dbgntboot.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "4d87543d4d7f73c1529c9f8066b475ab"
	strings:
		$s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
		$s3 = "sth junk the M$ Wind0wZ retur"
	condition:
		all of them
}

rule PHP_shell {
	meta:
		description = "Webshells Auto-generated - file shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "45e8a00567f8a34ab1cccc86b4bc74b9"
	strings:
		$s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz"
		$s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s"
	condition:
		all of them
}

rule hxdef100 {
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "55cc1769cef44910bd91b7b73dee1f6c"
	strings:
		$s0 = "RtlAnsiStringToUnicodeString"
		$s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
		$s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"
	condition:
		all of them
}
