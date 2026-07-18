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

/* Generated from WShell_THOR_Webshells.yar; shard 8. Do not edit generated shards independently. */

rule rdrbs100 {
	meta:
		description = "Webshells Auto-generated - file rdrbs100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7c752bcd6da796d80a6830c61a632bff"
	strings:
		$s3 = "Server address must be IP in A.B.C.D format."
		$s4 = " mapped ports in the list. Currently "
	condition:
		all of them
}

rule Mithril_Mithril {
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "017191562d72ab0ca551eb89256650bd"
	strings:
		$s0 = "OpenProcess error!"
		$s1 = "WriteProcessMemory error!"
		$s4 = "GetProcAddress error!"
		$s5 = "HHt`HHt\\"
		$s6 = "Cmaudi0"
		$s7 = "CreateRemoteThread error!"
		$s8 = "Kernel32"
		$s9 = "VirtualAllocEx error!"
	condition:
		all of them
}

rule hxdef100_2 {
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b393e2e13b9c57fb501b7cd7ad96b25"
	strings:
		$s0 = "\\\\.\\mailslot\\hxdef-rkc000"
		$s2 = "Shared Components\\On Access Scanner\\BehaviourBlo"
		$s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
	condition:
		all of them
}

rule Release_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "76a59fc3242a2819307bb9d593bef2e0"
	strings:
		$s0 = ";;;Y;`;d;h;l;p;t;x;|;"
		$s1 = "0 0&00060K0R0X0f0l0q0w0"
		$s2 = ": :$:(:,:0:4:8:D:`=d="
		$s3 = "4@5P5T5\\5T7\\7d7l7t7|7"
		$s4 = "1,121>1C1K1Q1X1^1e1k1s1y1"
		$s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9"
		$s6 = "0)0O0\\0a0o0\"1E1P1q1"
		$s7 = "<.<I<d<h<l<p<t<x<|<"
		$s8 = "3&31383>3F3Q3X3`3f3w3|3"
		$s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z="
	condition:
		all of them
}

rule webadmin {
	meta:
		description = "Webshells Auto-generated - file webadmin.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a90de401b30e5b590362ba2dde30937"
	strings:
		$s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"
	condition:
		all of them
}

rule commands {
	meta:
		description = "Webshells Auto-generated - file commands.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "174486fe844cb388e2ae3494ac2d1ec2"
	strings:
		$s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID"
		$s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F"
	condition:
		all of them
}

rule hkdoordll {
	meta:
		description = "Webshells Auto-generated - file hkdoordll.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b715c009d47686c0e62d0981efce2552"
	strings:
		$s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"
	condition:
		all of them
}

rule r57shell_2 {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8023394542cddf8aee5dec6072ed02b5"
	strings:
		$s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"
	condition:
		all of them
}

rule Mithril_v1_45_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
	strings:
		$s3 = "syspath"
		$s4 = "\\Mithril"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}

rule dbgiis6cli {
	meta:
		description = "Webshells Auto-generated - file dbgiis6cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3044dceb632b636563f66fee3aaaf8f3"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
		$s5 = "###command:(NO more than 100 bytes!)"
	condition:
		all of them
}

rule remview_2003_04_22 {
	meta:
		description = "Webshells Auto-generated - file remview_2003_04_22.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "17d3e4e39fbca857344a7650f7ea55e3"
	strings:
		$s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""
	condition:
		all of them
}

rule FSO_s_test {
	meta:
		description = "Webshells Auto-generated - file test.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "82cf7b48da8286e644f575b039a99c26"
	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";"
		$s2 = "fwrite ($fp, \"$yazi\");"
	condition:
		all of them
}

rule Debug_cress {
	meta:
		description = "Webshells Auto-generated - file cress.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "36a416186fe010574c9be68002a7286a"
	strings:
		$s0 = "\\Mithril "
		$s4 = "Mithril.exe"
	condition:
		all of them
}

rule webshell {
	meta:
		description = "Webshells Auto-generated - file webshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f2f8c02921f29368234bfb4d4622ad19"
	strings:
		$s0 = "RhViRYOzz"
		$s1 = "d\\O!jWW"
		$s2 = "bc!jWW"
		$s3 = "0W[&{l"
		$s4 = "[INhQ@\\"
	condition:
		all of them
}

rule FSO_s_EFSO_2 {
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a341270f9ebd01320a7490c12cb2e64c"
	strings:
		$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
		$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
	condition:
		all of them
}

rule thelast_index3 {
	meta:
		description = "Webshells Auto-generated - file index3.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cceff6dc247aaa25512bad22120a14b4"
	strings:
		$s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"
	condition:
		all of them
}

rule adjustcr {
	meta:
		description = "Webshells Auto-generated - file adjustcr.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "17037fa684ef4c90a25ec5674dac2eb6"
	strings:
		$s0 = "$Info: This file is packed with the UPX executable packer $"
		$s2 = "$License: NRV for UPX is distributed under special license $"
		$s6 = "AdjustCR Carr"
		$s7 = "ION\\System\\FloatingPo"
	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_xIShell {
	meta:
		description = "Webshells Auto-generated - file xIShell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "997c8437c0621b4b753a546a53a88674"
	strings:
		$s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
	condition:
		all of them
}

rule HYTop_AppPack_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
	strings:
		$s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
	condition:
		all of them
}

rule xssshell {
	meta:
		description = "Webshells Auto-generated - file xssshell.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"
	strings:
		$s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_usr {
	meta:
		description = "Webshells Auto-generated - file usr.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ade3357520325af50c9098dc8a21a024"
	strings:
		$s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
	condition:
		all of them
}

rule FSO_s_phpinj {
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dd39d17e9baca0363cc1c3664e608929"
	strings:
		$s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"
	condition:
		all of them
}

rule xssshell_db {
	meta:
		description = "Webshells Auto-generated - file db.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cb62e2ec40addd4b9930a9e270f5b318"
	strings:
		$s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
	condition:
		all of them
}

rule PHP_sh {
	meta:
		description = "Webshells Auto-generated - file sh.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1e9e879d49eb0634871e9b36f99fe528"
	strings:
		$s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
	condition:
		all of them
}

rule xssshell_default {
	meta:
		description = "Webshells Auto-generated - file default.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d156782ae5e0b3724de3227b42fcaf2f"
	strings:
		$s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
	condition:
		all of them
}

rule EditServer_Webshell_2 {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"
	strings:
		$s0 = "@HOTMAIL.COM"
		$s1 = "Press Any Ke"
		$s3 = "glish MenuZ"
	condition:
		all of them
}

rule by064cli {
	meta:
		description = "Webshells Auto-generated - file by064cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "10e0dff366968b770ae929505d2a9885"
	strings:
		$s7 = "packet dropped,redirecting"
		$s9 = "input the password(the default one is 'by')"
	condition:
		all of them
}

rule Mithril_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"
	strings:
		$s0 = "please enter the password:"
		$s3 = "\\dllTest.pdb"
	condition:
		all of them
}

rule peek_a_boo {
	meta:
		description = "Webshells Auto-generated - file peek-a-boo.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aca339f60d41fdcba83773be5d646776"
	strings:
		$s0 = "__vbaHresultCheckObj"
		$s1 = "\\VB\\VB5.OLB"
		$s2 = "capGetDriverDescriptionA"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s8 = "__vbaErrorOverflow"
	condition:
		all of them
}

rule fmlibraryv3 {
	meta:
		description = "Webshells Auto-generated - file fmlibraryv3.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c34c248fed6d5a20d8203924a2088acc"
	strings:
		$s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
	condition:
		all of them
}

rule Debug_dllTest_2 {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
	strings:
		$s4 = "\\Debug\\dllTest.pdb"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}

rule connector {
	meta:
		description = "Webshells Auto-generated - file connector.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3ba1827fca7be37c8296cd60be9dc884"
	strings:
		$s2 = "If ( AttackID = BROADCAST_ATTACK )"
		$s4 = "Add UNIQUE ID for victims / zombies"
	condition:
		all of them
}

rule shelltools_g0t_root_HideRun {
	meta:
		description = "Webshells Auto-generated - file HideRun.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "45436d9bfd8ff94b71eeaeb280025afe"
	strings:
		$s0 = "Usage -- hiderun [AppName]"
		$s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."
	condition:
		all of them
}

rule regshell {
	meta:
		description = "Webshells Auto-generated - file regshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "db2fdc821ca6091bab3ebd0d8bc46ded"
	strings:
		$s0 = "Changes the base hive to HKEY_CURRENT_USER."
		$s4 = "Displays a list of values and sub-keys in a registry Hive."
		$s5 = "Enter a menu selection number (1 - 3) or 99 to Exit: "
	condition:
		all of them
}

rule PHP_Shell_v1_7 {
	meta:
		description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b5978501c7112584532b4ca6fb77cba5"
	strings:
		$s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"
	condition:
		all of them
}

rule xssshell_save {
	meta:
		description = "Webshells Auto-generated - file save.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "865da1b3974e940936fe38e8e1964980"
	strings:
		$s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
		$s5 = "VictimID = fm_NStr(Victims(i))"
	condition:
		all of them
}

rule screencap {
	meta:
		description = "Webshells Auto-generated - file screencap.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "51139091dea7a9418a50f2712ea72aa6"
	strings:
		$s0 = "GetDIBColorTable"
		$s1 = "Screen.bmp"
		$s2 = "CreateDCA"
	condition:
		all of them
}

rule FSO_s_phpinj_2 {
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dd39d17e9baca0363cc1c3664e608929"
	strings:
		$s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"
	condition:
		all of them
}

rule ZXshell2_0_rar_Folder_zxrecv {
	meta:
		description = "Webshells Auto-generated - file zxrecv.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5d3d12a39f41d51341ef4cb7ce69d30f"
	strings:
		$s0 = "RyFlushBuff"
		$s1 = "teToWideChar^FiYP"
		$s2 = "mdesc+8F D"
		$s3 = "\\von76std"
		$s4 = "5pur+virtul"
		$s5 = "- Kablto io"
		$s6 = "ac#f{lowi8a"
	condition:
		all of them
}

rule FSO_s_ajan {
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "22194f8c44524f80254e1b5aec67b03e"
	strings:
		$s4 = "entrika.write \"BinaryStream.SaveToFile"
	condition:
		all of them
}

rule c99shell {
	meta:
		description = "Webshells Auto-generated - file c99shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "90b86a9c63e2cd346fe07cea23fbfc56"
	strings:
		$s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"
	condition:
		all of them
}

rule phpspy_2005_full {
	meta:
		description = "Webshells Auto-generated - file phpspy_2005_full.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d1c69bb152645438440e6c903bac16b2"
	strings:
		$s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"
	condition:
		all of them
}

rule FSO_s_zehir4_2 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5b496a61363d304532bcf52ee21f5d55"
	strings:
		$s4 = "\"Program Files\\Serv-u\\Serv"
	condition:
		all of them
}

rule httpdoor {
	meta:
		description = "Webshells Auto-generated - file httpdoor.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6097ea963455a09474471a9864593dc3"
	strings:
		$s4 = "''''''''''''''''''DaJKHPam"
		$s5 = "o,WideCharR]!n]"
		$s6 = "HAutoComplete"
		$s7 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:sch"
	condition:
		all of them
}

rule FSO_s_indexer_2 {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "135fc50f85228691b401848caef3be9e"
	strings:
		$s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
	condition:
		all of them
}

rule HYTop_DevPack_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
	strings:
		$s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
		$s8 = "scrollbar-darkshadow-color:#9C9CD3;"
		$s9 = "scrollbar-face-color:#E4E4F3;"
	condition:
		all of them
}

rule _root_040_zip_Folder_deploy {
	meta:
		description = "Webshells Auto-generated - file deploy.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2c9f9c58999256c73a5ebdb10a9be269"
	strings:
		$s5 = "halon synscan 127.0.0.1 1-65536"
		$s8 = "Obviously you replace the ip address with that of the target."

	condition:
		all of them
}

rule by063cli {
	meta:
		description = "Webshells Auto-generated - file by063cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "49ce26eb97fd13b6d92a5e5d169db859"
	strings:
		$s2 = "#popmsghello,are you all right?"
		$s4 = "connect failed,check your network and remote ip."
	condition:
		all of them
}

rule icyfox007v1_10_rar_Folder_asp {
	meta:
		description = "Webshells Auto-generated - file asp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2c412400b146b7b98d6e7755f7159bb9"
	strings:
		$s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
	condition:
		all of them
}

rule FSO_s_EFSO_2_2 {
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a341270f9ebd01320a7490c12cb2e64c"
	strings:
		$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
		$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
	condition:
		all of them
}

rule byshell063_ntboot_2 {
	meta:
		description = "Webshells Auto-generated - file ntboot.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"
	strings:
		$s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"
	condition:
		all of them
}

rule u_uay {
	meta:
		description = "Webshells Auto-generated - file uay.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"
	strings:
		$s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
		$s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
	condition:
		1 of them
}

rule bin_wuaus {
	meta:
		description = "Webshells Auto-generated - file wuaus.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "46a365992bec7377b48a2263c49e4e7d"
	strings:
		$s1 = "9(90989@9V9^9f9n9v9"
		$s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
		$s3 = ";(=@=G=O=T=X=\\="
		$s4 = "TCP Send Error!!"
		$s5 = "1\"1;1X1^1e1m1w1~1"
		$s8 = "=$=)=/=<=Y=_=j=p=z="
	condition:
		all of them
}

rule pwreveal {
	meta:
		description = "Webshells Auto-generated - file pwreveal.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b4e8447826a45b76ca45ba151a97ad50"
	strings:
		$s0 = "*<Blank - no es"
		$s3 = "JDiamondCS "
		$s8 = "sword set> [Leith=0 bytes]"
		$s9 = "ION\\System\\Floating-"
	condition:
		all of them
}

rule shelltools_g0t_root_xwhois {
	meta:
		description = "Webshells Auto-generated - file xwhois.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0bc98bd576c80d921a3460f8be8816b4"
	strings:
		$s1 = "rting! "
		$s2 = "aTypCog("
		$s5 = "Diamond"
		$s6 = "r)r=rQreryr"
	condition:
		all of them
}

rule vanquish_2 {
	meta:
		description = "Webshells Auto-generated - file vanquish.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2dcb9055785a2ee01567f52b5a62b071"
	strings:
		$s2 = "Vanquish - DLL injection failed:"
	condition:
		all of them
}

rule down_rar_Folder_down {
	meta:
		description = "Webshells Auto-generated - file down.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "db47d7a12b3584a2e340567178886e71"
	strings:
		$s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
	condition:
		all of them
}

rule cmdShell {
	meta:
		description = "Webshells Auto-generated - file cmdShell.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8a9fef43209b5d2d4b81dfbb45182036"
	strings:
		$s1 = "if cmdPath=\"wscriptShell\" then"
	condition:
		all of them
}

rule ZXshell2_0_rar_Folder_nc {
	meta:
		description = "Webshells Auto-generated - file nc.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2cd1bf15ae84c5f6917ddb128827ae8b"
	strings:
		$s0 = "WSOCK32.dll"
		$s1 = "?bSUNKNOWNV"
		$s7 = "p@gram Jm6h)"
		$s8 = "ser32.dllCONFP@"
	condition:
		all of them
}

rule portlessinst {
	meta:
		description = "Webshells Auto-generated - file portlessinst.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "74213856fc61475443a91cd84e2a6c2f"
	strings:
		$s2 = "Fail To Open Registry"
		$s3 = "f<-WLEggDr\""
		$s6 = "oMemoryCreateP"
	condition:
		all of them
}

rule SetupBDoor {
	meta:
		description = "Webshells Auto-generated - file SetupBDoor.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "41f89e20398368e742eda4a3b45716b6"
	strings:
		$s1 = "\\BDoor\\SetupBDoor"
	condition:
		all of them
}

rule phpshell_3 {
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "e8693a2d4a2ffea4df03bb678df3dc6d"
	strings:
		$s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
		$s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"
	condition:
		all of them
}

rule BIN_Server {
	meta:
		description = "Webshells Auto-generated - file Server.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
	strings:
		$s0 = "configserver"
		$s1 = "GetLogicalDrives"
		$s2 = "WinExec"
		$s4 = "fxftest"
		$s5 = "upfileok"
		$s7 = "upfileer"
	condition:
		all of them
}

rule HYTop2006_rar_Folder_2006 {
	meta:
		description = "Webshells Auto-generated - file 2006.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c19d6f4e069188f19b08fa94d44bc283"
	strings:
		$s6 = "strBackDoor = strBackDoor "
	condition:
		all of them
}

rule r57shell_3 {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "87995a49f275b6b75abe2521e03ac2c0"
	strings:
		$s1 = "<b>\".$_POST['cmd']"
	condition:
		all of them
}

rule HDConfig {
	meta:
		description = "Webshells Auto-generated - file HDConfig.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7d60e552fdca57642fd30462416347bd"
	strings:
		$s0 = "An encryption key is derived from the password hash. "
		$s3 = "A hash object has been created. "
		$s4 = "Error during CryptCreateHash!"
		$s5 = "A new key container has been created."
		$s6 = "The password has been added to the hash. "
	condition:
		all of them
}

rule FSO_s_ajan_2 {
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "22194f8c44524f80254e1b5aec67b03e"
	strings:
		$s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
		$s3 = "/file.zip"
	condition:
		all of them
}

rule Webshell_and_Exploit_CN_APT_HK : Webshell
{
meta:
	author = "Florian Roth"
	description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
	date = "10.10.2014"
	score = 50
strings:
	$a0 = "<script language=javascript src=http://java-se.com/o.js</script>" fullword
	$s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">"
	$s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">"
condition:
	$a0 or ( all of ($s*) )
}

rule JSP_Browser_APT_webshell {
	meta:
		description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
		author = "F.Roth"
		date = "10.10.2014"
		score = 60
	strings:
		$a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
		$a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
		$a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
		$a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
	condition:
		all of them
}

rule JSP_jfigueiredo_APT_webshell {
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "F.Roth"
		date = "12.10.2014"
		score = 60
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
	strings:
		$a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
		$a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
	condition:
		all of them
}

rule JSP_jfigueiredo_APT_webshell_2 {
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "F.Roth"
		date = "12.10.2014"
		score = 60
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"
	strings:
		$a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
		$a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
		$s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
		$s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
	condition:
		all of ($a*) or all of ($s*)
}

rule AJAX_FileUpload_webshell {
	meta:
		description = "AJAX JS/CSS components providing web shell by APT groups"
		author = "F.Roth"
		date = "12.10.2014"
		score = 75
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/ajaxfileupload.js"
	strings:
		$a1 = "var frameId = 'jUploadFrame' + id;" ascii
		$a2 = "var form = jQuery('<form  action=\"\" method=\"POST\" name=\"' + formId + '\" id=\"' + formId + '\" enctype=\"multipart/form-data\"></form>');" ascii
		$a3 = "jQuery(\"<div>\").html(data).evalScripts();" ascii
	condition:
		all of them
}

rule Webshell_Insomnia {
	meta:
		description = "Insomnia Webshell - file InsomniaShell.aspx"
		author = "Florian Roth"
		reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
		date = "2014/12/09"
		hash = "e0cfb2ffaa1491aeaf7d3b4ee840f72d42919d22"
		score = 80
	strings:
		$s0 = "Response.Write(\"- Failed to create named pipe:\");" fullword ascii
		$s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" fullword ascii
		$s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
		$s3 = "Response.Write(\"- Error Getting User Info<br>\");" fullword ascii
		$s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," fullword ascii
		$s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" fullword ascii
		$s9 = "username = DumpAccountSid(tokUser.User.Sid);" fullword ascii
		$s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii
	condition:
		3 of them
}

rule HawkEye_PHP_Panel {
	meta:
		description = "Detects HawkEye Keyloggers PHP Panel"
		author = "Florian Roth"
		date = "2014/12/14"
		score = 60
	strings:
		$s0 = "$fname = $_GET['fname'];" ascii fullword
		$s1 = "$data = $_GET['data'];" ascii fullword
		$s2 = "unlink($fname);" ascii fullword
		$s3 = "echo \"Success\";" fullword ascii
	condition:
		all of ($s*) and filesize < 600
}

rule SoakSoak_Infected_Wordpress {
	meta:
		description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
		reference = "http://goo.gl/1GzWUX"
		author = "Florian Roth"
		date = "2014/12/15"
		score = 60
	strings:
		$s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
		$s1 = "function FuncQueueObject()" ascii fullword
		$s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
	condition:
		all of ($s*)
}
