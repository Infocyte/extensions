--[[
    Infocyte Extension
    Name: Yara Scanner
    Type: Collection
    Description: Example script showing how to use YARA
    Author: Infocyte
    Created: 20191018
    Updated: 20191127 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)

-- This extension will yara scan files below
scanactiveprocesses = true
scanappdata = false

-- Provide additional paths below
if hunt.env.is_windows() then
    additionalpaths = {
        'c:\\windows\\system32\\calc.exe',
        'c:\\windows\\system32\\notepad.exe',
        "c:\\windows\\"
    }

elseif hunt.env.is_macos() then
    additionalpaths = {
        '/bin/sh',
        '/bin/ls'
    }

elseif hunt.env.is_linux() then
    additionalpaths = {
        '/bin/cat',
        '/bin/tar'
    }

end

----------------------------------------------------
-- SECTION 2: Functions & Rules

-- #region bad_rules
bad_rules = [==[
import "pe"
rule Base64d_PE
{
	meta:
		description = "Contains a base64-encoded executable"
		author = "Florian Roth"
		date = "2017-04-21"

	strings:
		$s0 = "TVqQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s1 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii

	condition:
		any of them
}

rule APT_KimSuky_bckdr_dll {

   meta:

      description = "Armadillo packed DLL used in Kimsuky campaign"
      author = "Christiaan Beek - McAfee Advanced Threat Research"
      reference = "https://securelist.com/the-kimsuky-operation-a-north-korean-apt/57915/"
      date = "2018-02-09"
      hash1 = "afe4237ff1a3415072d2e1c2c8954b013471491c6afdce3f04d2f77e91b0b688"
      hash2 = "38897be10924bc694632e774ef80d22a94fed100b0ba29f9bd6f254db5f5be0f"
      hash3 = "8433f648789bcc97684b5ec112ee9948f4667087c615ff19a45216b8a3c27539"
      hash4 = "1cdbe9eda77a123cf25baf2dc15218e0afd9b65dae80ea9e00c465b676187a1d"
      hash5 = "53e3cdbfbfb4fe673e10c8bdadc5d8790e21d01f0b40ffde0a08837ab9a3df91"
      hash6 = "d643d0375168dcb1640d9fefc0c4035d7772c0a3e41b0498780eee9e1935dfff"
      hash7 = "7cde78633a2cb14b088a3fe59cfad7dd29493dc41c92e3215a27516770273b84"

   strings:

      $x1 = "taskmgr.exe Execute Ok!!!" fullword ascii
      $x2 = "taskmgr.exe Execute Err!!!" fullword ascii
      $x3 = "kkk.exe Executing!!!" fullword ascii
      $s4 = "ShellExecuteA Ok!!!" fullword ascii
      $s5 = "ShellExecuteA Err!!!" fullword ascii
      $s6 = "Manage.dll" fullword ascii
      $s7 = "%s_%s.txt" fullword ascii
      $s8 = "kkk.exe Copy Ok!" fullword ascii
      $s9 = "File Executing!" fullword ascii
      $s10 = "////// KeyLog End //////" fullword ascii
      $s11 = "//////// SystemInfo End ///////" fullword ascii
      $s12 = "//////// SystemInfo ///////" fullword ascii
      $s13 = "///// UserId //////" fullword ascii
      $s14 = "///// UserId End //////" fullword ascii
      $s15 = "////// KeyLog //////" fullword ascii
      $s16 = "Decrypt Erro!!!" fullword ascii
      $s17 = "File Delete Ok!" fullword ascii
      $s18 = "Down Ok!!!" fullword ascii

      $op0 = { be 40 e9 00 10 8d bd 3c ff ff ff 83 c4 48 f3 a5 }
      $op1 = { 8b ce 33 c0 8b d1 8d bc 24 34 02 00 00 c1 e9 02 }
      $op2 = { be dc e9 00 10 8d bd 1c ff ff ff f3 a5 8d bd 1c }

   condition:

      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) and 4 of them ) and all of ($op*)) or ( all of them )
}
rule Shifu {

	meta:

		reference = "https://blogs.mcafee.com/mcafee-labs/japanese-banking-trojan-shifu-combines-malware-tools/"
		author = "McAfee Labs"

	strings:

		$b = "RegCreateKeyA"
		$a = "CryptCreateHash"
		$c = {2F 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 25 00 73 00 00 00 00 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 00 00 72 00 75 00 6E}
		$d = {53 00 6E 00 64 00 56 00 6F 00 6C 00 2E 00 65 00 78 00 65}
		$e = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45}

	condition:

		all of them
}
rule VPNFilter {

   meta:

      description = "Filter for 2nd stage malware used in VPNfilter attack"
      author = "Christiaan Beek @ McAfee Advanced Threat Research"
      reference = "https://blog.talosintelligence.com/2018/05/VPNFilter.html"
      date = "2018-05-23"
      hash1 = "9eb6c779dbad1b717caa462d8e040852759436ed79cc2172692339bc62432387"
      hash2 = "4b03288e9e44d214426a02327223b5e516b1ea29ce72fa25a2fcef9aa65c4b0b"
      hash3 = "9683b04123d7e9fe4c8c26c69b09c2233f7e1440f828837422ce330040782d17"
      hash4 = "0649fda8888d701eb2f91e6e0a05a2e2be714f564497c44a3813082ef8ff250b"
      hash5 = "8a20dc9538d639623878a3d3d18d88da8b635ea52e5e2d0c2cce4a8c5a703db1"
      hash6 = "776cb9a7a9f5afbaffdd4dbd052c6420030b2c7c3058c1455e0a79df0e6f7a1d"
      hash7 = "37e29b0ea7a9b97597385a12f525e13c3a7d02ba4161a6946f2a7d978cc045b4"
      hash8 = "d6097e942dd0fdc1fb28ec1814780e6ecc169ec6d24f9954e71954eedbc4c70e"

   strings:

      $s1 = "id-at-postalAddress" fullword ascii
      $s2 = "/bin/shell" fullword ascii
      $s3 = "/DZrtenNLQNiTrM9AM+vdqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQAB" fullword ascii
      $s4 = "Usage does not match the keyUsage extension" fullword ascii
      $s5 = "id-at-postalCode" fullword ascii
      $s6 = "vTeY4KZMaUrveEel5tWZC94RSMKgxR6cyE1nBXyTQnDOGbfpNNgBKxyKbINWoOJU" fullword ascii
      $s7 = "id-ce-extKeyUsage" fullword ascii
      $s8 = "/f8wYwYDVR0jBFwwWoAUtFrkpbPe0lL2udWmlQ/rPrzH/f+hP6Q9MDsxCzAJBgNV" fullword ascii
      $s9 = "/etc/config/hosts" fullword ascii
      $s10 = "%s%-18s: %d bits" fullword ascii
      $s11 = "id-ce-keyUsage" fullword ascii
      $s12 = "Machine is not on the network" fullword ascii
      $s13 = "No XENIX semaphores available" fullword ascii
      $s14 = "No CSI structure available" fullword ascii
      $s15 = "Name not unique on network" fullword ascii

   condition:

      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )) or ( all of them )
}

rule Monero_Mining_Detection {

   meta:

      description = "Monero mining software"
      author = "Christiaan Beek"
      reference = "MoneroMiner"
      date = "2018-04-05"

   strings:

      $1 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $2 = "--cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
      $3 = "* THREADS:      %d, %s, av=%d, %sdonate=%d%%%s" fullword ascii
      $4 = "--user-agent         set custom user-agent string for pool" fullword ascii
      $5 = "-O, --userpass=U:P       username:password pair for mining server" fullword ascii
      $6 = "--cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
      $7 = "-p, --pass=PASSWORD      password for mining server" fullword ascii
      $8 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
      $9 = "-k, --keepalive          send keepalived for prevent timeout (need pool support)" fullword ascii
      $10 = "--max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)" fullword ascii
      $11 = "--nicehash           enable nicehash/xmrig-proxy support" fullword ascii
      $12 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $13 = "* CPU:          %s (%d) %sx64 %sAES-NI" fullword ascii
      $14 = "-r, --retries=N          number of times to retry before switch to backup server (default: 5)" fullword ascii
      $15 = "-B, --background         run the miner in the background" fullword ascii
      $16 = "* API PORT:     %d" fullword ascii
      $17 = "--api-access-token=T access token for API" fullword ascii
      $18 = "-t, --threads=N          number of miner threads" fullword ascii
      $19 = "--print-time=N       print hashrate report every N seconds" fullword ascii
      $20 = "-u, --user=USERNAME      username for mining server" fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )) or ( all of them )
}

rule screenlocker_acroware {

   meta:

      description = "Rule to detect the ScreenLocker Acroware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"

   strings:

      $s1 = "C:\\Users\\patri\\Documents\\Visual Studio 2015\\Projects\\Advanced Ransi\\Advanced Ransi\\obj\\Debug\\Advanced Ransi.pdb" fullword ascii
      $s2 = "All your Personal Data got encrypted and the decryption key is stored on a hidden" fullword ascii
      $s3 = "alphaoil@mail2tor.com any try of removing this Ransomware will result in an instantly " fullword ascii
      $s4 = "HKEY_CURRENT_USER\\SoftwareE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
      $s5 = "webserver, after 72 hours thedecryption key will get removed and your personal" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them
}
rule amba_ransomware {

   meta:

      description = "Rule to detect Amba Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      hash1 = "7c08cdf9f4e8be34ef6af5b53794163023c2b013f34c4134b8922f42933012a0"
      hash2 = "73155a084aac8434bb0779a0b88e97d5cf2d0760e9d25f2f42346d3e06cdaac2"
      hash3 = "ec237bc926ce9008a219b8b30882f3ac18531bd314ee852369fc712368c6acd5"
      hash4 = "b9b6045a45dd22fcaf2fc13d39eba46180d489cb4eb152c87568c2404aecac2f"

   strings:

      $s1 = "64DCRYPT.SYS" fullword wide
      $s2 = "32DCRYPT.SYS" fullword wide
      $s3 = "64DCINST.EXE" fullword wide
      $s4 = "32DCINST.EXE" fullword wide
      $s5 = "32DCCON.EXE" fullword wide
      $s6 = "64DCCON.EXE" fullword wide
      $s8 = "32DCAPI.DLL" fullword wide
      $s9 = "64DCAPI.DLL" fullword wide
      $s10 = "ICYgc2h1dGRvd24gL2YgL3IgL3QgMA==" fullword ascii
      $s11 = "QzpcVXNlcnNcQUJDRFxuZXRwYXNzLnR4dA==" fullword ascii
      $s12 = ")!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v)" fullword ascii
      $s13 = "RGVmcmFnbWVudFNlcnZpY2U="
      $s14 = "LWVuY3J5cHQgcHQ5IC1wIA=="
      $s15 = "LWVuY3J5cHQgcHQ3IC1wIA=="
      $s16 = "LWVuY3J5cHQgcHQ2IC1wIA=="
      $s17 = "LWVuY3J5cHQgcHQzIC1wIA=="

   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}
rule anatova_ransomware {

   meta:

      description = "Rule to detect the Anatova Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/happy-new-year-2019-anatova-is-here/"

   strings:

        $regex = /anatova[0-9]@tutanota.com/

    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and $regex
}

rule cryptonar_ransomware {

   meta:

      description = "Rule to detect CryptoNar Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://www.bleepingcomputer.com/news/security/cryptonar-ransomware-discovered-and-quickly-decrypted/"

   strings:

      $s1 = "C:\\narnar\\CryptoNar\\CryptoNarDecryptor\\obj\\Debug\\CryptoNar.pdb" fullword ascii
      $s2 = "CryptoNarDecryptor.exe" fullword wide
      $s3 = "server will eliminate the key after 72 hours since its generation (since the moment your computer was infected). Once this has " fullword ascii
      $s4 = "Do not delete this file, else the decryption process will be broken" fullword wide
      $s5 = "key you received, and wait until the decryption process is done." fullword ascii
      $s6 = "In order to receive your decryption key, you will have to pay $200 in bitcoins to this bitcoin address: [bitcoin address]" fullword ascii
      $s7 = "Decryption process failed" fullword wide
      $s8 = "CryptoNarDecryptor.KeyValidationWindow.resources" fullword ascii
      $s9 = "Important note: Removing CryptoNar will not restore access to your encrypted files." fullword ascii
      $s10 = "johnsmith987654@tutanota.com" fullword wide
      $s11 = "Decryption process will start soon" fullword wide
      $s12 = "CryptoNarDecryptor.DecryptionProgressBarForm.resources" fullword ascii
      $s13 = "DecryptionProcessProgressBar" fullword wide
      $s14 = "CryptoNarDecryptor.Properties.Resources.resources" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB) and all of them
}
rule crime_ransomware_windows_GPGQwerty
{
meta:

	author = "McAfee Labs"
	description = "Detect GPGQwerty ransomware"
	reference = "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"
	date = "2018-03-21"

strings:

	$a = "gpg.exe ???recipient qwerty  -o"
	$b = "%s%s.%d.qwerty"
	$c = "del /Q /F /S %s$recycle.bin"
	$d = "cryz1@protonmail.com"

condition:
	all of them
}
rule kraken_cryptor_ransomware_loader {

   meta:

      description = "Rule to detect the Kraken Cryptor Ransomware loader"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $pdb = "C:\\Users\\Krypton\\source\\repos\\UAC\\UAC\\obj\\Release\\UAC.pdb" fullword ascii
      $s2 = "SOFTWARE\\Classes\\mscfile\\shell\\open\\command" fullword wide
      $s3 = "public_key" fullword ascii
      $s4 = "KRAKEN DECRYPTOR" ascii
      $s5 = "UNIQUE KEY" fullword ascii


   condition:

      ( uint16(0) == 0x5a4d and filesize < 600KB ) and $pdb or all of ($s*)
}

rule kraken_cryptor_ransomware {

   meta:

      description = "Rule to detect the Kraken Cryptor Ransomware"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s1 = "Kraken Cryptor" fullword ascii nocase
      $s2 = "support_email" fullword ascii
      $fw1 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iU01CIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD00" ascii
      $fw2 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iUkRQIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD0z" ascii
      $fw3 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iUkRQIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD0z" ascii
      $fw4 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iU01CIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD00" ascii
      $uac = "<!--<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />-->   " fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and filesize < 600KB ) and all of ($fw*) or all of ($s*) or $uac
}

rule locdoor_ransomware {

   meta:

      description = "Rule to detect Locdoor/DryCry"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://twitter.com/leotpsc/status/1036180615744376832"

   strings:

      $s1 = "copy \"Locdoor.exe\" \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\temp00000000.exe\"" fullword ascii
      $s2 = "copy wscript.vbs C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\wscript.vbs" fullword ascii
      $s3 = "!! Your computer's important files have been encrypted! Your computer's important files have been encrypted!" fullword ascii
      $s4 = "echo CreateObject(\"SAPI.SpVoice\").Speak \"Your computer's important files have been encrypted! " fullword ascii
      $s5 = "! Your computer's important files have been encrypted! " fullword ascii
      $s7 = "This program is not supported on your operating system." fullword ascii
      $s8 = "echo Your computer's files have been encrypted to Locdoor Ransomware! To make a recovery go to localbitcoins.com and create a wa" ascii
      $s9 = "Please enter the password." fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and filesize < 600KB ) and all of them
}

rule LockerGogaRansomware {

   meta:

      description = "LockerGoga Ransomware"
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-03-20"
      hash1 = "88d149f3e47dc337695d76da52b25660e3a454768af0d7e59c913995af496a0f"
      hash2 = "c97d9bbc80b573bdeeda3812f4d00e5183493dd0d5805e2508728f65977dda15"
      hash3 = "ba15c27f26265f4b063b65654e9d7c248d0d651919fafb68cb4765d1e057f93f"

   strings:

      $1 = "boost::interprocess::spin_recursive_mutex recursive lock overflow" fullword ascii
      $2 = ".?AU?$error_info_injector@Usync_queue_is_closed@concurrent@boost@@@exception_detail@boost@@" fullword ascii
      $3 = ".?AV?$CipherModeFinalTemplate_CipherHolder@V?$BlockCipherFinal@$00VDec@RC6@CryptoPP@@@CryptoPP@@VCBC_Decryption@2@@CryptoPP@@" fullword ascii
      $4 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $5 = "cipher.exe" fullword ascii
      $6 = ".?AU?$placement_destroy@Utrace_queue@@@ipcdetail@interprocess@boost@@" fullword ascii
      $7 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $8 = "CreateProcess failed" fullword ascii
      $9 = "boost::dll::shared_library::load() failed" fullword ascii
      $op1 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }
      $op2 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }

   condition:

      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 6 of them ) and all of ($op*)) or ( all of them )
}
rule loocipher_ransomware {

   meta:

      description = "Rule to detect Loocipher ransomware"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $x1 = "c:\\users\\usuario\\desktop\\cryptolib\\gfpcrypt.h" fullword ascii
      $x2 = "c:\\users\\usuario\\desktop\\cryptolib\\eccrypto.h" fullword ascii
      $s3 = "c:\\users\\usuario\\desktop\\cryptolib\\gf2n.h" fullword ascii
      $s4 = "c:\\users\\usuario\\desktop\\cryptolib\\queue.h" fullword ascii
      $s5 = "ThreadUserTimer: GetThreadTimes failed with error " fullword ascii
      $s6 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::operator *" fullword wide
      $s7 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::operator +=" fullword wide
      $s8 = "std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short> >::operator []" fullword wide
      $s9 = "std::vector<struct CryptoPP::ProjectivePoint,class std::allocator<struct CryptoPP::ProjectivePoint> >::operator []" fullword wide
      $s10 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::operator *" fullword wide
      $s11 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::operator +=" fullword wide
      $s12 = "std::vector<struct CryptoPP::WindowSlider,class std::allocator<struct CryptoPP::WindowSlider> >::operator []" fullword wide
      $s13 = "std::istreambuf_iterator<char,struct std::char_traits<char> >::operator ++" fullword wide
      $s14 = "std::istreambuf_iterator<char,struct std::char_traits<char> >::operator *" fullword wide
      $s15 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::_Compat" fullword wide
      $s16 = "std::vector<class CryptoPP::PolynomialMod2,class std::allocator<class CryptoPP::PolynomialMod2> >::operator []" fullword wide
      $s17 = "DL_ElgamalLikeSignatureAlgorithm: this signature scheme does not support message recovery" fullword ascii
      $s18 = "std::vector<struct CryptoPP::ECPPoint,class std::allocator<struct CryptoPP::ECPPoint> >::operator []" fullword wide
      $s19 = "std::vector<struct CryptoPP::EC2NPoint,class std::allocator<struct CryptoPP::EC2NPoint> >::operator []" fullword wide
      $s20 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::_Compat" fullword wide

   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 1 of ($x*) and 4 of them ) ) or ( all of them )
}

rule ransom_monglock {
   meta:
      description = "Ransomware encrypting Mongo Databases "
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-04-25"
      hash1 = "ef80edbea5e22f134bd76704bec003fbd0c16098f73e1c501c514cb728bd566b"
      hash2 = "8f8455252f3e4518dc80b9cfc426b7ce20d228e243f72c07c8e9d076045462d0"
      hash3 = "98bb99db9969f80c174919f16982e42dbd9b916c8925c36ba4f7146e3f29215c"
      hash4 = "ccbbfd383e3164a2dff1245e75fb1622fc092d1a90edb2f259730dfd23bf2538"
      hash5 = "c4de2d485ec862b308d00face6b98a7801ce4329a8fc10c63cf695af537194a8"
   strings:
      $x1 = "C:\\Windows\\system32\\cmd.exe" fullword wide
      $s1 = "and a Proof of Payment together will be ignored. We will drop the backup after 24 hours. You are welcome! " fullword ascii
      $s2 = "Your File and DataBase is downloaded and backed up on our secured servers. To recover your lost data : Send 0.1 BTC to our BitCoin" ascii
      $s3 = "No valid port number in connect to host string (%s)" fullword ascii
      $s4 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii
      $s5 = "# https://curl.haxx.se/docs/http-cookies.html" fullword ascii
      $s6 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii
      $s7 = "detail may be available in the Windows System event log." fullword ascii
      $s8 = "Found bundle for host %s: %p [%s]" fullword ascii
      $s9 = "No valid port number in proxy string (%s)" fullword ascii


      $op0 = { 50 8d 85 78 f6 ff ff 50 ff b5 70 f6 ff ff ff 15 }
      $op1 = { 83 fb 01 75 45 83 7e 14 08 72 34 8b 0e 66 8b 45 }
      $op2 = { c7 41 0c df ff ff ff c7 41 10 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them ) and all of ($op*)
      ) or ( all of them )
}

rule nemty_ransomware {

   meta:

      description = "Rule to detect Nemty Ransomware"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $x1 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default}" fullword ascii
      $s2 = "https://pbs.twimg.com/media/Dn4vwaRW0AY-tUu.jpg:large :D" fullword ascii
      $s3 = "MSDOS.SYS" fullword wide
      $s4 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} " ascii
      $s5 = "recoveryenabled no & wbadmin delete catalog -quiet & wmic shadowcopy delete" fullword ascii
      $s6 = "DECRYPT.txt" fullword ascii
      $s7 = "pv3mi+NQplLqkkJpTNmji/M6mL4NGe5IHsRFJirV6HSyx8mC8goskf5lXH2d57vh52iqhhEc5maLcSrIKbukcnmUwym+In1OnvHp070=" fullword ascii
      $s8 = "\\NEMTY-DECRYPT.txt\"" fullword ascii
      $s9 = "rfyPvccxgVaLvW9OOY2J090Mq987N9lif/RoIDP89luS9Ouv9gUImpgCTVGWvJzrqiS8hQ5El02LdEvKcJ+7dn3DxiXSNG1PwLrY59KzGs/gUvXnYcmT6t34qfZmr8g8" ascii
      $s10 = "IO.SYS" fullword wide
      $s11 = "QgzjKXcD1Jh/cOLBh1OMb+rWxUbToys2ArG9laNWAWk0rNIv2dnIDpc+mSbp91E8qVN8Mv8K5jC3EBr4TB8jh5Ns/onBhPZ9rLXR7wIkaXGeTZi/4/XOtO3DFiad4+vf" ascii
      $s12 = "NEMTY-DECRYPT.txt" fullword wide
      $s13 = "pvXmjPQRoUmjj0g9QZ24wvEqyvcJVvFWXc0LL2XL5DWmz8me5wElh/48FHKcpbnq8C2kwQ==" fullword ascii
      $s14 = "a/QRAGlNLvqNuONkUWCQTNfoW45DFkZVjUPn0t3tJQnHWPhJR2HWttXqYpQQIMpn" fullword ascii
      $s15 = "KeoJrLFoTgXaTKTIr+v/ObwtC5BKtMitXq8aaDT8apz98QQvQgMbncLSJWJG+bHvaMhG" fullword ascii
      $s16 = "pu/hj6YerUnqlUM9A8i+i/UhnvsIE+9XTYs=" fullword ascii
      $s17 = "grQkLxaGvL0IBGGCRlJ8Q4qQP/midozZSBhFGEDpNElwvWXhba6kTH1LoX8VYNOCZTDzLe82kUD1TSAoZ/fz+8QN7pLqol5+f9QnCLB9QKOi0OmpIS1DLlngr9YH99vt" ascii
      $s18 = "BOOTSECT.BAK" fullword wide
      $s19 = "bbVU/9TycwPO+5MgkokSHkAbUSRTwcbYy5tmDXAU1lcF7d36BTpfvzaV5/VI6ARRt2ypsxHGlnOJQUTH6Ya//Eu0jPi/6s2MmOk67csw/msiaaxuHXDostsSCC+kolVX" ascii
      $s20 = "puh4wXjVYWJzFN6aIgnClL4W/1/5Eg6bm5uEv6Dru0pfOvhmbF1SY3zav4RQVQTYMfZxAsaBYfJ+Gx+6gDEmKggypl1VcVXWRbxAuDIXaByh9aP4B2QvhLnJxZLe+AG5" ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) and 4 of them ))
}
rule pico_ransomware {

   meta:

      description = "Rule to detect Pico Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://twitter.com/siri_urz/status/1035138577934557184"

   strings:

      $s1 = "C:\\Users\\rikfe\\Desktop\\Ransomware\\ThanatosSource\\Release\\Ransomware.pdb" fullword ascii
      $s2 = "\\Downloads\\README.txt" fullword ascii
      $s3 = "\\Music\\README.txt" fullword ascii
      $s4 = "\\Videos\\README.txt" fullword ascii
      $s5 = "\\Pictures\\README.txt" fullword ascii
      $s6 = "\\Desktop\\README.txt" fullword ascii
      $s7 = "\\Documents\\README.txt" fullword ascii
      $s8 = "/c taskkill /im " fullword ascii
      $s9 = "\\AppData\\Roaming\\" fullword ascii
      $s10 = "gMozilla/5.0 (Windows NT 6.1) Thanatos/1.1" fullword wide
      $s11 = "AppData\\Roaming" fullword ascii
      $s12 = "\\Downloads" fullword ascii
      $s13 = "operator co_await" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB ) and all of them
}

rule Robbinhood_ransomware {
   meta:
      description = "Robbinhood GoLang ransowmare"
      author = "Christiaan Beek @ McAfee ATR"
      date = "2019-05-10"
      hash1 = "9977ba861016edef0c3fb38517a8a68dbf7d3c17de07266cfa515b750b0d249e"
      hash2 = "27f9f740263b73a9b7e6dd8071c8ca2b2c22f310bde9a650fc524a4115f2fa14"
      hash3 = "3bc78141ff3f742c5e942993adfbef39c2127f9682a303b5e786ed7f9a8d184b"
      hash4 = "4e58b0289017d53dda4c912f0eadf567852199d044d2e2bda5334eb97fa0b67c"
      hash5 = "21cb84fc7b33e8e31364ff0e58b078db8f47494a239dc3ccbea8017ff60807e3"
      hash6 = "e128d5aa0b5a9c6851e69cbf9d2c983eefd305a10cba7e0c8240c8e2f79a544f"
   strings:
      $s1 = ".enc_robbinhood" nocase
      $s2 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s3 = "pub.key" nocase
      $s4 = "main.EnableShadowFucks" nocase
      $s5 = "main.EnableRecoveryFCK" nocase
      $s6 = "main.EnableLogLaunders" nocase
      $s7 = "main.EnableServiceFuck" nocase


      $op0 = { 8d 05 2d 98 51 00 89 44 24 30 c7 44 24 34 1d }
      $op1 = { 8b 5f 10 01 c3 8b 47 04 81 c3 b5 bc b0 34 8b 4f }
      $op2 = { 0f b6 34 18 8d 7e d0 97 80 f8 09 97 77 39 81 fd }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($s*) ) and all of ($op*)
      ) or ( all of them )
}

rule Ryuk_Ransomware {
   meta:
      description = "Ryuk Ransomware hunting rule"
      author = "Christiaan Beek - McAfee ATR team"
      reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/ryuk-ransomware-attack-rush-to-attribution-misses-the-point/"
      date = "2019-04-25"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "\\System32\\cmd.exe" fullword wide
      $s1 = "C:\\Users\\Admin\\Documents\\Visual Studio 2015\\Projects\\ConsoleApplication54new crypted" ascii
      $s2 = "fg4tgf4f3.dll" fullword wide
      $s3 = "lsaas.exe" fullword wide
      $s4 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s5 = "\\Documents and Settings\\Default User\\finish" fullword wide
      $s6 = "\\users\\Public\\sys" fullword wide
      $s7 = "\\users\\Public\\finish" fullword wide
      $s8 = "You will receive btc address for payment in the reply letter" fullword ascii
      $s9 = "hrmlog" fullword wide
      $s10 = "No system is safe" fullword ascii
      $s11 = "keystorage2" fullword wide
      $s12 = "klnagent" fullword wide
      $s13 = "sqbcoreservice" fullword wide
      $s14 = "tbirdconfig" fullword wide
      $s15 = "taskkill" fullword wide

      $op0 = { 8b 40 10 89 44 24 34 c7 84 24 c4 }
      $op1 = { c7 44 24 34 00 40 00 00 c7 44 24 38 01 }

   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) and 4 of them ) and all of ($op*)
      ) or ( all of them )
}
rule SamSam_Ransomware_Latest
{

   meta:

      description = "Latest SamSA ransomware samples"
      author = "Christiaan Beek"
      reference = "http://blog.talosintelligence.com/2018/01/samsam-evolution-continues-netting-over.html"
      date = "2018-01-23"
      hash1 = "e7bebd1b1419f42293732c70095f35c8310fa3afee55f1df68d4fe6bbee5397e"
      hash2 = "72832db9b951663b8f322778440b8720ea95cde0349a1d26477edd95b3915479"
      hash3 = "3531bb1077c64840b9c95c45d382448abffa4f386ad88e125c96a38166832252"
      hash4 = "88d24b497cfeb47ec6719752f2af00c802c38e7d4b5d526311d552c6d5f4ad34"
      hash5 = "8eabfa74d88e439cfca9ccabd0ee34422892d8e58331a63bea94a7c4140cf7ab"
      hash6 = "88e344977bf6451e15fe202d65471a5f75d22370050fe6ba4dfa2c2d0fae7828"

strings:

      $s1 = "bedf08175d319a2f879fe720032d11e5" fullword wide
      $s2 = "ksdghksdghkddgdfgdfgfd" fullword ascii
      $s3 = "osieyrgvbsgnhkflkstesadfakdhaksjfgyjqqwgjrwgehjgfdjgdffg" fullword ascii
      $s4 = "5c2d376c976669efaf9cb107f5a83d0c" fullword wide
      $s5 = "B917754BCFE717EB4F7CE04A5B11A6351EEC5015" fullword ascii
      $s6 = "f99e47c1d4ccb2b103f5f730f8eb598a" fullword wide
      $s7 = "d2db284217a6e5596913e2e1a5b2672f" fullword wide
      $s8 = "0bddb8acd38f6da118f47243af48d8af" fullword wide
      $s9 = "f73623dcb4f62b0e5b9b4d83e1ee4323" fullword wide
      $s10 = "916ab48e32e904b8e1b87b7e3ced6d55" fullword wide
      $s11 = "c6e61622dc51e17195e4df6e359218a2" fullword wide
      $s12 = "2a9e8d549af13031f6bf7807242ce27f" fullword wide
      $s13 = "e3208957ad76d2f2e249276410744b29" fullword wide
      $s14 = "b4d28bbd65da97431f494dd7741bee70" fullword wide
      $s15 = "81ee346489c272f456f2b17d96365c34" fullword wide
      $s16 = "94682debc6f156b7e90e0d6dc772734d" fullword wide
      $s17 = "6943e17a989f11af750ea0441a713b89" fullword wide
      $s18 = "b1c7e24b315ff9c73a9a89afac5286be" fullword wide
      $s19 = "90928fd1250435589cc0150849bc0cff" fullword wide
      $s20 = "67da807268764a7badc4904df351932e" fullword wide

      $op0 = { 30 01 00 2b 68 79 33 38 68 34 77 65 36 34 74 72 }
      $op1 = { 01 00 b2 04 00 00 01 00 84 }
      $op2 = { 68 09 00 00 38 66 00 00 23 55 53 00 a0 6f 00 00 }

   condition:

      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them ) and all of ($op*)) or ( all of them )
}
rule shrug2_ransomware {

   meta:

      description = "Rule to detect the Shrug Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://blogs.quickheal.com/new-net-ransomware-shrug2/"

   strings:

      $s1 = "C:\\Users\\Gamer\\Desktop\\Shrug2\\ShrugTwo\\ShrugTwo\\obj\\Debug\\ShrugTwo.pdb" fullword ascii
      $s2 = "http://tempacc11vl.000webhostapp.com/" fullword wide
      $s4 = "Shortcut for @ShrugDecryptor@.exe" fullword wide
      $s5 = "C:\\Users\\" fullword wide
      $s6 = "http://clients3.google.com/generate_204" fullword wide
      $s7 = "\\Desktop\\@ShrugDecryptor@.lnk" fullword wide

   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them
}

rule ransomware_sodinokibi {
   meta:
      description = "Using a recently disclosed vulnerability in Oracle WebLogic, criminals use it to install a new variant of ransomware called ???Sodinokibi"
      author = "Christiaan Beek | McAfee ATR team"
      date = "2019-05-13"
      hash1 = "95ac3903127b74f8e4d73d987f5e3736f5bdd909ba756260e187b6bf53fb1a05"
      hash2 = "34dffdb04ca07b014cdaee857690f86e490050335291ccc84c94994fa91e0160"
      hash3 = "0fa207940ea53e2b54a2b769d8ab033a6b2c5e08c78bf4d7dade79849960b54d"
      hash4 = "9b62f917afa1c1a61e3be0978c8692dac797dd67ce0e5fd2305cc7c6b5fef392"
   strings:
      $x1 = "sodinokibi.exe" fullword wide

      $y0 = { 8d 85 6c ff ff ff 50 53 50 e8 62 82 00 00 83 c4 }
      $y1 = { e8 24 ea ff ff ff 75 08 8b ce e8 61 fc ff ff 8b }
      $y2 = { e8 01 64 ff ff ff b6 b0 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and pe.imphash() == "672b84df309666b9d7d2bc8cc058e4c2" and ( 8 of them ) and all of ($y*)
      ) or ( all of them )
}
]==]
-- #endregion


-- #region suspicious_rules
suspicious_rules = [==[
/*
    These rules are the GNU General Public License. See <http://www.gnu.org/licenses/>.
*/
rule RE_ToolReferences
{
    meta:
        description = "Contains references to debugging or reversing tools"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = /ida(q)?(64)?.exe/ nocase wide ascii
        $a1 = "ImmunityDebugger.exe" nocase wide ascii
        $a2 = "ollydbg.exe" nocase wide ascii
        $a3 = "lordpe.exe" nocase wide ascii
        $a4 = "peid.exe" nocase wide ascii
        $a5 = "windbg.exe" nocase wide ascii
    condition:
        any of them
}

rule AntivirusReferences
{
    meta:
        description = "Contains references to security software"
        author = "Jerome Athias"
        source = "Metasploit's killav.rb script"

    strings:
        $a0 = "AAWTray.exe" nocase wide ascii
        $a1 = "Ad-Aware.exe" nocase wide ascii
        $a2 = "MSASCui.exe" nocase wide ascii
        $a3 = "_avp32.exe" nocase wide ascii
        $a4 = "_avpcc.exe" nocase wide ascii
        $a5 = "_avpm.exe" nocase wide ascii
        $a6 = "aAvgApi.exe" nocase wide ascii
        $a7 = "ackwin32.exe" nocase wide ascii
        $a8 = "adaware.exe" nocase wide ascii
        $a9 = "advxdwin.exe" nocase wide ascii
        $a10 = "agentsvr.exe" nocase wide ascii
        $a11 = "agentw.exe" nocase wide ascii
        $a12 = "alertsvc.exe" nocase wide ascii
        $a13 = "alevir.exe" nocase wide ascii
        $a14 = "alogserv.exe" nocase wide ascii
        $a15 = "amon9x.exe" nocase wide ascii
        $a16 = "anti-trojan.exe" nocase wide ascii
        $a17 = "antivirus.exe" nocase wide ascii
        $a18 = "ants.exe" nocase wide ascii
        $a19 = "apimonitor.exe" nocase wide ascii
        $a20 = "aplica32.exe" nocase wide ascii
        $a21 = "apvxdwin.exe" nocase wide ascii
        $a22 = "arr.exe" nocase wide ascii
        $a23 = "atcon.exe" nocase wide ascii
        $a24 = "atguard.exe" nocase wide ascii
        $a25 = "atro55en.exe" nocase wide ascii
        $a26 = "atupdater.exe" nocase wide ascii
        $a27 = "atwatch.exe" nocase wide ascii
        $a28 = "au.exe" nocase wide ascii
        $a29 = "aupdate.exe" nocase wide ascii
        $a31 = "autodown.exe" nocase wide ascii
        $a32 = "autotrace.exe" nocase wide ascii
        $a33 = "autoupdate.exe" nocase wide ascii
        $a34 = "avconsol.exe" nocase wide ascii
        $a35 = "ave32.exe" nocase wide ascii
        $a36 = "avgcc32.exe" nocase wide ascii
        $a37 = "avgctrl.exe" nocase wide ascii
        $a38 = "avgemc.exe" nocase wide ascii
        $a39 = "avgnt.exe" nocase wide ascii
        $a40 = "avgrsx.exe" nocase wide ascii
        $a41 = "avgserv.exe" nocase wide ascii
        $a42 = "avgserv9.exe" nocase wide ascii
        $a43 = /av(gui|guard|center|gtray|gidsagent|gwdsvc|grsa|gcsrva|gcsrvx).exe/ nocase wide ascii
        $a44 = "avgw.exe" nocase wide ascii
        $a45 = "avkpop.exe" nocase wide ascii
        $a46 = "avkserv.exe" nocase wide ascii
        $a47 = "avkservice.exe" nocase wide ascii
        $a48 = "avkwctl9.exe" nocase wide ascii
        $a49 = "avltmain.exe" nocase wide ascii
        $a50 = "avnt.exe" nocase wide ascii
        $a51 = "avp.exe" nocase wide ascii
        $a52 = "avp.exe" nocase wide ascii
        $a53 = "avp32.exe" nocase wide ascii
        $a54 = "avpcc.exe" nocase wide ascii
        $a55 = "avpdos32.exe" nocase wide ascii
        $a56 = "avpm.exe" nocase wide ascii
        $a57 = "avptc32.exe" nocase wide ascii
        $a58 = "avpupd.exe" nocase wide ascii
        $a59 = "avsched32.exe" nocase wide ascii
        $a60 = "avsynmgr.exe" nocase wide ascii
        $a61 = "avwin.exe" nocase wide ascii
        $a62 = "avwin95.exe" nocase wide ascii
        $a63 = "avwinnt.exe" nocase wide ascii
        $a64 = "avwupd.exe" nocase wide ascii
        $a65 = "avwupd32.exe" nocase wide ascii
        $a66 = "avwupsrv.exe" nocase wide ascii
        $a67 = "avxmonitor9x.exe" nocase wide ascii
        $a68 = "avxmonitornt.exe" nocase wide ascii
        $a69 = "avxquar.exe" nocase wide ascii
        $a73 = "beagle.exe" nocase wide ascii
        $a74 = "belt.exe" nocase wide ascii
        $a75 = "bidef.exe" nocase wide ascii
        $a76 = "bidserver.exe" nocase wide ascii
        $a77 = "bipcp.exe" nocase wide ascii
        $a79 = "bisp.exe" nocase wide ascii
        $a80 = "blackd.exe" nocase wide ascii
        $a81 = "blackice.exe" nocase wide ascii
        $a82 = "blink.exe" nocase wide ascii
        $a83 = "blss.exe" nocase wide ascii
        $a84 = "bootconf.exe" nocase wide ascii
        $a85 = "bootwarn.exe" nocase wide ascii
        $a86 = "borg2.exe" nocase wide ascii
        $a87 = "bpc.exe" nocase wide ascii
        $a89 = "bs120.exe" nocase wide ascii
        $a90 = "bundle.exe" nocase wide ascii
        $a91 = "bvt.exe" nocase wide ascii
        $a92 = "ccapp.exe" nocase wide ascii
        $a93 = "ccevtmgr.exe" nocase wide ascii
        $a94 = "ccpxysvc.exe" nocase wide ascii
        $a95 = "cdp.exe" nocase wide ascii
        $a96 = "cfd.exe" nocase wide ascii
        $a97 = "cfgwiz.exe" nocase wide ascii
        $a98 = "cfiadmin.exe" nocase wide ascii
        $a99 = "cfiaudit.exe" nocase wide ascii
        $a100 = "cfinet.exe" nocase wide ascii
        $a101 = "cfinet32.exe" nocase wide ascii
        $a102 = "claw95.exe" nocase wide ascii
        $a103 = "claw95cf.exe" nocase wide ascii
        $a104 = "clean.exe" nocase wide ascii
        $a105 = "cleaner.exe" nocase wide ascii
        $a106 = "cleaner3.exe" nocase wide ascii
        $a107 = "cleanpc.exe" nocase wide ascii
        $a108 = "click.exe" nocase wide ascii
        $a111 = "cmesys.exe" nocase wide ascii
        $a112 = "cmgrdian.exe" nocase wide ascii
        $a113 = "cmon016.exe" nocase wide ascii
        $a114 = "connectionmonitor.exe" nocase wide ascii
        $a115 = "cpd.exe" nocase wide ascii
        $a116 = "cpf9x206.exe" nocase wide ascii
        $a117 = "cpfnt206.exe" nocase wide ascii
        $a118 = "ctrl.exe" nocase wide ascii fullword
        $a119 = "cv.exe" nocase wide ascii
        $a120 = "cwnb181.exe" nocase wide ascii
        $a121 = "cwntdwmo.exe" nocase wide ascii
        $a123 = "dcomx.exe" nocase wide ascii
        $a124 = "defalert.exe" nocase wide ascii
        $a125 = "defscangui.exe" nocase wide ascii
        $a126 = "defwatch.exe" nocase wide ascii
        $a127 = "deputy.exe" nocase wide ascii
        $a129 = "dllcache.exe" nocase wide ascii
        $a130 = "dllreg.exe" nocase wide ascii
        $a132 = "dpf.exe" nocase wide ascii
        $a134 = "dpps2.exe" nocase wide ascii
        $a135 = "drwatson.exe" nocase wide ascii
        $a136 = "drweb32.exe" nocase wide ascii
        $a137 = "drwebupw.exe" nocase wide ascii
        $a138 = "dssagent.exe" nocase wide ascii
        $a139 = "dvp95.exe" nocase wide ascii
        $a140 = "dvp95_0.exe" nocase wide ascii
        $a141 = "ecengine.exe" nocase wide ascii
        $a142 = "efpeadm.exe" nocase wide ascii
        $a143 = "emsw.exe" nocase wide ascii
        $a145 = "esafe.exe" nocase wide ascii
        $a146 = "escanhnt.exe" nocase wide ascii
        $a147 = "escanv95.exe" nocase wide ascii
        $a148 = "espwatch.exe" nocase wide ascii
        $a150 = "etrustcipe.exe" nocase wide ascii
        $a151 = "evpn.exe" nocase wide ascii
        $a152 = "exantivirus-cnet.exe" nocase wide ascii
        $a153 = "exe.avxw.exe" nocase wide ascii
        $a154 = "expert.exe" nocase wide ascii
        $a156 = "f-agnt95.exe" nocase wide ascii
        $a157 = "f-prot.exe" nocase wide ascii
        $a158 = "f-prot95.exe" nocase wide ascii
        $a159 = "f-stopw.exe" nocase wide ascii
        $a160 = "fameh32.exe" nocase wide ascii
        $a161 = "fast.exe" nocase wide ascii
        $a162 = "fch32.exe" nocase wide ascii
        $a163 = "fih32.exe" nocase wide ascii
        $a164 = "findviru.exe" nocase wide ascii
        $a165 = "firewall.exe" nocase wide ascii
        $a166 = "fnrb32.exe" nocase wide ascii
        $a167 = "fp-win.exe" nocase wide ascii
        $a169 = "fprot.exe" nocase wide ascii
        $a170 = "frw.exe" nocase wide ascii
        $a171 = "fsaa.exe" nocase wide ascii
        $a172 = "fsav.exe" nocase wide ascii
        $a173 = "fsav32.exe" nocase wide ascii
        $a176 = "fsav95.exe" nocase wide ascii
        $a177 = "fsgk32.exe" nocase wide ascii
        $a178 = "fsm32.exe" nocase wide ascii
        $a179 = "fsma32.exe" nocase wide ascii
        $a180 = "fsmb32.exe" nocase wide ascii
        $a181 = "gator.exe" nocase wide ascii
        $a182 = "gbmenu.exe" nocase wide ascii
        $a183 = "gbpoll.exe" nocase wide ascii
        $a184 = "generics.exe" nocase wide ascii
        $a185 = "gmt.exe" nocase wide ascii
        $a186 = "guard.exe" nocase wide ascii
        $a187 = "guarddog.exe" nocase wide ascii
        $a189 = "hbinst.exe" nocase wide ascii
        $a190 = "hbsrv.exe" nocase wide ascii
        $a191 = "hotactio.exe" nocase wide ascii
        $a192 = "hotpatch.exe" nocase wide ascii
        $a193 = "htlog.exe" nocase wide ascii
        $a194 = "htpatch.exe" nocase wide ascii
        $a195 = "hwpe.exe" nocase wide ascii
        $a196 = "hxdl.exe" nocase wide ascii
        $a197 = "hxiul.exe" nocase wide ascii
        $a198 = "iamapp.exe" nocase wide ascii
        $a199 = "iamserv.exe" nocase wide ascii
        $a200 = "iamstats.exe" nocase wide ascii
        $a201 = "ibmasn.exe" nocase wide ascii
        $a202 = "ibmavsp.exe" nocase wide ascii
        $a203 = "icload95.exe" nocase wide ascii
        $a204 = "icloadnt.exe" nocase wide ascii
        $a205 = "icmon.exe" nocase wide ascii
        $a206 = "icsupp95.exe" nocase wide ascii
        $a207 = "icsuppnt.exe" nocase wide ascii
        $a209 = "iedll.exe" nocase wide ascii
        $a210 = "iedriver.exe" nocase wide ascii
        $a212 = "iface.exe" nocase wide ascii
        $a213 = "ifw2000.exe" nocase wide ascii
        $a214 = "inetlnfo.exe" nocase wide ascii
        $a215 = "infus.exe" nocase wide ascii
        $a216 = "infwin.exe" nocase wide ascii
        $a218 = "intdel.exe" nocase wide ascii
        $a219 = "intren.exe" nocase wide ascii
        $a220 = "iomon98.exe" nocase wide ascii
        $a221 = "istsvc.exe" nocase wide ascii
        $a222 = "jammer.exe" nocase wide ascii
        $a224 = "jedi.exe" nocase wide ascii
        $a227 = "kavpf.exe" nocase wide ascii
        $a228 = "kazza.exe" nocase wide ascii
        $a229 = "keenvalue.exe" nocase wide ascii
        $a236 = "ldnetmon.exe" nocase wide ascii
        $a237 = "ldpro.exe" nocase wide ascii
        $a238 = "ldpromenu.exe" nocase wide ascii
        $a239 = "ldscan.exe" nocase wide ascii
        $a240 = "lnetinfo.exe" nocase wide ascii
        $a242 = "localnet.exe" nocase wide ascii
        $a243 = "lockdown.exe" nocase wide ascii
        $a244 = "lockdown2000.exe" nocase wide ascii
        $a245 = "lookout.exe" nocase wide ascii
        $a248 = "luall.exe" nocase wide ascii
        $a249 = "luau.exe" nocase wide ascii
        $a250 = "lucomserver.exe" nocase wide ascii
        $a251 = "luinit.exe" nocase wide ascii
        $a252 = "luspt.exe" nocase wide ascii
        $a253 = "mapisvc32.exe" nocase wide ascii
        $a254 = "mcagent.exe" nocase wide ascii
        $a255 = "mcmnhdlr.exe" nocase wide ascii
        $a256 = "mcshield.exe" nocase wide ascii
        $a257 = "mctool.exe" nocase wide ascii
        $a258 = "mcupdate.exe" nocase wide ascii
        $a259 = "mcvsrte.exe" nocase wide ascii
        $a260 = "mcvsshld.exe" nocase wide ascii
        $a262 = "mfin32.exe" nocase wide ascii
        $a263 = "mfw2en.exe" nocase wide ascii
        $a265 = "mgavrtcl.exe" nocase wide ascii
        $a266 = "mgavrte.exe" nocase wide ascii
        $a267 = "mghtml.exe" nocase wide ascii
        $a268 = "mgui.exe" nocase wide ascii
        $a269 = "minilog.exe" nocase wide ascii
        $a270 = "mmod.exe" nocase wide ascii
        $a271 = "monitor.exe" nocase wide ascii
        $a272 = "moolive.exe" nocase wide ascii
        $a273 = "mostat.exe" nocase wide ascii
        $a274 = "mpfagent.exe" nocase wide ascii
        $a275 = "mpfservice.exe" nocase wide ascii
        $a276 = "mpftray.exe" nocase wide ascii
        $a277 = "mrflux.exe" nocase wide ascii
        $a278 = "msapp.exe" nocase wide ascii
        $a279 = "msbb.exe" nocase wide ascii
        $a280 = "msblast.exe" nocase wide ascii
        $a281 = "mscache.exe" nocase wide ascii
        $a282 = "msccn32.exe" nocase wide ascii
        $a283 = "mscman.exe" nocase wide ascii
        $a285 = "msdm.exe" nocase wide ascii
        $a286 = "msdos.exe" nocase wide ascii
        $a287 = "msiexec16.exe" nocase wide ascii
        $a288 = "msinfo32.exe" nocase wide ascii
        $a289 = "mslaugh.exe" nocase wide ascii
        $a290 = "msmgt.exe" nocase wide ascii
        $a291 = "msmsgri32.exe" nocase wide ascii
        $a292 = "mssmmc32.exe" nocase wide ascii
        $a293 = "mssys.exe" nocase wide ascii
        $a294 = "msvxd.exe" nocase wide ascii
        $a295 = "mu0311ad.exe" nocase wide ascii
        $a296 = "mwatch.exe" nocase wide ascii
        $a297 = "n32scanw.exe" nocase wide ascii
        $a298 = "nav.exe" nocase wide ascii
        $a300 = "navapsvc.exe" nocase wide ascii
        $a301 = "navapw32.exe" nocase wide ascii
        $a302 = "navdx.exe" nocase wide ascii
        $a303 = "navlu32.exe" nocase wide ascii
        $a304 = "navnt.exe" nocase wide ascii
        $a305 = "navstub.exe" nocase wide ascii
        $a306 = "navw32.exe" nocase wide ascii
        $a307 = "navwnt.exe" nocase wide ascii
        $a308 = "nc2000.exe" nocase wide ascii
        $a309 = "ncinst4.exe" nocase wide ascii
        $a310 = "ndd32.exe" nocase wide ascii
        $a311 = "neomonitor.exe" nocase wide ascii
        $a312 = "neowatchlog.exe" nocase wide ascii
        $a313 = "netarmor.exe" nocase wide ascii
        $a314 = "netd32.exe" nocase wide ascii
        $a315 = "netinfo.exe" nocase wide ascii
        $a317 = "netscanpro.exe" nocase wide ascii
        $a320 = "netutils.exe" nocase wide ascii
        $a321 = "nisserv.exe" nocase wide ascii
        $a322 = "nisum.exe" nocase wide ascii
        $a323 = "nmain.exe" nocase wide ascii
        $a324 = "nod32.exe" nocase wide ascii
        $a325 = "normist.exe" nocase wide ascii
        $a327 = "notstart.exe" nocase wide ascii
        $a329 = "npfmessenger.exe" nocase wide ascii
        $a330 = "nprotect.exe" nocase wide ascii
        $a331 = "npscheck.exe" nocase wide ascii
        $a332 = "npssvc.exe" nocase wide ascii
        $a333 = "nsched32.exe" nocase wide ascii
        $a334 = "nssys32.exe" nocase wide ascii
        $a335 = "nstask32.exe" nocase wide ascii
        $a336 = "nsupdate.exe" nocase wide ascii
        $a338 = "ntrtscan.exe" nocase wide ascii
        $a340 = "ntxconfig.exe" nocase wide ascii
        $a341 = "nui.exe" nocase wide ascii
        $a342 = "nupgrade.exe" nocase wide ascii
        $a343 = "nvarch16.exe" nocase wide ascii
        $a344 = "nvc95.exe" nocase wide ascii
        $a345 = "nvsvc32.exe" nocase wide ascii
        $a346 = "nwinst4.exe" nocase wide ascii
        $a347 = "nwservice.exe" nocase wide ascii
        $a348 = "nwtool16.exe" nocase wide ascii
        $a350 = "onsrvr.exe" nocase wide ascii
        $a351 = "optimize.exe" nocase wide ascii
        $a352 = "ostronet.exe" nocase wide ascii
        $a353 = "otfix.exe" nocase wide ascii
        $a354 = "outpost.exe" nocase wide ascii
        $a360 = "pavcl.exe" nocase wide ascii
        $a361 = "pavproxy.exe" nocase wide ascii
        $a362 = "pavsched.exe" nocase wide ascii
        $a363 = "pavw.exe" nocase wide ascii
        $a364 = "pccwin98.exe" nocase wide ascii
        $a365 = "pcfwallicon.exe" nocase wide ascii
        $a367 = "pcscan.exe" nocase wide ascii
        $a369 = "periscope.exe" nocase wide ascii
        $a370 = "persfw.exe" nocase wide ascii
        $a371 = "perswf.exe" nocase wide ascii
        $a372 = "pf2.exe" nocase wide ascii
        $a373 = "pfwadmin.exe" nocase wide ascii
        $a374 = "pgmonitr.exe" nocase wide ascii
        $a375 = "pingscan.exe" nocase wide ascii
        $a376 = "platin.exe" nocase wide ascii
        $a377 = "pop3trap.exe" nocase wide ascii
        $a378 = "poproxy.exe" nocase wide ascii
        $a379 = "popscan.exe" nocase wide ascii
        $a380 = "portdetective.exe" nocase wide ascii
        $a381 = "portmonitor.exe" nocase wide ascii
        $a382 = "powerscan.exe" nocase wide ascii
        $a383 = "ppinupdt.exe" nocase wide ascii
        $a384 = "pptbc.exe" nocase wide ascii
        $a385 = "ppvstop.exe" nocase wide ascii
        $a387 = "prmt.exe" nocase wide ascii
        $a388 = "prmvr.exe" nocase wide ascii
        $a389 = "procdump.exe" nocase wide ascii
        $a390 = "processmonitor.exe" nocase wide ascii
        $a392 = "programauditor.exe" nocase wide ascii
        $a393 = "proport.exe" nocase wide ascii
        $a394 = "protectx.exe" nocase wide ascii
        $a395 = "pspf.exe" nocase wide ascii
        $a396 = "purge.exe" nocase wide ascii
        $a397 = "qconsole.exe" nocase wide ascii
        $a398 = "qserver.exe" nocase wide ascii
        $a399 = "rapapp.exe" nocase wide ascii
        $a400 = "rav7.exe" nocase wide ascii
        $a401 = "rav7win.exe" nocase wide ascii
        $a404 = "rb32.exe" nocase wide ascii
        $a405 = "rcsync.exe" nocase wide ascii
        $a406 = "realmon.exe" nocase wide ascii
        $a407 = "reged.exe" nocase wide ascii
        $a410 = "rescue.exe" nocase wide ascii
        $a412 = "rrguard.exe" nocase wide ascii
        $a413 = "rshell.exe" nocase wide ascii
        $a414 = "rtvscan.exe" nocase wide ascii
        $a415 = "rtvscn95.exe" nocase wide ascii
        $a416 = "rulaunch.exe" nocase wide ascii
        $a421 = "safeweb.exe" nocase wide ascii
        $a422 = "sahagent.exe" nocase wide ascii
        $a424 = "savenow.exe" nocase wide ascii
        $a425 = "sbserv.exe" nocase wide ascii
        $a428 = "scan32.exe" nocase wide ascii
        $a430 = "scanpm.exe" nocase wide ascii
        $a431 = "scrscan.exe" nocase wide ascii
        $a435 = "sfc.exe" nocase wide ascii
        $a436 = "sgssfw32.exe" nocase wide ascii
        $a439 = "shn.exe" nocase wide ascii
        $a440 = "showbehind.exe" nocase wide ascii
        $a441 = "smc.exe" nocase wide ascii
        $a442 = "sms.exe" nocase wide ascii
        $a443 = "smss32.exe" nocase wide ascii
        $a445 = "sofi.exe" nocase wide ascii
        $a447 = "spf.exe" nocase wide ascii
        $a449 = "spoler.exe" nocase wide ascii
        $a450 = "spoolcv.exe" nocase wide ascii
        $a451 = "spoolsv32.exe" nocase wide ascii
        $a452 = "spyxx.exe" nocase wide ascii
        $a453 = "srexe.exe" nocase wide ascii
        $a454 = "srng.exe" nocase wide ascii
        $a455 = "ss3edit.exe" nocase wide ascii
        $a457 = "ssgrate.exe" nocase wide ascii
        $a458 = "st2.exe" nocase wide ascii fullword
        $a461 = "supftrl.exe" nocase wide ascii
        $a470 = "symproxysvc.exe" nocase wide ascii
        $a471 = "symtray.exe" nocase wide ascii
        $a472 = "sysedit.exe" nocase wide ascii
        $a480 = "taumon.exe" nocase wide ascii
        $a481 = "tbscan.exe" nocase wide ascii
        $a483 = "tca.exe" nocase wide ascii
        $a484 = "tcm.exe" nocase wide ascii
        $a488 = "teekids.exe" nocase wide ascii
        $a489 = "tfak.exe" nocase wide ascii
        $a490 = "tfak5.exe" nocase wide ascii
        $a491 = "tgbob.exe" nocase wide ascii
        $a492 = "titanin.exe" nocase wide ascii
        $a493 = "titaninxp.exe" nocase wide ascii
        $a496 = "trjscan.exe" nocase wide ascii
        $a500 = "tvmd.exe" nocase wide ascii
        $a501 = "tvtmd.exe" nocase wide ascii
        $a513 = "vet32.exe" nocase wide ascii
        $a514 = "vet95.exe" nocase wide ascii
        $a515 = "vettray.exe" nocase wide ascii
        $a517 = "vir-help.exe" nocase wide ascii
        $a519 = "vnlan300.exe" nocase wide ascii
        $a520 = "vnpc3000.exe" nocase wide ascii
        $a521 = "vpc32.exe" nocase wide ascii
        $a522 = "vpc42.exe" nocase wide ascii
        $a523 = "vpfw30s.exe" nocase wide ascii
        $a524 = "vptray.exe" nocase wide ascii
        $a525 = "vscan40.exe" nocase wide ascii
        $a527 = "vsched.exe" nocase wide ascii
        $a528 = "vsecomr.exe" nocase wide ascii
        $a529 = "vshwin32.exe" nocase wide ascii
        $a531 = "vsmain.exe" nocase wide ascii
        $a532 = "vsmon.exe" nocase wide ascii
        $a533 = "vsstat.exe" nocase wide ascii
        $a534 = "vswin9xe.exe" nocase wide ascii
        $a535 = "vswinntse.exe" nocase wide ascii
        $a536 = "vswinperse.exe" nocase wide ascii
        $a537 = "w32dsm89.exe" nocase wide ascii
        $a538 = "w9x.exe" nocase wide ascii
        $a541 = "webscanx.exe" nocase wide ascii
        $a543 = "wfindv32.exe" nocase wide ascii
        $a545 = "wimmun32.exe" nocase wide ascii
        $a566 = "wnad.exe" nocase wide ascii
        $a567 = "wnt.exe" nocase wide ascii
        $a568 = "wradmin.exe" nocase wide ascii
        $a569 = "wrctrl.exe" nocase wide ascii
        $a570 = "wsbgate.exe" nocase wide ascii
        $a573 = "wyvernworksfirewall.exe" nocase wide ascii
        $a575 = "zapro.exe" nocase wide ascii
        $a577 = "zatutor.exe" nocase wide ascii
        $a579 = "zonealarm.exe" nocase wide ascii
		// Strings from Dubnium below
		$a580 = "QQPCRTP.exe" nocase wide ascii
		$a581 = "QQPCTray.exe" nocase wide ascii
		$a582 = "ZhuDongFangYu.exe" nocase wide ascii
		$a583 = /360(tray|sd|rp).exe/ nocase wide ascii
		$a584 = /qh(safetray|watchdog|activedefense).exe/ nocase wide ascii
		$a585 = "McNASvc.exe" nocase wide ascii
		$a586 = "MpfSrv.exe" nocase wide ascii
		$a587 = "McProxy.exe" nocase wide ascii
		$a588 = "mcmscsvc.exe" nocase wide ascii
		$a589 = "McUICnt.exe" nocase wide ascii
		$a590 = /ui(WatchDog|seagnt|winmgr).exe/ nocase wide ascii
		$a591 = "ufseagnt.exe" nocase wide ascii
		$a592 = /core(serviceshell|frameworkhost).exe/ nocase wide ascii
		$a593 = /ay(agent|rtsrv|updsrv).aye/ nocase wide ascii
		$a594 = /avast(ui|svc).exe/ nocase wide ascii
		$a595 = /ms(seces|mpeng).exe/ nocase wide ascii
		$a596 = "afwserv.exe" nocase wide ascii
		$a597 = "FiddlerUser"

    condition:
        any of them
}
rule VirtualBox_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualBox presence"
        author = "Cuckoo project"
    strings:
        $virtualbox1 = "VBoxHook.dll" nocase wide ascii
        $virtualbox2 = "VBoxService" nocase wide ascii
        $virtualbox3 = "VBoxTray" nocase wide ascii
        $virtualbox4 = "VBoxMouse" nocase wide ascii
        $virtualbox5 = "VBoxGuest" nocase wide ascii
        $virtualbox6 = "VBoxSF" nocase wide ascii
        $virtualbox7 = "VBoxGuestAdditions" nocase wide ascii
        $virtualbox8 = "VBOX HARDDISK" nocase wide ascii
        $virtualbox9 = "vboxservice" nocase wide ascii
        $virtualbox10 = "vboxtray" nocase wide ascii

        // MAC addresses
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"
        $virtualbox_mac_1c = "080027"

        // PCI Vendor IDs, from Hacking Team's leak
        $virtualbox_vid_1 = "VEN_80EE" nocase wide ascii

        // Registry keys
        $virtualbox_reg_1 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase wide ascii
        $virtualbox_reg_2 = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\VBOX__/ nocase wide ascii

        // Other
        $virtualbox_files = /C:\\Windows\\System32\\drivers\\vbox.{15}\.(sys|dll)/ nocase wide ascii
        $virtualbox_services = "System\\ControlSet001\\Services\\VBox[A-Za-z]+" nocase wide ascii
        $virtualbox_pipe = /\\\\.\\pipe\\(VBoxTrayIPC|VBoxMiniRdDN)/ nocase wide ascii
        $virtualbox_window = /VBoxTrayToolWnd(Class)?/ nocase wide ascii
    condition:
        any of them
}

rule Dropper_Strings
{
    meta:
        description = "May have dropper capabilities"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "CurrentVersion\\Run" nocase wide ascii
        $a1 = "CurrentControlSet\\Services" nocase wide ascii
        $a2 = "Programs\\Startup" nocase wide ascii
        $a3 = "%temp%" nocase wide ascii
        $a4 = "%allusersprofile%" nocase wide ascii
    condition:
        any of them
}

rule create_service {
    meta:
        author = "x0r"
        description = "Create a windows service"
	version = "0.2"
    strings:
	$f1 = "Advapi32.dll" nocase
        $c1 = "CreateService"
        $c2 = "ControlService"
        $c3 = "StartService"
        $c4 = "QueryServiceStatus"
    condition:
        all of them
}

rule network_dyndns {
    meta:
        author = "x0r"
        description = "Communications dyndns network"
	version = "0.1"
    strings:
	$s1 =".no-ip.org"
        $s2 =".publicvm.com"
        $s3 =".linkpc.net"
        $s4 =".dynu.com"
        $s5 =".dynu.net"
        $s6 =".afraid.org"
        $s7 =".chickenkiller.com"
        $s8 =".crabdance.com"
        $s9 =".ignorelist.com"
        $s10 =".jumpingcrab.com"
        $s11 =".moo.com"
        $s12 =".strangled.com"
        $s13 =".twillightparadox.com"
        $s14 =".us.to"
        $s15 =".strangled.net"
        $s16 =".info.tm"
        $s17 =".homenet.org"
        $s18 =".biz.tm"
        $s19 =".continent.kz"
        $s20 =".ax.lt"
        $s21 =".system-ns.com"
        $s22 =".adultdns.com"
        $s23 =".craftx.biz"
        $s24 =".ddns01.com"
        $s25 =".dns53.biz"
        $s26 =".dnsapi.info"
        $s27 =".dnsd.info"
        $s28 =".dnsdynamic.com"
        $s29 =".dnsdynamic.net"
        $s30 =".dnsget.org"
        $s31 =".fe100.net"
        $s32 =".flashserv.net"
        $s33 =".ftp21.net"
    condition:
        any of them
}

rule network_tor {
    meta:
        author = "x0r"
        description = "Communications over TOR network"
	version = "0.1"
    strings:
        $p1 = "tor\\hidden_service\\private_key" nocase
        $p2 = "tor\\hidden_service\\hostname" nocase
        $p3 = "tor\\lock" nocase
        $p4 = "tor\\state" nocase
    condition:
        any of them
}

rule network_dropper {
    meta:
        author = "x0r"
        description = "File downloader/dropper"
	version = "0.1"
    strings:
        $f1 = "urlmon.dll" nocase
        $c1 = "URLDownloadToFile"
        $c2 = "URLDownloadToCacheFile"
        $c3 = "URLOpenStream"
        $c4 = "URLOpenPullStream"
    condition:
        $f1 and 1 of ($c*)
}

rule network_ftp {
    meta:
        author = "x0r"
        description = "Communications over FTP"
	version = "0.1"
    strings:
	   $f1 = "Wininet.dll" nocase
        $c1 = "FtpGetCurrentDirectory"
        $c2 = "FtpGetFile"
        $c3 = "FtpPutFile"
        $c4 = "FtpSetCurrentDirectory"
        $c5 = "FtpOpenFile"
        $c6 = "FtpGetFileSize"
        $c7 = "FtpDeleteFile"
        $c8 = "FtpCreateDirectory"
        $c9 = "FtpRemoveDirectory"
        $c10 = "FtpRenameFile"
        $c11 = "FtpDownload"
        $c12 = "FtpUpload"
        $c13 = "FtpGetDirectory"
    condition:
        $f1 and (4 of ($c*))
}

rule network_tcp_socket {
    meta:
        author = "x0r"
        description = "Communications over RAW socket"
	version = "0.1"
    strings:
	$f1 = "Ws2_32.dll" nocase
        $f2 = "wsock32.dll" nocase
        $c1 = "WSASocket"
        $c2 = "socket"
        $c3 = "send"
        $c4 = "WSASend"
        $c5 = "WSAConnect"
        $c6 = "connect"
        $c7 = "WSAStartup"
        $c8 = "closesocket"
        $c9 = "WSACleanup"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dns {
    meta:
        author = "x0r"
        description = "Communications use DNS"
	version = "0.1"
    strings:
        $f1 = "System.Net"
        $f2 = "Ws2_32.dll" nocase
        $f3 = "Dnsapi.dll" nocase
        $f4 = "wsock32.dll" nocase
        $c2 = "GetHostEntry"
	    $c3 = "getaddrinfo"
	    $c4 = "gethostbyname"
	    $c5 = "WSAAsyncGetHostByName"
	    $c6 = "DnsQuery"
    condition:
        1 of ($f*) and  1 of ($c*)
}

rule certificate {
    meta:
        author = "x0r"
        description = "Inject certificate in store"
	version = "0.1"
    strings:
        $f1 = "Crypt32.dll" nocase
        $r1 = "software\\microsoft\\systemcertificates\\spc\\certificates" nocase
        $c1 = "CertOpenSystemStore"
    condition:
	all of them
}

rule lookupip {
    meta:
        author = "x0r"
        description = "Lookup external IP"
	version = "0.1"
    strings:
        $n1 = "checkip.dyndns.org" nocase
        $n2 = "whatismyip.org" nocase
        $n3 = "whatsmyipaddress.com" nocase
        $n4 = "getmyip.org" nocase
        $n5 = "getmyip.co.uk" nocase
    condition:
        any of them
}

rule keylogger {
    meta:
        author = "x0r"
        description = "Run a keylogger"
	version = "0.1"
    strings:
	    $f1 = "User32.dll" nocase
        $c1 = "GetAsyncKeyState"
        $c2 = "GetKeyState"
        $c3 = "MapVirtualKey"
        $c4 = "GetKeyboardType"
    condition:
        $f1 and 1 of ($c*)
}

rule cred_local {
    meta:
        author = "x0r"
        description = "Steal credential"
	version = "0.1"
    strings:
        $c1 = "LsaEnumerateLogonSessions"
        $c2 = "SamIConnect"
        $c3 = "SamIGetPrivateData"
        $c4 = "SamQueryInformationUse"
        $c5 = "CredEnumerateA"
        $c6 = "CredEnumerateW"
        $r1 = "software\\microsoft\\internet account manager" nocase
        $r2 = "software\\microsoft\\identitycrl\\creds" nocase
        $r3 = "Security\\Policy\\Secrets"
    condition:
        any of them
}
]==]
-- #endregion

-- #region info_rules
info_rules = [==[
rule MZ_executable {
	strings:
		$mz = "MZ"

	condition:
		$mz at 0
}
rule embedded_url {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ wide ascii
    condition:
        $url_regex
}
]==]
-- #endregion



function GetFileName(path)
  return path:match("^.+/(.+)$")
end

function GetFileExtension(path)
  return path:match("^.+(%..+)$")
end

function is_executable(path)
    magicnumbers = {
        "MZ",
        ".ELF"
    }
    local f,msg = io.open(path, "rb")
    if not f then
        hunt.debug(msg)
        return nil
    end
    local bytes = f:read(4)
    if bytes then
        -- print(bytes)
        for _,n in pairs(magicnumbers) do
            magicheader = string.find(bytes, n)
            if magicheader then
                -- print(string.byte(magicheader))
                f:close()
                return true
            end
        end
        f:close()
        return false
    end
end


----------------------------------------------------
-- SECTION 3: Collection / Inspection

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- Load Yara rules
yara_bad = hunt.yara.new()
yara_bad:add_rule(bad_rules)

yara_suspicious = hunt.yara.new()
yara_suspicious:add_rule(suspicious_rules)

yara_info = hunt.yara.new()
yara_info:add_rule(info_rules)


-- Add active processes
paths = {}
if scanactiveprocesses then
    procs = hunt.process.list()
    for i, proc in pairs(procs) do
        --hunt.debug("Adding processpath["..i.."]: " .. proc:path())
        paths[proc:path()] = true
    end
end

-- Add appdata paths
if scanappdata then
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        opts = {
            "files",
            "size<1mb",
            "recurse=1" --depth of 1
        }
        for _, path in pairs(hunt.fs.ls(userfolder:path().."\\appdata\\roaming", opts)) do
            if is_executable(path:path()) then
                paths[path:path()] = true
            end
        end
    end
end

-- Add additional paths
for i, path in pairs(additionalpaths) do
    files = hunt.fs.ls(path)
    if type(files) == "table" then
        for _,path in pairs(files) do
            if is_executable(path:name()) then
                paths[path:name()] = true
            end
        end
    else
        if is_executable(path:name()) then
            paths[files:name()] = true
        end
    end
end

matchedpaths = {}

-- Scan all paths with Yara signatures
for path, i in pairs(paths) do
    print('[i] Scanning ' .. path)
    for _, signature in pairs(yara_bad:scan(path)) do
        if not hash then
            hash = hunt.hash.sha1(path)
        end
        hunt.log('[BAD] Yara matched [' .. signature .. '] in file: ' .. path .. " <"..hash..">")
        bad = true
		matchedpaths[path] = true
    end
    for _, signature in pairs(yara_suspicious:scan(path)) do
        if not hash then
            hash = hunt.hash.sha1(path)
        end
        hunt.log('[SUSPICIOUS] Yara matched [' .. signature .. '] in file: ' .. path .. " <"..hash..">")
        suspicious = true
		matchedpaths[path] = true
    end
    for _, signature in pairs(yara_info:scan(path)) do
        if not hash then
            hash = hunt.hash.sha1(path)
        end
        hunt.log('[INFO] Yara matched [' .. signature .. '] in file: ' .. path .. " <"..hash..">")
        lowrisk = true
    end
    hash = nil
end

-- Add bad and suspicious files to Artifacts list for analysis
for path,i in pairs(matchedpaths) do
	-- Create a new artifact
	artifact = hunt.survey.artifact()
	artifact:exe(path)
	artifact:type("Yara Match")
	hunt.survey.add(artifact)
end

-- Set threat status
if bad then
    hunt.status.bad()
elseif suspicious then
    hunt.status.suspicious()
elseif lowrisk then
    hunt.status.lowrisk()
else
    hunt.status.good()
end

hunt.verbose("Result: Extension successfully executed on " .. host_info:hostname())

----------------------------------------------------
