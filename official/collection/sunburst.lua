--[=[
name: Sunburst Malware Scanner
filetype: Infocyte Extension
type: Collection
description: | 
    Checks for indicators of compromise related to Solarigate such as Sunburst, Raindrop, Teardrop and supernova.
    All active processes, loaded DLLs, and some additional path folders specified below are scanned.
    Sunburst is reported to be used as a custom dropper embedded in legitimate signed Solarwinds DLLS.
    This dropper will load other malware payloads such as Cobalt Strike Beacons into memory 
    which are used to steal credentials and pivot through the network.
    Beacons and other memory-only footholds will be found natively with 
    Infocyte's memory scans (you will see memory injects in common Windows processes)
    Kerberosting (golden tickets) is also used but you will need to review eventId 4769 for suspicious behavior
    https://cyber.dhs.gov/ed/21-01/
    https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
author: Infocyte
guid: 88526dd4-bba9-40e0-a561-d108c1c1fa2b
created: 2020-12-14
updated: 2020-12-16

# Global variables
globals:

# Runtime arguments
args:

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])


-- max file size to scan
max_size_default = 10000
max_size = hunt.global.number("yarascanner_max_size", false, max_size_default)

additional_paths = hunt.global.string("sunburst_additional_paths")

scan_activeprocesses = true
scan_userfolders = true
primary_paths = {
    "C:\\WINDOWS\\SysWOW64\\netsetupsvc.dll"
}

dllnames = {
    "SolarWinds.Orion.Core.BusinessLayer.dll",
    "App_Web_logoimagehandler.ashx.b6031896.dll"
}

hunt.debug(f"Inputs: max_size=${max_size}; additional_paths=${additional_paths}")

rules = [=[
// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/sunburst_countermeasures/blob/main/LICENSE.txt

rule APT_Backdoor_MSIL_SUNBURST_1
{
    meta:
        author = "FireEye"
        description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $cmd_regex_encoded = "U4qpjjbQtUzUTdONrTY2q42pVapRgooABYxQuIZmtUoA" wide
        $cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
        $fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
        $fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
        $fake_orion_eventmanager_encoded = "U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==" wide
        $fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
        $fake_orion_message_encoded = "U/JNLS5OTE9VslKqNqhVAgA=" wide
        $fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
        $fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }
    condition:
        $fnv_xor and ($cmd_regex_encoded or $cmd_regex_plain) or ( ($fake_orion_event_encoded or $fake_orion_event_plain) and ($fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain) and ($fake_orion_message_encoded and $fake_orion_message_plain) )
}

rule APT_Backdoor_MSIL_SUNBURST_2
{
    meta:
        author = "FireEye"
        description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $a = "0y3Kzy8BAA==" wide
        $aa = "S8vPKynWL89PS9OvNqjVrTYEYqNa3fLUpDSgTLVxrR5IzggA" wide
        $ab = "S8vPKynWL89PS9OvNqjVrTYEYqPaauNaPZCYEQA=" wide
        $ac = "C88sSs1JLS4GAA==" wide
        $ad = "C/UEAA==" wide
        $ae = "C89MSU8tKQYA" wide
        $af = "8wvwBQA=" wide
        $ag = "cyzIz8nJBwA=" wide
        $ah = "c87JL03xzc/LLMkvysxLBwA=" wide
        $ai = "88tPSS0GAA==" wide
        $aj = "C8vPKc1NLQYA" wide
        $ak = "88wrSS1KS0xOLQYA" wide
        $al = "c87PLcjPS80rKQYA" wide
        $am = "Ky7PLNAvLUjRBwA=" wide
        $an = "06vIzQEA" wide
        $b = "0y3NyyxLLSpOzIlPTgQA" wide
        $c = "001OBAA=" wide
        $d = "0y0oysxNLKqMT04EAA==" wide
        $e = "0y3JzE0tLknMLQAA" wide
        $f = "003PyU9KzAEA" wide
        $h = "0y1OTS4tSk1OBAA=" wide
        $i = "K8jO1E8uytGvNqitNqytNqrVA/IA" wide
        $j = "c8rPSQEA" wide
        $k = "c8rPSfEsSczJTAYA" wide
        $l = "c60oKUp0ys9JAQA=" wide
        $m = "c60oKUp0ys9J8SxJzMlMBgA=" wide
        $n = "8yxJzMlMBgA=" wide
        $o = "88lMzygBAA==" wide
        $p = "88lMzyjxLEnMyUwGAA==" wide
        $q = "C0pNL81JLAIA" wide
        $r = "C07NzXTKz0kBAA==" wide
        $s = "C07NzXTKz0nxLEnMyUwGAA==" wide
        $t = "yy9IzStOzCsGAA==" wide
        $u = "y8svyQcA" wide
        $v = "SytKTU3LzysBAA==" wide
        $w = "C84vLUpOdc5PSQ0oygcA" wide
        $x = "C84vLUpODU4tykwLKMoHAA==" wide
        $y = "C84vLUpO9UjMC07MKwYA" wide
        $z = "C84vLUpO9UjMC04tykwDAA==" wide
    condition:
        ($a and $b and $c and $d and $e and $f and $h and $i) or ($j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ($aa or $ab)) or ($t and $u and $v and $w and $x and $y and $z and ($aa or $ab)) or ($ac and $ad and $ae and $af and $ag and $ah and ($am or $an)) or ($ai and $aj and $ak and $al and ($am or $an))
}

rule APT_Backdoor_MSIL_SUNBURST_3
{
    meta:
        author = "FireEye"
        description = "This rule is looking for certain portions of the SUNBURST backdoor that deal with C2 communications. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $sb1 = { 05 14 51 1? 0A 04 28 [2] 00 06 0? [0-16] 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F [1-32] 03 0? 05 28 [2] 00 06 0? [0-32] 03 [0-16] 59 45 06 }
        $sb2 = { FE 16 [2] 00 01 6F [2] 00 0A 1? 8D [2] 00 01 [0-32] 1? 1? 7B 9? [0-16] 1? 1? 7D 9? [0-16] 6F [2] 00 0A 28 [2] 00 0A 28 [2] 00 0A [0-32] 02 7B [2] 00 04 1? 6F [2] 00 0A [2-32] 02 7B [2] 00 04 20 [4] 6F [2] 00 0A [0-32] 13 ?? 11 ?? 11 ?? 6E 58 13 ?? 11 ?? 11 ?? 9? 1? [0-32] 60 13 ?? 0? 11 ?? 28 [4] 11 ?? 11 ?? 9? 28 [4] 28 [4-32] 9? 58 [0-32] 6? 5F 13 ?? 02 7B [2] 00 04 1? ?? 1? ?? 6F [2] 00 0A 8D [2] 00 01 }
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Backdoor_MSIL_SUNBURST_4
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific methods used by the SUNBURST backdoor. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
        $ss5 = "\x00ExecuteEngine\x00"
        $ss6 = "\x00ParseServiceResponse\x00"
        $ss7 = "\x00RunTask\x00"
        $ss8 = "\x00CreateUploadRequest\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

import "pe"

rule APT_Webshell_SUPERNOVA_1
{
    meta:
        author = "FireEye"
        description = "SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args). This rule is looking for specific strings and attributes related to SUPERNOVA."
    strings:
        $compile1 = "CompileAssemblyFromSource"
        $compile2 = "CreateCompiler"
        $context = "ProcessRequest"
        $httpmodule = "IHttpHandler" ascii
        $string1 = "clazz"
        $string2 = "//NetPerfMon//images//NoLogo.gif" wide
        $string3 = "SolarWinds" ascii nocase wide
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and pe.imports("mscoree.dll","_CorDllMain") and $httpmodule and $context and all of ($compile*) and all of ($string*)
}
rule APT_Webshell_SUPERNOVA_2
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
    strings:
        $dynamic = "DynamicRun"
        $solar = "Solarwinds" nocase
        $string1 = "codes"
        $string2 = "clazz"
        $string3 = "method"
        $string4 = "args"
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and 3 of ($string*) and $dynamic and $solar
}

// https://labs.sentinelone.com/solarwinds-understanding-detecting-the-supernova-webshell-trojan/
rule SentinelLabs_SUPERNOVA
{
	meta:
		description = "Identifies potential versions of App_Web_logoimagehandler.ashx.b6031896.dll weaponized with SUPERNOVA"
		date = "2020-12-22"
		author = "SentinelLabs"
	strings:

		$ = "clazz"
		$ = "codes"
		$ = "args"
		$ = "ProcessRequest"
		$ = "DynamicRun"
		$ = "get_IsReusable"
		$ = "logoimagehandler.ashx" wide
		$ = "SiteNoclogoImage" wide
		$ = "SitelogoImage" wide

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and pe.imports("mscoree.dll")) and all of them

}

rule RaindropPacker
{
    meta:
        description = "Identifies the custom Cobalt Strike loader, Raindrop, used by Solarigate attackers"
		date = "2020-01-18"
        copyright = "Symantec"
        family = "Raindrop"

    strings:
        $code = {
            41 8B 4F 20                         //      mov     ecx, [r15+20h]
            49 8D 77 24                         //      lea     rsi, [r15+24h]
            89 8D ?? ?? 00 00                   //      mov     dword ptr [rbp+0A0h+arg_0], ecx
            E8 ?? ?? ?? ??                      //      call    sub_180010270
            33 D2                               //      xor     edx, edx
            48 8D 4C 24 ??                      //      lea     rcx, [rsp+1A0h+var_160]
            44 8D 42 10                         //      lea     r8d, [rdx+10h]
            E8 ?? ?? ?? ??                      //      call    sub_180038610
            48 8D 5C 24 ??                      //      lea     rbx, [rsp+1A0h+var_150]
            F7 DB                               //      neg     ebx
            48 8D 7C 24 ??                      //      lea     rdi, [rsp+1A0h+var_150]
            48 C1 EB 02                         //      shr     rbx, 2
            48 8D 54 24 ??                      //      lea     rdx, [rsp+1A0h+var_160]
            83 E3 03                            //      and     ebx, 3
            48 8D 3C 9F                         //      lea     rdi, [rdi+rbx*4]
            48 8B CF                            //      mov     rcx, rdi
            E8 ?? ?? ?? ??                      //      call    sub_1800101D0
            48 8D 4C 24 ??                      //      lea     rcx, [rsp+1A0h+var_140]
            49 8B D7                            //      mov     rdx, r15
            48 8D 0C 99                         //      lea     rcx, [rcx+rbx*4]
            BB 20 00 00 00                      //      mov     ebx, 20h
            44 8B C3                            //      mov     r8d, ebx
            E8 ?? ?? ?? ??                      //      call    sub_180010ED0
            44 8B 85 ?? ?? 00 00                //      mov     r8d, dword ptr [rbp+0A0h+arg_0]
            48 8B D6                            //      mov     rdx, rsi        ; _QWORD
            49 C1 E8 04                         //      shr     r8, 4           ; _QWORD
            48 8B CF                            //      mov     rcx, rdi        ; _QWORD
            FF 15 ?? ?? ?? ??                   //      call    cs:qword_180056E90
            8B 95 ?? ?? 00 00                   //      mov     edx, dword ptr [rbp+0A0h+arg_0]
            4C 8D 85 ?? ?? 00 00                //      lea     r8, [rbp+0A0h+dwSize]
            48 83 A5 ?? ?? 00 00 00             //      and     [rbp+0A0h+dwSize], 0
            48 8B CE                            //      mov     rcx, rsi
            E8 ?? ?? ?? ??                      //      call    sub_180009630
            48 8B 95 ?? ?? 00 00                //      mov     rdx, [rbp+0A0h+dwSize] ; dwSize
            44 8B CB                            //      mov     r9d, ebx        ; flProtect
            41 B8 00 10 00 00                   //      mov     r8d, 1000h      ; flAllocationType
            33 C9                               //      xor     ecx, ecx        ; lpAddress
            FF 15 ?? ?? ?? ??                   //      call    cs:VirtualAlloc
            48 8B 95 ?? ?? 00 00                //      mov     rdx, [rbp+0A0h+dwSize] ; dwSize
            4C 8D 8D ?? ?? 00 00                //      lea     r9, [rbp+0A0h+flOldProtect] ; lpflOldProtect
            48 8B C8                            //      mov     rcx, rax        ; lpAddress
            41 B8 04 00 00 00                   //      mov     r8d, 4          ; flNewProtect
            48 8B D8                            //      mov     rbx, rax
            FF 15 ?? ?? ?? ??                   //      call    cs:VirtualProtect
            4C 8D 8D ?? ?? 00 00                //      lea     r9, [rbp+0A0h+arg_0]
            4C 8B C6                            //      mov     r8, rsi
            48 8D 95 ?? ?? 00 00                //      lea     rdx, [rbp+0A0h+dwSize]
            48 8B CB                            //      mov     rcx, rbx
            E8 ?? ?? ?? ??                      //      call    sub_1800095A0
            4D 8B C6                            //      mov     r8, r14
            33 D2                               //      xor     edx, edx
            49 8B CF                            //      mov     rcx, r15
            E8 ?? ?? ?? ??                      //      call    sub_180038610
            33 D2                               //      xor     edx, edx        ; dwSize
            41 B8 00 80 00 00                   //      mov     r8d, 8000h      ; dwFreeType
            49 8B CF                            //      mov     rcx, r15        ; lpAddress
            FF 15 ?? ?? ?? ??                   //      call    cs:VirtualFree
            48 8B 95 ?? ?? 00 00                //      mov     rdx, [rbp+0A0h+dwSize]
            48 85 D2                            //      test    rdx, rdx
            74 1B                               //      jz      short l_1
            48 8B CB                            //      mov     rcx, rbx
            80 31 ??                            // l_0: xor     byte ptr [rcx], 39h
            48 FF C1                            //      inc     rcx
            48 8B 95 ?? ?? 00 00                //      mov     rdx, [rbp+0A0h+dwSize] ; dwSize
            48 8B C1                            //      mov     rax, rcx
            48 2B C3                            //      sub     rax, rbx
            48 3B C2                            //      cmp     rax, rdx
            72 E8                               //      jb      short l_0
            44 8B 85 ?? ?? 00 00                // l_1: mov     r8d, [rbp+0A0h+flOldProtect] ; flNewProtect
            4C 8D 8D ?? ?? 00 00                //      lea     r9, [rbp+0A0h+flOldProtect] ; lpflOldProtect
            48 8B CB                            //      mov     rcx, rbx        ; lpAddress
            FF 15 ?? ?? ?? ??                   //      call    cs:VirtualProtect
            FF D3                               //      call    rbx
        }

    condition:
        all of them
}
]=]

-- #region memory_rules
memory_rules = [=[
// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/sunburst_countermeasures/blob/main/LICENSE.txt

rule APT_Dropper_Raw64_TEARDROP_1
{
    meta:
        author = "FireEye"
        description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
        $sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
        $sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }
    condition:
        all of them
}

rule APT_Dropper_Win64_TEARDROP_2
{
    meta:
        author = "FireEye"
        description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
        $loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
        $loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
        $loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
        $loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
]=]
-- #endregion

--[=[ SECTION 2: Functions ]=]

function is_executable(path)
    --[=[
        Check if a file is an executable (PE or ELF) by magic number. 
        Input:  [string]path
        Output: [bool] Is Executable
    ]=] 
    magicnumbers = {
        "MZ",
        ".ELF"
    }
    local f,msg = io.open(path, "rb")
    if not f then
        --hunt.debug(msg)
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

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
end

  
function get_fileextension(path)
    match = path:match("^.+(%..+)$")
    return match
end

function string_to_list(str)
    -- Converts a comma seperated list to a lua list object
    list = {}
    for s in string.gmatch(str, '([^,]+)') do
        table.insert(list, s)
    end
    return list
end


function yara_scan_memory(signatures)
    --[=[
        Scans all processes memory with yara signatures and returns list of matched processes 
        Will also make a log entry with each match. 
        Input:  [string]signatures
        Output: [bool]match
                [table]matches { pid, path, owner, signature }
    ]=]

    -- input validation
    if type(signatures) ~= "string" then
        hunt.error(f"[yara_scan] Invalid format for inputs to function. [string]signatures=${type(signatures)}")
        return
    end
    str = string.gsub(signatures, '[ \t]+%f[\r\n%z]', '') -- strip whitespace
    if not str or str == '' then
        hunt.warn("No signatures provided for memory")
        return nil, {}
    end
        
    yara_memory = hunt.yara.new()
    yara_memory:add_rule(signatures)

    procs = {}
    matches = {}
    -- Scan process memory with Yara signatures
    for _, proc in pairs(hunt.process.list()) do
        procname = string.match(proc:path(), "^.+[\\/](.+)$")
        procpid = proc:pid()

        hunt.debug(f"Scanning process memory for name=${procname} (pid=${procpid})")
        for _, signature in pairs(yara_memory:scan_process(proc:pid())) do
            hunt.verbose(f"Matched yara rule [BAD]${signature} within MEMORY of ${procname} [${procpid}]")
            m = {}
            m["owner"] = proc:owner()
            m["path"] = proc:path()
            m["pid"] = proc:pid()
            m["procname"] = procname
            m["signature"] = signature
            table.insert(matches, m)
        end
    end
    return #matches > 0, matches
end

function yara_scan(paths, signatures) 
    --[=[
        Scans list of files with yara signatures and returns list of matched file paths 
        Will also make a log entry with each match. 
        Input:  [table]paths
                [string]signatures
        Output: [bool]match
                [table]matches { sha1, path, signature }
    ]=]

    -- Input validation
    if type(paths) ~= "table" or type(signatures) ~= "string" then
        hunt.error(f"[yara_scan] Invalid format for inputs to function. [table]paths=${type(paths)}, [string]signatures=${type(signatures)}")
    end 
    str = string.gsub(signatures, '[ \t]+%f[\r\n%z]', '') -- strip whitespace
    if not str or str == '' then
        hunt.warn("No signatures provided")
        return nil, {}
    end
    
    unique_paths = {} -- add to keys of list to easily unique paths
    matches = {}
    print(#matches)
    -- Load Yara rules
    yara = hunt.yara.new()
    yara:add_rule(signatures)

    -- Scan all paths with Yara signatures
    n=1
    for i, path in pairs(paths) do
        -- dedup paths
        if unique_paths[path] then
            goto continue
        end
        if verbose then hunt.log(f"[${n}] Scanning ${path} with ${levels[level]} signatures") end
        for _, signature in pairs(yara:scan(path)) do
            if not hash then
                hash = hunt.hash.sha1(path)
            end
            hunt.verbose(f"Matched yara rule [${levels[level]}]${signature} on: ${path} <${hash}>")
            m = {}
            m["path"] = path
            m["sha1"] = hash
            m["signature"] = signature
            table.insert(matches, m)
        end
        unique_paths[path] = true
        n=n+1
        hash = nil
        if test and n > 3 then
            return #matches > 0, matches
        end
        ::continue::
    end
    return #matches > 0, matches
end


--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

paths = {}

opts = {
    "files",
    f"size<=${max_size}kb", -- any file below this size
}

-- Add active processes
if scan_activeprocesses then
    hunt.log("Scanning active processes with yara")
    procs = hunt.process.list()
    for i, proc in pairs(procs) do
        file = hunt.fs.ls(proc:path(), opts)
        if #file == 1 and file[1]:size() < max_size * 1000 then
           table.insert(paths, proc:path())
        end
    end
end

if scan_userfolders then
    hunt.log("Scanning scripts and executables within user folders with yara")
    -- Add user paths
    appdata_opts = {
        "files",
        f"size<${max_size}kb", -- any file below this size
        "recurse=3" -- depth of 1
    }
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        for _, path in pairs(hunt.fs.ls(userfolder:path(), appdata_opts)) do
            if get_fileextension(path:path()) == "ps1" or is_executable(path:path()) then
                table.insert(paths, path:path())
            end
        end
    end
end

-- Add primary paths
if primary_paths then
    hunt.log("Scanning reported indicator of compromise paths with yara")
    if type(primary_paths) == "table" then
        more_paths = primary_paths
    else
        more_paths = string_to_list(primary_paths)
    end

    for i, path in pairs(more_paths) do
        files = hunt.fs.ls(path, opts)
        for _,path2 in pairs(files) do
            table.insert(paths, path2:path())
        end
    end
end

-- Add additional paths
if additional_paths then
    hunt.log("Scanning additional user provided paths with yara")
    if type(additional_paths) == "table" then
        more_paths = additional_paths
    else
        more_paths = string_to_list(additional_paths)
    end

    for i, path in pairs(more_paths) do
        files = hunt.fs.ls(path, opts)
        for _,path2 in pairs(files) do
            if get_fileextension(path2:path()) == "ps1" or is_executable(path2:path()) then
                table.insert(paths, path2:path())
            end
        end
    end
end


-- Scan
level = 0 -- threat level (0 is not defined)
all_matches = {}
levels = {}
levels[1] = "BAD"
levels[2] = "SUSPICIOUS"
levels[3] = "INFO"

hunt.log(f"Scanning ${#paths} paths with file rules")
match, matches = yara_scan(paths, rules) 
if match then
    hunt.log("Found matches!")
    level = 1
    all_matches = table.concat(all_matches,matches)
    for _, m in pairs(matches) do
        hunt.log(f"Matched yara rule [${levels[level]}]${m['signature']} on: ${m['path']} <${m['hash']}>")
    end
else
    hunt.log("No matches found with file rules!")
end

-- Scan process memory with Yara signatures
-- Memory scanning only in latest version. Uncomment if you have Infocyte version .3527 or greater
hunt.log(f"Scanning process memory with memory_rules")
match, procs = yara_scan_memory(memory_rules)
if match then
    hunt.log(f"Found in-memory matches within ${#procs} processes")
    level = 1
    for _, m in pairs(procs) do
        hunt.log(f"Matched yara rule [${levels[level]}]${m['signature']} in process memory of ${m['procname']}-${m['pid']} owned by ${m['owner']}")
    end
elseif match == false then
    hunt.log(f"No matches found within memory")
end


-- Add bad and suspicious files to Artifacts list for analysis
n = 0
for path,i in pairs(all_matches) do
    if test and n > 3 then
        break
    end
    -- Create a new artifact
    artifact = hunt.survey.artifact()
    artifact:exe(path)
    artifact:type("Yara Match")
    hunt.survey.add(artifact)
    n = n + 1
end


-- Look for DLL
for _, dll in pairs(dllnames) do
    name = dll
    hunt.log(f"Searching for loaded DLL: ${name}")
    psscript = f"$r = Get-Process -Module -ea 0 | where { $_.ModuleName -eq '${name}'};"
    psscript = psscript..[=[
    if ($r) {
        $a = $r | select -First 1 | select FileVersionInfo | fl | Out-String; 
        return $a.trim()
    } else { return 'Not Found'}
    ]=]
    out, err = hunt.env.run_powershell(psscript)
    if out and out == 'Not Found' then 
        hunt.log(f"${name} not found")
    elseif out and out ~= 'Not Found' then
        hunt.log(f"${name} FOUND!\n${out}")
        if level ~= 1 then 
            level = 2
        end
    elseif err then 
        hunt.error(err)
        return
    end
end

-- Set threat status
if level == 1 then
    result = "Bad"
    hunt.status.bad()
elseif level == 2 then
    result = "Suspicious"
    hunt.status.suspicious()
elseif level == 3 then
    result = "Low Risk"
    hunt.status.low_risk()
else
    result = "Good"
    hunt.status.good()
end

hunt.log(f"Yara scan completed. Result=${result}. Found ${#procs} processes with memory matches. Added ${n} paths (all bad and suspicious matches) to Artifacts for processing and retrieval.")
