--[[
    Infocyte Extension
    Name: Yara Scanner
    Type: Collection
    Description: Example script showing how to use YARA
    Author: Infocyte
    Created: 20191018
    Updated: 20191018 (Gerritz)
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


-- #region suspicious_rules
suspicious_rules = [==[
/*
    These rules are part of Manalyze which is under them
    GNU General Public License. See <http://www.gnu.org/licenses/>.
*/

rule System_Tools
{
    meta:
        description = "Contains references to system / monitoring tools"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "wireshark.exe" nocase wide ascii
        $a1 = "ethereal.exe" nocase wide ascii
        $a2 = "netstat.exe" nocase wide ascii
        $a3 = /taskm(an|gr|on).exe/ nocase wide ascii
        $a4 = /regedit(32)?.exe/ nocase wide ascii
        $a5 = "sc.exe" nocase wide ascii
        $a6 = "procexp.exe" nocase wide ascii
        $a7 = "procmon.exe" nocase wide ascii
        $a8 = "netmon.exe" nocase wide ascii
        $a9 = "regmon.exe" nocase wide ascii
        $a10 = "filemon.exe" nocase wide ascii
        $a11 = "msconfig.exe" nocase wide ascii
        $a12 = "vssadmin.exe" nocase wide ascii
        $a13 = "bcdedit.exe" nocase wide ascii
        $a14 = "dumpcap.exe" nocase wide ascii
        $a15 = "tcpdump.exe" nocase wide ascii
		$a16 = "mshta.exe" nocase wide ascii    // Used by DUBNIUM to download files
        $a17 = "control.exe" nocase wide ascii  // Used by EquationGroup to launch DLLs
        $a18 = "regsvr32.exe" nocase wide ascii
        $a19 = "rundll32.exe" nocase wide ascii

    condition:
        any of them
}

rule Browsers
{
    meta:
        description = "Contains references to internet browsers"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $ie = "iexplore.exe" nocase wide ascii
        $ff = "firefox.exe" nocase wide ascii
        $ff_key = "key3.db"
        $ff_log = "signons.sqlite"
        $chrome = "chrome.exe" nocase wide ascii
        // TODO: Add user-agent strings
    condition:
        any of them
}

rule RE_Tools
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

rule Antivirus
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

rule VM_Generic_Detection : AntiVM
{
    meta:
        description = "Tries to detect virtualized environments"
    strings:
        $a0 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $a1 = "HARDWARE\\Description\\System" nocase wide ascii
        $a2 = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" nocase wide ascii
        $a3 = "SYSTEM\\CurrentControlSet\\Enum\\IDE" nocase wide ascii
        $redpill = { 0F 01 0D 00 00 00 00 C3 } // Copied from the Cuckoo project

        // CLSIDs used to detect if speakers are present. Hoping this will not cause false positives.
        $teslacrypt1 = { D1 29 06 E3 E5 27 CE 11 87 5D 00 60 8C B7 80 66 } // CLSID_AudioRender
        $teslacrypt2 = { B3 EB 36 E4 4F 52 CE 11 9F 53 00 20 AF 0B A7 70 } // CLSID_FilterGraph

    condition:
        any of ($a*) or $redpill or all of ($teslacrypt*)
}

rule VMWare_Detection : AntiVM
{
    meta:
        description = "Looks for VMWare presence"
        author = "Cuckoo project"

    strings:
        $a0 = "VMXh"
        $a1 = "vmware" nocase wide ascii
        $vmware4 = "hgfs.sys" nocase wide ascii
        $vmware5 = "mhgfs.sys" nocase wide ascii
        $vmware6 = "prleth.sys" nocase wide ascii
        $vmware7 = "prlfs.sys" nocase wide ascii
        $vmware8 = "prlmouse.sys" nocase wide ascii
        $vmware9 = "prlvideo.sys" nocase wide ascii
        $vmware10 = "prl_pv32.sys" nocase wide ascii
        $vmware11 = "vpc-s3.sys" nocase wide ascii
        $vmware12 = "vmsrvc.sys" nocase wide ascii
        $vmware13 = "vmx86.sys" nocase wide ascii
        $vmware14 = "vmnet.sys" nocase wide ascii
        $vmware15 = "vmicheartbeat" nocase wide ascii
        $vmware16 = "vmicvss" nocase wide ascii
        $vmware17 = "vmicshutdown" nocase wide ascii
        $vmware18 = "vmicexchange" nocase wide ascii
        $vmware19 = "vmdebug" nocase wide ascii
        $vmware20 = "vmmouse" nocase wide ascii
        $vmware21 = "vmtools" nocase wide ascii
        $vmware22 = "VMMEMCTL" nocase wide ascii
        $vmware23 = "vmx86" nocase wide ascii

        // VMware MAC addresses
        $vmware_mac_1a = "00-05-69" wide ascii
        $vmware_mac_1b = "00:05:69" wide ascii
        $vmware_mac_1c = "000569" wide ascii
        $vmware_mac_2a = "00-50-56" wide ascii
        $vmware_mac_2b = "00:50:56" wide ascii
        $vmware_mac_2c = "005056" wide ascii
        $vmware_mac_3a = "00-0C-29" nocase wide ascii
        $vmware_mac_3b = "00:0C:29" nocase wide ascii
        $vmware_mac_3c = "000C29" nocase wide ascii
        $vmware_mac_4a = "00-1C-14" nocase wide ascii
        $vmware_mac_4b = "00:1C:14" nocase wide ascii
        $vmware_mac_4c = "001C14" nocase wide ascii

        // PCI Vendor IDs, from Hacking Team's leak
        $virtualbox_vid_1 = "VEN_15ad" nocase wide ascii

    condition:
        any of them
}

rule Sandboxie_Detection : AntiVM
{
    meta:
        description = "Looks for Sandboxie presence"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $sbie = "SbieDll.dll" nocase wide ascii
        $buster = /LOG_API(_VERBOSE)?.DLL/ nocase wide ascii
        $sbie_process_1 = "SbieSvc.exe" nocase wide ascii
        $sbie_process_2 = "SbieCtrl.exe" nocase wide ascii
        $sbie_process_3 = "SandboxieRpcSs.exe" nocase wide ascii
        $sbie_process_4 = "SandboxieDcomLaunch.exe" nocase wide ascii
        $sbie_process_5 = "SandboxieCrypto.exe" nocase wide ascii
        $sbie_process_6 = "SandboxieBITS.exe" nocase wide ascii
        $sbie_process_7 = "SandboxieWUAU.exe" nocase wide ascii

    condition:
        any of them
}

rule VirtualPC_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualPC presence"
        author = "Cuckoo project"

    strings:
        $a0 = {0F 3F 07 0B }
        $virtualpc1 = "vpcbus" nocase wide ascii
        $virtualpc2 = "vpc-s3" nocase wide ascii
        $virtualpc3 = "vpcuhub" nocase wide ascii
        $virtualpc4 = "msvmmouf" nocase wide ascii

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

rule Parallels_Detection : AntiVM
{
    meta:
        description = "Looks for Parallels presence"
    strings:
        $a0 = "magi"
        $a1 = "c!nu"
        $a2 = "mber"

        // PCI Vendor IDs, from Hacking Team's leak
        $parallels_vid_1 = "VEN_80EE" nocase wide ascii
    condition:
        all of them
}

rule Qemu_Detection : AntiVM
{
    meta:
        description = "Looks for Qemu presence"
    strings:
        $a0 = "qemu" nocase wide ascii
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

rule AutoIT_compiled_script
{
    meta:
        description = "Is an AutoIT compiled script"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "AutoIt Error" ascii wide
        $a1 = "reserved for AutoIt internal use" ascii wide
    condition:
        any of them
}

rule WMI_strings
{
    meta:
        description = "Accesses the WMI"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        // WMI namespaces which may be referenced in the ConnectServer call. All in the form of "ROOT\something"
        $a0 = /ROOT\\(CIMV2|AccessLogging|ADFS|aspnet|Cli|Hardware|interop|InventoryLogging|Microsoft.{10}|Policy|RSOP|SECURITY|ServiceModel|snmpStandardCimv2|subscription|virtualization|WebAdministration|WMI)/ nocase ascii wide
    condition:
        any of them
}

rule Obfuscated_Strings
{
	meta:
		description = "Contains obfuscated function names"
		author = "Ivan Kwiatkowski (@JusticeRage)"
	strings:
		$a0 = { (46 | 66) 64 75 (51 | 71) 73 6E 62 (40 | 60) 65 65 73 64 72 72 } // [Gg]et[Pp]roc[Aa]ddress XOR 0x01
		$a1 = { (45 | 65) 67 76 (52 | 72) 70 6D 61 (43 | 63) 66 66 70 67 71 71 } // GetProcAddress XOR 0x02
		$a2 = { (44 | 64) 66 77 (53 | 73) 71 6C 60 (42 | 62) 67 67 71 66 70 70 } // etc...
		$a3 = { (43 | 63) 61 70 (54 | 74) 76 6B 67 (45 | 65) 60 60 76 61 77 77 }
		$a4 = { (42 | 62) 60 71 (55 | 75) 77 6A 66 (44 | 64) 61 61 77 60 76 76 }
		$a5 = { (41 | 61) 63 72 (56 | 76) 74 69 65 (47 | 67) 62 62 74 63 75 75 }
		$a6 = { (40 | 60) 62 73 (57 | 77) 75 68 64 (46 | 66) 63 63 75 62 74 74 }
		$a7 = { (4F | 6F) 6D 7C (58 | 78) 7A 67 6B (49 | 69) 6C 6C 7A 6D 7B 7B }
		$a8 = { (4E | 6E) 6C 7D (59 | 79) 7B 66 6A (48 | 68) 6D 6D 7B 6C 7A 7A }
		$a9 = { (4D | 6D) 6F 7E (5A | 7A) 78 65 69 (4B | 6B) 6E 6E 78 6F 79 79 }
		$a10 = { (4C | 6C) 6E 7F (5B | 7B) 79 64 68 (4A | 6A) 6F 6F 79 6E 78 78 }
		$a11 = { (4B | 6B) 69 78 (5C | 7C) 7E 63 6F (4D | 6D) 68 68 7E 69 7F 7F }
		$a12 = { (4A | 6A) 68 79 (5D | 7D) 7F 62 6E (4C | 6C) 69 69 7F 68 7E 7E }
		$a13 = { (49 | 69) 6B 7A (5E | 7E) 7C 61 6D (4F | 6F) 6A 6A 7C 6B 7D 7D }
		$a14 = { (48 | 68) 6A 7B (5F | 7F) 7D 60 6C (4E | 6E) 6B 6B 7D 6A 7C 7C }
		$a15 = { (57 | 77) 75 64 (40 | 60) 62 7F 73 (51 | 71) 74 74 62 75 63 63 }
		$a16 = { (56 | 76) 74 65 (41 | 61) 63 7E 72 (50 | 70) 75 75 63 74 62 62 }
		$a17 = { (55 | 75) 77 66 (42 | 62) 60 7D 71 (53 | 73) 76 76 60 77 61 61 }
		$a18 = { (54 | 74) 76 67 (43 | 63) 61 7C 70 (52 | 72) 77 77 61 76 60 60 }
		$a19 = { (53 | 73) 71 60 (44 | 64) 66 7B 77 (55 | 75) 70 70 66 71 67 67 }
		$a20 = { (52 | 72) 70 61 (45 | 65) 67 7A 76 (54 | 74) 71 71 67 70 66 66 }
		$a21 = { (51 | 71) 73 62 (46 | 66) 64 79 75 (57 | 77) 72 72 64 73 65 65 }
		$a22 = { (50 | 70) 72 63 (47 | 67) 65 78 74 (56 | 76) 73 73 65 72 64 64 }
		$a23 = { (5F | 7F) 7D 6C (48 | 68) 6A 77 7B (59 | 79) 7C 7C 6A 7D 6B 6B }
		$a24 = { (5E | 7E) 7C 6D (49 | 69) 6B 76 7A (58 | 78) 7D 7D 6B 7C 6A 6A }
		$a25 = { (5D | 7D) 7F 6E (4A | 6A) 68 75 79 (5B | 7B) 7E 7E 68 7F 69 69 }
		$a26 = { (5C | 7C) 7E 6F (4B | 6B) 69 74 78 (5A | 7A) 7F 7F 69 7E 68 68 }
		$a27 = { (5B | 7B) 79 68 (4C | 6C) 6E 73 7F (5D | 7D) 78 78 6E 79 6F 6F }
		$a28 = { (5A | 7A) 78 69 (4D | 6D) 6F 72 7E (5C | 7C) 79 79 6F 78 6E 6E }
		$a29 = { (59 | 79) 7B 6A (4E | 6E) 6C 71 7D (5F | 7F) 7A 7A 6C 7B 6D 6D }
		$a30 = { (58 | 78) 7A 6B (4F | 6F) 6D 70 7C (5E | 7E) 7B 7B 6D 7A 6C 6C }
		// XOR 0x20 removed because it toggles capitalization and causes [Gg]ET[Pp]ROC[Aa]DDRESS to match.
		$a32 = { (66 | 46) 44 55 (71 | 51) 53 4E 42 (60 | 40) 45 45 53 44 52 52 }
		$a33 = { (65 | 45) 47 56 (72 | 52) 50 4D 41 (63 | 43) 46 46 50 47 51 51 }
		$a34 = { (64 | 44) 46 57 (73 | 53) 51 4C 40 (62 | 42) 47 47 51 46 50 50 }
		$a35 = { (63 | 43) 41 50 (74 | 54) 56 4B 47 (65 | 45) 40 40 56 41 57 57 }
		$a36 = { (62 | 42) 40 51 (75 | 55) 57 4A 46 (64 | 44) 41 41 57 40 56 56 }
		$a37 = { (61 | 41) 43 52 (76 | 56) 54 49 45 (67 | 47) 42 42 54 43 55 55 }
		$a38 = { (60 | 40) 42 53 (77 | 57) 55 48 44 (66 | 46) 43 43 55 42 54 54 }
		$a39 = { (6F | 4F) 4D 5C (78 | 58) 5A 47 4B (69 | 49) 4C 4C 5A 4D 5B 5B }
		$a40 = { (6E | 4E) 4C 5D (79 | 59) 5B 46 4A (68 | 48) 4D 4D 5B 4C 5A 5A }
		$a41 = { (6D | 4D) 4F 5E (7A | 5A) 58 45 49 (6B | 4B) 4E 4E 58 4F 59 59 }
		$a42 = { (6C | 4C) 4E 5F (7B | 5B) 59 44 48 (6A | 4A) 4F 4F 59 4E 58 58 }
		$a43 = { (6B | 4B) 49 58 (7C | 5C) 5E 43 4F (6D | 4D) 48 48 5E 49 5F 5F }
		$a44 = { (6A | 4A) 48 59 (7D | 5D) 5F 42 4E (6C | 4C) 49 49 5F 48 5E 5E }
		$a45 = { (69 | 49) 4B 5A (7E | 5E) 5C 41 4D (6F | 4F) 4A 4A 5C 4B 5D 5D }
		$a46 = { (68 | 48) 4A 5B (7F | 5F) 5D 40 4C (6E | 4E) 4B 4B 5D 4A 5C 5C }
		$a47 = { (77 | 57) 55 44 (60 | 40) 42 5F 53 (71 | 51) 54 54 42 55 43 43 }
		$a48 = { (76 | 56) 54 45 (61 | 41) 43 5E 52 (70 | 50) 55 55 43 54 42 42 }
		$a49 = { (75 | 55) 57 46 (62 | 42) 40 5D 51 (73 | 53) 56 56 40 57 41 41 }
		$a50 = { (74 | 54) 56 47 (63 | 43) 41 5C 50 (72 | 52) 57 57 41 56 40 40 }
		$a51 = { (73 | 53) 51 40 (64 | 44) 46 5B 57 (75 | 55) 50 50 46 51 47 47 }
		$a52 = { (72 | 52) 50 41 (65 | 45) 47 5A 56 (74 | 54) 51 51 47 50 46 46 }
		$a53 = { (71 | 51) 53 42 (66 | 46) 44 59 55 (77 | 57) 52 52 44 53 45 45 }
		$a54 = { (70 | 50) 52 43 (67 | 47) 45 58 54 (76 | 56) 53 53 45 52 44 44 }
		$a55 = { (7F | 5F) 5D 4C (68 | 48) 4A 57 5B (79 | 59) 5C 5C 4A 5D 4B 4B }
		$a56 = { (7E | 5E) 5C 4D (69 | 49) 4B 56 5A (78 | 58) 5D 5D 4B 5C 4A 4A }
		$a57 = { (7D | 5D) 5F 4E (6A | 4A) 48 55 59 (7B | 5B) 5E 5E 48 5F 49 49 }
		$a58 = { (7C | 5C) 5E 4F (6B | 4B) 49 54 58 (7A | 5A) 5F 5F 49 5E 48 48 }
		$a59 = { (7B | 5B) 59 48 (6C | 4C) 4E 53 5F (7D | 5D) 58 58 4E 59 4F 4F }
		$a60 = { (7A | 5A) 58 49 (6D | 4D) 4F 52 5E (7C | 5C) 59 59 4F 58 4E 4E }
		$a61 = { (79 | 59) 5B 4A (6E | 4E) 4C 51 5D (7F | 5F) 5A 5A 4C 5B 4D 4D }
		$a62 = { (78 | 58) 5A 4B (6F | 4F) 4D 50 5C (7E | 5E) 5B 5B 4D 5A 4C 4C }
		$a63 = { (07 | 27) 25 34 (10 | 30) 32 2F 23 (01 | 21) 24 24 32 25 33 33 }
		$a64 = { (06 | 26) 24 35 (11 | 31) 33 2E 22 (00 | 20) 25 25 33 24 32 32 }
		$a65 = { (05 | 25) 27 36 (12 | 32) 30 2D 21 (03 | 23) 26 26 30 27 31 31 }
		$a66 = { (04 | 24) 26 37 (13 | 33) 31 2C 20 (02 | 22) 27 27 31 26 30 30 }
		$a67 = { (03 | 23) 21 30 (14 | 34) 36 2B 27 (05 | 25) 20 20 36 21 37 37 }
		$a68 = { (02 | 22) 20 31 (15 | 35) 37 2A 26 (04 | 24) 21 21 37 20 36 36 }
		$a69 = { (01 | 21) 23 32 (16 | 36) 34 29 25 (07 | 27) 22 22 34 23 35 35 }
		$a70 = { (00 | 20) 22 33 (17 | 37) 35 28 24 (06 | 26) 23 23 35 22 34 34 }
		$a71 = { (0F | 2F) 2D 3C (18 | 38) 3A 27 2B (09 | 29) 2C 2C 3A 2D 3B 3B }
		$a72 = { (0E | 2E) 2C 3D (19 | 39) 3B 26 2A (08 | 28) 2D 2D 3B 2C 3A 3A }
		$a73 = { (0D | 2D) 2F 3E (1A | 3A) 38 25 29 (0B | 2B) 2E 2E 38 2F 39 39 }
		$a74 = { (0C | 2C) 2E 3F (1B | 3B) 39 24 28 (0A | 2A) 2F 2F 39 2E 38 38 }
		$a75 = { (0B | 2B) 29 38 (1C | 3C) 3E 23 2F (0D | 2D) 28 28 3E 29 3F 3F }
		$a76 = { (0A | 2A) 28 39 (1D | 3D) 3F 22 2E (0C | 2C) 29 29 3F 28 3E 3E }
		$a77 = { (09 | 29) 2B 3A (1E | 3E) 3C 21 2D (0F | 2F) 2A 2A 3C 2B 3D 3D }
		$a78 = { (08 | 28) 2A 3B (1F | 3F) 3D 20 2C (0E | 2E) 2B 2B 3D 2A 3C 3C }
		$a79 = { (17 | 37) 35 24 (00 | 20) 22 3F 33 (11 | 31) 34 34 22 35 23 23 }
		$a80 = { (16 | 36) 34 25 (01 | 21) 23 3E 32 (10 | 30) 35 35 23 34 22 22 }
		$a81 = { (15 | 35) 37 26 (02 | 22) 20 3D 31 (13 | 33) 36 36 20 37 21 21 }
		$a82 = { (14 | 34) 36 27 (03 | 23) 21 3C 30 (12 | 32) 37 37 21 36 20 20 }
		$a83 = { (13 | 33) 31 20 (04 | 24) 26 3B 37 (15 | 35) 30 30 26 31 27 27 }
		$a84 = { (12 | 32) 30 21 (05 | 25) 27 3A 36 (14 | 34) 31 31 27 30 26 26 }
		$a85 = { (11 | 31) 33 22 (06 | 26) 24 39 35 (17 | 37) 32 32 24 33 25 25 }
		$a86 = { (10 | 30) 32 23 (07 | 27) 25 38 34 (16 | 36) 33 33 25 32 24 24 }
		$a87 = { (1F | 3F) 3D 2C (08 | 28) 2A 37 3B (19 | 39) 3C 3C 2A 3D 2B 2B }
		$a88 = { (1E | 3E) 3C 2D (09 | 29) 2B 36 3A (18 | 38) 3D 3D 2B 3C 2A 2A }
		$a89 = { (1D | 3D) 3F 2E (0A | 2A) 28 35 39 (1B | 3B) 3E 3E 28 3F 29 29 }
		$a90 = { (1C | 3C) 3E 2F (0B | 2B) 29 34 38 (1A | 3A) 3F 3F 29 3E 28 28 }
		$a91 = { (1B | 3B) 39 28 (0C | 2C) 2E 33 3F (1D | 3D) 38 38 2E 39 2F 2F }
		$a92 = { (1A | 3A) 38 29 (0D | 2D) 2F 32 3E (1C | 3C) 39 39 2F 38 2E 2E }
		$a93 = { (19 | 39) 3B 2A (0E | 2E) 2C 31 3D (1F | 3F) 3A 3A 2C 3B 2D 2D }
		$a94 = { (18 | 38) 3A 2B (0F | 2F) 2D 30 3C (1E | 3E) 3B 3B 2D 3A 2C 2C }
		$a95 = { (27 | 07) 05 14 (30 | 10) 12 0F 03 (21 | 01) 04 04 12 05 13 13 }
		$a96 = { (26 | 06) 04 15 (31 | 11) 13 0E 02 (20 | 00) 05 05 13 04 12 12 }
		$a97 = { (25 | 05) 07 16 (32 | 12) 10 0D 01 (23 | 03) 06 06 10 07 11 11 }
		$a98 = { (24 | 04) 06 17 (33 | 13) 11 0C 00 (22 | 02) 07 07 11 06 10 10 }
		$a99 = { (23 | 03) 01 10 (34 | 14) 16 0B 07 (25 | 05) 00 00 16 01 17 17 }
		$a100 = { (22 | 02) 00 11 (35 | 15) 17 0A 06 (24 | 04) 01 01 17 00 16 16 }
		$a101 = { (21 | 01) 03 12 (36 | 16) 14 09 05 (27 | 07) 02 02 14 03 15 15 }
		$a102 = { (20 | 00) 02 13 (37 | 17) 15 08 04 (26 | 06) 03 03 15 02 14 14 }
		$a103 = { (2F | 0F) 0D 1C (38 | 18) 1A 07 0B (29 | 09) 0C 0C 1A 0D 1B 1B }
		$a104 = { (2E | 0E) 0C 1D (39 | 19) 1B 06 0A (28 | 08) 0D 0D 1B 0C 1A 1A }
		$a105 = { (2D | 0D) 0F 1E (3A | 1A) 18 05 09 (2B | 0B) 0E 0E 18 0F 19 19 }
		$a106 = { (2C | 0C) 0E 1F (3B | 1B) 19 04 08 (2A | 0A) 0F 0F 19 0E 18 18 }
		$a107 = { (2B | 0B) 09 18 (3C | 1C) 1E 03 0F (2D | 0D) 08 08 1E 09 1F 1F }
		$a108 = { (2A | 0A) 08 19 (3D | 1D) 1F 02 0E (2C | 0C) 09 09 1F 08 1E 1E }
		$a109 = { (29 | 09) 0B 1A (3E | 1E) 1C 01 0D (2F | 0F) 0A 0A 1C 0B 1D 1D }
		$a110 = { (28 | 08) 0A 1B (3F | 1F) 1D 00 0C (2E | 0E) 0B 0B 1D 0A 1C 1C }
		$a111 = { (37 | 17) 15 04 (20 | 00) 02 1F 13 (31 | 11) 14 14 02 15 03 03 }
		$a112 = { (36 | 16) 14 05 (21 | 01) 03 1E 12 (30 | 10) 15 15 03 14 02 02 }
		$a113 = { (35 | 15) 17 06 (22 | 02) 00 1D 11 (33 | 13) 16 16 00 17 01 01 }
		$a114 = { (34 | 14) 16 07 (23 | 03) 01 1C 10 (32 | 12) 17 17 01 16 00 00 }
		$a115 = { (33 | 13) 11 00 (24 | 04) 06 1B 17 (35 | 15) 10 10 06 11 07 07 }
		$a116 = { (32 | 12) 10 01 (25 | 05) 07 1A 16 (34 | 14) 11 11 07 10 06 06 }
		$a117 = { (31 | 11) 13 02 (26 | 06) 04 19 15 (37 | 17) 12 12 04 13 05 05 }
		$a118 = { (30 | 10) 12 03 (27 | 07) 05 18 14 (36 | 16) 13 13 05 12 04 04 }
		$a119 = { (3F | 1F) 1D 0C (28 | 08) 0A 17 1B (39 | 19) 1C 1C 0A 1D 0B 0B }
		$a120 = { (3E | 1E) 1C 0D (29 | 09) 0B 16 1A (38 | 18) 1D 1D 0B 1C 0A 0A }
		$a121 = { (3D | 1D) 1F 0E (2A | 0A) 08 15 19 (3B | 1B) 1E 1E 08 1F 09 09 }
		$a122 = { (3C | 1C) 1E 0F (2B | 0B) 09 14 18 (3A | 1A) 1F 1F 09 1E 08 08 }
		$a123 = { (3B | 1B) 19 08 (2C | 0C) 0E 13 1F (3D | 1D) 18 18 0E 19 0F 0F }
		$a124 = { (3A | 1A) 18 09 (2D | 0D) 0F 12 1E (3C | 1C) 19 19 0F 18 0E 0E }
		$a125 = { (39 | 19) 1B 0A (2E | 0E) 0C 11 1D (3F | 1F) 1A 1A 0C 1B 0D 0D }
		$a126 = { (38 | 18) 1A 0B (2F | 0F) 0D 10 1C (3E | 1E) 1B 1B 0D 1A 0C 0C }
		$a127 = { (C7 | E7) E5 F4 (D0 | F0) F2 EF E3 (C1 | E1) E4 E4 F2 E5 F3 F3 }
		$a128 = { (C6 | E6) E4 F5 (D1 | F1) F3 EE E2 (C0 | E0) E5 E5 F3 E4 F2 F2 }
		$a129 = { (C5 | E5) E7 F6 (D2 | F2) F0 ED E1 (C3 | E3) E6 E6 F0 E7 F1 F1 }
		$a130 = { (C4 | E4) E6 F7 (D3 | F3) F1 EC E0 (C2 | E2) E7 E7 F1 E6 F0 F0 }
		$a131 = { (C3 | E3) E1 F0 (D4 | F4) F6 EB E7 (C5 | E5) E0 E0 F6 E1 F7 F7 }
		$a132 = { (C2 | E2) E0 F1 (D5 | F5) F7 EA E6 (C4 | E4) E1 E1 F7 E0 F6 F6 }
		$a133 = { (C1 | E1) E3 F2 (D6 | F6) F4 E9 E5 (C7 | E7) E2 E2 F4 E3 F5 F5 }
		$a134 = { (C0 | E0) E2 F3 (D7 | F7) F5 E8 E4 (C6 | E6) E3 E3 F5 E2 F4 F4 }
		$a135 = { (CF | EF) ED FC (D8 | F8) FA E7 EB (C9 | E9) EC EC FA ED FB FB }
		$a136 = { (CE | EE) EC FD (D9 | F9) FB E6 EA (C8 | E8) ED ED FB EC FA FA }
		$a137 = { (CD | ED) EF FE (DA | FA) F8 E5 E9 (CB | EB) EE EE F8 EF F9 F9 }
		$a138 = { (CC | EC) EE FF (DB | FB) F9 E4 E8 (CA | EA) EF EF F9 EE F8 F8 }
		$a139 = { (CB | EB) E9 F8 (DC | FC) FE E3 EF (CD | ED) E8 E8 FE E9 FF FF }
		$a140 = { (CA | EA) E8 F9 (DD | FD) FF E2 EE (CC | EC) E9 E9 FF E8 FE FE }
		$a141 = { (C9 | E9) EB FA (DE | FE) FC E1 ED (CF | EF) EA EA FC EB FD FD }
		$a142 = { (C8 | E8) EA FB (DF | FF) FD E0 EC (CE | EE) EB EB FD EA FC FC }
		$a143 = { (D7 | F7) F5 E4 (C0 | E0) E2 FF F3 (D1 | F1) F4 F4 E2 F5 E3 E3 }
		$a144 = { (D6 | F6) F4 E5 (C1 | E1) E3 FE F2 (D0 | F0) F5 F5 E3 F4 E2 E2 }
		$a145 = { (D5 | F5) F7 E6 (C2 | E2) E0 FD F1 (D3 | F3) F6 F6 E0 F7 E1 E1 }
		$a146 = { (D4 | F4) F6 E7 (C3 | E3) E1 FC F0 (D2 | F2) F7 F7 E1 F6 E0 E0 }
		$a147 = { (D3 | F3) F1 E0 (C4 | E4) E6 FB F7 (D5 | F5) F0 F0 E6 F1 E7 E7 }
		$a148 = { (D2 | F2) F0 E1 (C5 | E5) E7 FA F6 (D4 | F4) F1 F1 E7 F0 E6 E6 }
		$a149 = { (D1 | F1) F3 E2 (C6 | E6) E4 F9 F5 (D7 | F7) F2 F2 E4 F3 E5 E5 }
		$a150 = { (D0 | F0) F2 E3 (C7 | E7) E5 F8 F4 (D6 | F6) F3 F3 E5 F2 E4 E4 }
		$a151 = { (DF | FF) FD EC (C8 | E8) EA F7 FB (D9 | F9) FC FC EA FD EB EB }
		$a152 = { (DE | FE) FC ED (C9 | E9) EB F6 FA (D8 | F8) FD FD EB FC EA EA }
		$a153 = { (DD | FD) FF EE (CA | EA) E8 F5 F9 (DB | FB) FE FE E8 FF E9 E9 }
		$a154 = { (DC | FC) FE EF (CB | EB) E9 F4 F8 (DA | FA) FF FF E9 FE E8 E8 }
		$a155 = { (DB | FB) F9 E8 (CC | EC) EE F3 FF (DD | FD) F8 F8 EE F9 EF EF }
		$a156 = { (DA | FA) F8 E9 (CD | ED) EF F2 FE (DC | FC) F9 F9 EF F8 EE EE }
		$a157 = { (D9 | F9) FB EA (CE | EE) EC F1 FD (DF | FF) FA FA EC FB ED ED }
		$a158 = { (D8 | F8) FA EB (CF | EF) ED F0 FC (DE | FE) FB FB ED FA EC EC }
		$a159 = { (E7 | C7) C5 D4 (F0 | D0) D2 CF C3 (E1 | C1) C4 C4 D2 C5 D3 D3 }
		$a160 = { (E6 | C6) C4 D5 (F1 | D1) D3 CE C2 (E0 | C0) C5 C5 D3 C4 D2 D2 }
		$a161 = { (E5 | C5) C7 D6 (F2 | D2) D0 CD C1 (E3 | C3) C6 C6 D0 C7 D1 D1 }
		$a162 = { (E4 | C4) C6 D7 (F3 | D3) D1 CC C0 (E2 | C2) C7 C7 D1 C6 D0 D0 }
		$a163 = { (E3 | C3) C1 D0 (F4 | D4) D6 CB C7 (E5 | C5) C0 C0 D6 C1 D7 D7 }
		$a164 = { (E2 | C2) C0 D1 (F5 | D5) D7 CA C6 (E4 | C4) C1 C1 D7 C0 D6 D6 }
		$a165 = { (E1 | C1) C3 D2 (F6 | D6) D4 C9 C5 (E7 | C7) C2 C2 D4 C3 D5 D5 }
		$a166 = { (E0 | C0) C2 D3 (F7 | D7) D5 C8 C4 (E6 | C6) C3 C3 D5 C2 D4 D4 }
		$a167 = { (EF | CF) CD DC (F8 | D8) DA C7 CB (E9 | C9) CC CC DA CD DB DB }
		$a168 = { (EE | CE) CC DD (F9 | D9) DB C6 CA (E8 | C8) CD CD DB CC DA DA }
		$a169 = { (ED | CD) CF DE (FA | DA) D8 C5 C9 (EB | CB) CE CE D8 CF D9 D9 }
		$a170 = { (EC | CC) CE DF (FB | DB) D9 C4 C8 (EA | CA) CF CF D9 CE D8 D8 }
		$a171 = { (EB | CB) C9 D8 (FC | DC) DE C3 CF (ED | CD) C8 C8 DE C9 DF DF }
		$a172 = { (EA | CA) C8 D9 (FD | DD) DF C2 CE (EC | CC) C9 C9 DF C8 DE DE }
		$a173 = { (E9 | C9) CB DA (FE | DE) DC C1 CD (EF | CF) CA CA DC CB DD DD }
		$a174 = { (E8 | C8) CA DB (FF | DF) DD C0 CC (EE | CE) CB CB DD CA DC DC }
		$a175 = { (F7 | D7) D5 C4 (E0 | C0) C2 DF D3 (F1 | D1) D4 D4 C2 D5 C3 C3 }
		$a176 = { (F6 | D6) D4 C5 (E1 | C1) C3 DE D2 (F0 | D0) D5 D5 C3 D4 C2 C2 }
		$a177 = { (F5 | D5) D7 C6 (E2 | C2) C0 DD D1 (F3 | D3) D6 D6 C0 D7 C1 C1 }
		$a178 = { (F4 | D4) D6 C7 (E3 | C3) C1 DC D0 (F2 | D2) D7 D7 C1 D6 C0 C0 }
		$a179 = { (F3 | D3) D1 C0 (E4 | C4) C6 DB D7 (F5 | D5) D0 D0 C6 D1 C7 C7 }
		$a180 = { (F2 | D2) D0 C1 (E5 | C5) C7 DA D6 (F4 | D4) D1 D1 C7 D0 C6 C6 }
		$a181 = { (F1 | D1) D3 C2 (E6 | C6) C4 D9 D5 (F7 | D7) D2 D2 C4 D3 C5 C5 }
		$a182 = { (F0 | D0) D2 C3 (E7 | C7) C5 D8 D4 (F6 | D6) D3 D3 C5 D2 C4 C4 }
		$a183 = { (FF | DF) DD CC (E8 | C8) CA D7 DB (F9 | D9) DC DC CA DD CB CB }
		$a184 = { (FE | DE) DC CD (E9 | C9) CB D6 DA (F8 | D8) DD DD CB DC CA CA }
		$a185 = { (FD | DD) DF CE (EA | CA) C8 D5 D9 (FB | DB) DE DE C8 DF C9 C9 }
		$a186 = { (FC | DC) DE CF (EB | CB) C9 D4 D8 (FA | DA) DF DF C9 DE C8 C8 }
		$a187 = { (FB | DB) D9 C8 (EC | CC) CE D3 DF (FD | DD) D8 D8 CE D9 CF CF }
		$a188 = { (FA | DA) D8 C9 (ED | CD) CF D2 DE (FC | DC) D9 D9 CF D8 CE CE }
		$a189 = { (F9 | D9) DB CA (EE | CE) CC D1 DD (FF | DF) DA DA CC DB CD CD }
		$a190 = { (F8 | D8) DA CB (EF | CF) CD D0 DC (FE | DE) DB DB CD DA CC CC }
		$a191 = { (87 | A7) A5 B4 (90 | B0) B2 AF A3 (81 | A1) A4 A4 B2 A5 B3 B3 }
		$a192 = { (86 | A6) A4 B5 (91 | B1) B3 AE A2 (80 | A0) A5 A5 B3 A4 B2 B2 }
		$a193 = { (85 | A5) A7 B6 (92 | B2) B0 AD A1 (83 | A3) A6 A6 B0 A7 B1 B1 }
		$a194 = { (84 | A4) A6 B7 (93 | B3) B1 AC A0 (82 | A2) A7 A7 B1 A6 B0 B0 }
		$a195 = { (83 | A3) A1 B0 (94 | B4) B6 AB A7 (85 | A5) A0 A0 B6 A1 B7 B7 }
		$a196 = { (82 | A2) A0 B1 (95 | B5) B7 AA A6 (84 | A4) A1 A1 B7 A0 B6 B6 }
		$a197 = { (81 | A1) A3 B2 (96 | B6) B4 A9 A5 (87 | A7) A2 A2 B4 A3 B5 B5 }
		$a198 = { (80 | A0) A2 B3 (97 | B7) B5 A8 A4 (86 | A6) A3 A3 B5 A2 B4 B4 }
		$a199 = { (8F | AF) AD BC (98 | B8) BA A7 AB (89 | A9) AC AC BA AD BB BB }
		$a200 = { (8E | AE) AC BD (99 | B9) BB A6 AA (88 | A8) AD AD BB AC BA BA }
		$a201 = { (8D | AD) AF BE (9A | BA) B8 A5 A9 (8B | AB) AE AE B8 AF B9 B9 }
		$a202 = { (8C | AC) AE BF (9B | BB) B9 A4 A8 (8A | AA) AF AF B9 AE B8 B8 }
		$a203 = { (8B | AB) A9 B8 (9C | BC) BE A3 AF (8D | AD) A8 A8 BE A9 BF BF }
		$a204 = { (8A | AA) A8 B9 (9D | BD) BF A2 AE (8C | AC) A9 A9 BF A8 BE BE }
		$a205 = { (89 | A9) AB BA (9E | BE) BC A1 AD (8F | AF) AA AA BC AB BD BD }
		$a206 = { (88 | A8) AA BB (9F | BF) BD A0 AC (8E | AE) AB AB BD AA BC BC }
		$a207 = { (97 | B7) B5 A4 (80 | A0) A2 BF B3 (91 | B1) B4 B4 A2 B5 A3 A3 }
		$a208 = { (96 | B6) B4 A5 (81 | A1) A3 BE B2 (90 | B0) B5 B5 A3 B4 A2 A2 }
		$a209 = { (95 | B5) B7 A6 (82 | A2) A0 BD B1 (93 | B3) B6 B6 A0 B7 A1 A1 }
		$a210 = { (94 | B4) B6 A7 (83 | A3) A1 BC B0 (92 | B2) B7 B7 A1 B6 A0 A0 }
		$a211 = { (93 | B3) B1 A0 (84 | A4) A6 BB B7 (95 | B5) B0 B0 A6 B1 A7 A7 }
		$a212 = { (92 | B2) B0 A1 (85 | A5) A7 BA B6 (94 | B4) B1 B1 A7 B0 A6 A6 }
		$a213 = { (91 | B1) B3 A2 (86 | A6) A4 B9 B5 (97 | B7) B2 B2 A4 B3 A5 A5 }
		$a214 = { (90 | B0) B2 A3 (87 | A7) A5 B8 B4 (96 | B6) B3 B3 A5 B2 A4 A4 }
		$a215 = { (9F | BF) BD AC (88 | A8) AA B7 BB (99 | B9) BC BC AA BD AB AB }
		$a216 = { (9E | BE) BC AD (89 | A9) AB B6 BA (98 | B8) BD BD AB BC AA AA }
		$a217 = { (9D | BD) BF AE (8A | AA) A8 B5 B9 (9B | BB) BE BE A8 BF A9 A9 }
		$a218 = { (9C | BC) BE AF (8B | AB) A9 B4 B8 (9A | BA) BF BF A9 BE A8 A8 }
		$a219 = { (9B | BB) B9 A8 (8C | AC) AE B3 BF (9D | BD) B8 B8 AE B9 AF AF }
		$a220 = { (9A | BA) B8 A9 (8D | AD) AF B2 BE (9C | BC) B9 B9 AF B8 AE AE }
		$a221 = { (99 | B9) BB AA (8E | AE) AC B1 BD (9F | BF) BA BA AC BB AD AD }
		$a222 = { (98 | B8) BA AB (8F | AF) AD B0 BC (9E | BE) BB BB AD BA AC AC }
		$a223 = { (A7 | 87) 85 94 (B0 | 90) 92 8F 83 (A1 | 81) 84 84 92 85 93 93 }
		$a224 = { (A6 | 86) 84 95 (B1 | 91) 93 8E 82 (A0 | 80) 85 85 93 84 92 92 }
		$a225 = { (A5 | 85) 87 96 (B2 | 92) 90 8D 81 (A3 | 83) 86 86 90 87 91 91 }
		$a226 = { (A4 | 84) 86 97 (B3 | 93) 91 8C 80 (A2 | 82) 87 87 91 86 90 90 }
		$a227 = { (A3 | 83) 81 90 (B4 | 94) 96 8B 87 (A5 | 85) 80 80 96 81 97 97 }
		$a228 = { (A2 | 82) 80 91 (B5 | 95) 97 8A 86 (A4 | 84) 81 81 97 80 96 96 }
		$a229 = { (A1 | 81) 83 92 (B6 | 96) 94 89 85 (A7 | 87) 82 82 94 83 95 95 }
		$a230 = { (A0 | 80) 82 93 (B7 | 97) 95 88 84 (A6 | 86) 83 83 95 82 94 94 }
		$a231 = { (AF | 8F) 8D 9C (B8 | 98) 9A 87 8B (A9 | 89) 8C 8C 9A 8D 9B 9B }
		$a232 = { (AE | 8E) 8C 9D (B9 | 99) 9B 86 8A (A8 | 88) 8D 8D 9B 8C 9A 9A }
		$a233 = { (AD | 8D) 8F 9E (BA | 9A) 98 85 89 (AB | 8B) 8E 8E 98 8F 99 99 }
		$a234 = { (AC | 8C) 8E 9F (BB | 9B) 99 84 88 (AA | 8A) 8F 8F 99 8E 98 98 }
		$a235 = { (AB | 8B) 89 98 (BC | 9C) 9E 83 8F (AD | 8D) 88 88 9E 89 9F 9F }
		$a236 = { (AA | 8A) 88 99 (BD | 9D) 9F 82 8E (AC | 8C) 89 89 9F 88 9E 9E }
		$a237 = { (A9 | 89) 8B 9A (BE | 9E) 9C 81 8D (AF | 8F) 8A 8A 9C 8B 9D 9D }
		$a238 = { (A8 | 88) 8A 9B (BF | 9F) 9D 80 8C (AE | 8E) 8B 8B 9D 8A 9C 9C }
		$a239 = { (B7 | 97) 95 84 (A0 | 80) 82 9F 93 (B1 | 91) 94 94 82 95 83 83 }
		$a240 = { (B6 | 96) 94 85 (A1 | 81) 83 9E 92 (B0 | 90) 95 95 83 94 82 82 }
		$a241 = { (B5 | 95) 97 86 (A2 | 82) 80 9D 91 (B3 | 93) 96 96 80 97 81 81 }
		$a242 = { (B4 | 94) 96 87 (A3 | 83) 81 9C 90 (B2 | 92) 97 97 81 96 80 80 }
		$a243 = { (B3 | 93) 91 80 (A4 | 84) 86 9B 97 (B5 | 95) 90 90 86 91 87 87 }
		$a244 = { (B2 | 92) 90 81 (A5 | 85) 87 9A 96 (B4 | 94) 91 91 87 90 86 86 }
		$a245 = { (B1 | 91) 93 82 (A6 | 86) 84 99 95 (B7 | 97) 92 92 84 93 85 85 }
		$a246 = { (B0 | 90) 92 83 (A7 | 87) 85 98 94 (B6 | 96) 93 93 85 92 84 84 }
		$a247 = { (BF | 9F) 9D 8C (A8 | 88) 8A 97 9B (B9 | 99) 9C 9C 8A 9D 8B 8B }
		$a248 = { (BE | 9E) 9C 8D (A9 | 89) 8B 96 9A (B8 | 98) 9D 9D 8B 9C 8A 8A }
		$a249 = { (BD | 9D) 9F 8E (AA | 8A) 88 95 99 (BB | 9B) 9E 9E 88 9F 89 89 }
		$a250 = { (BC | 9C) 9E 8F (AB | 8B) 89 94 98 (BA | 9A) 9F 9F 89 9E 88 88 }
		$a251 = { (BB | 9B) 99 88 (AC | 8C) 8E 93 9F (BD | 9D) 98 98 8E 99 8F 8F }
		$a252 = { (BA | 9A) 98 89 (AD | 8D) 8F 92 9E (BC | 9C) 99 99 8F 98 8E 8E }
		$a253 = { (B9 | 99) 9B 8A (AE | 8E) 8C 91 9D (BF | 9F) 9A 9A 8C 9B 8D 8D }
		$a254 = { (4D | 6D) 6E 60 65 (4D | 6D) 68 63 73 60 73 78 }  // "LoadLibrary" XOR 0x01
		$a255 = { (4E | 6E) 6D 63 66 (4E | 6E) 6B 60 70 63 70 7B }  // "LoadLibrary" XOR 0x02
		$a256 = { (4F | 6F) 6C 62 67 (4F | 6F) 6A 61 71 62 71 7A }  // etc...
		$a257 = { (48 | 68) 6B 65 60 (48 | 68) 6D 66 76 65 76 7D }
		$a258 = { (49 | 69) 6A 64 61 (49 | 69) 6C 67 77 64 77 7C }
		$a259 = { (4A | 6A) 69 67 62 (4A | 6A) 6F 64 74 67 74 7F }
		$a260 = { (4B | 6B) 68 66 63 (4B | 6B) 6E 65 75 66 75 7E }
		$a261 = { (44 | 64) 67 69 6C (44 | 64) 61 6A 7A 69 7A 71 }
		$a262 = { (45 | 65) 66 68 6D (45 | 65) 60 6B 7B 68 7B 70 }
		$a263 = { (46 | 66) 65 6B 6E (46 | 66) 63 68 78 6B 78 73 }
		$a264 = { (47 | 67) 64 6A 6F (47 | 67) 62 69 79 6A 79 72 }
		$a265 = { (40 | 60) 63 6D 68 (40 | 60) 65 6E 7E 6D 7E 75 }
		$a266 = { (41 | 61) 62 6C 69 (41 | 61) 64 6F 7F 6C 7F 74 }
		$a267 = { (42 | 62) 61 6F 6A (42 | 62) 67 6C 7C 6F 7C 77 }
		$a268 = { (43 | 63) 60 6E 6B (43 | 63) 66 6D 7D 6E 7D 76 }
		$a269 = { (5C | 7C) 7F 71 74 (5C | 7C) 79 72 62 71 62 69 }
		$a270 = { (5D | 7D) 7E 70 75 (5D | 7D) 78 73 63 70 63 68 }
		$a271 = { (5E | 7E) 7D 73 76 (5E | 7E) 7B 70 60 73 60 6B }
		$a272 = { (5F | 7F) 7C 72 77 (5F | 7F) 7A 71 61 72 61 6A }
		$a273 = { (58 | 78) 7B 75 70 (58 | 78) 7D 76 66 75 66 6D }
		$a274 = { (59 | 79) 7A 74 71 (59 | 79) 7C 77 67 74 67 6C }
		$a275 = { (5A | 7A) 79 77 72 (5A | 7A) 7F 74 64 77 64 6F }
		$a276 = { (5B | 7B) 78 76 73 (5B | 7B) 7E 75 65 76 65 6E }
		$a277 = { (54 | 74) 77 79 7C (54 | 74) 71 7A 6A 79 6A 61 }
		$a278 = { (55 | 75) 76 78 7D (55 | 75) 70 7B 6B 78 6B 60 }
		$a279 = { (56 | 76) 75 7B 7E (56 | 76) 73 78 68 7B 68 63 }
		$a280 = { (57 | 77) 74 7A 7F (57 | 77) 72 79 69 7A 69 62 }
		$a281 = { (50 | 70) 73 7D 78 (50 | 70) 75 7E 6E 7D 6E 65 }
		$a282 = { (51 | 71) 72 7C 79 (51 | 71) 74 7F 6F 7C 6F 64 }
		$a283 = { (52 | 72) 71 7F 7A (52 | 72) 77 7C 6C 7F 6C 67 }
		$a284 = { (53 | 73) 70 7E 7B (53 | 73) 76 7D 6D 7E 6D 66 }
		// XOR 0x20 removed because it toggles capitalization and causes [lL]OAD[Ll]IBRARY to match.
		$a286 = { (6D | 4D) 4E 40 45 (6D | 4D) 48 43 53 40 53 58 }
		$a287 = { (6E | 4E) 4D 43 46 (6E | 4E) 4B 40 50 43 50 5B }
		$a288 = { (6F | 4F) 4C 42 47 (6F | 4F) 4A 41 51 42 51 5A }
		$a289 = { (68 | 48) 4B 45 40 (68 | 48) 4D 46 56 45 56 5D }
		$a290 = { (69 | 49) 4A 44 41 (69 | 49) 4C 47 57 44 57 5C }
		$a291 = { (6A | 4A) 49 47 42 (6A | 4A) 4F 44 54 47 54 5F }
		$a292 = { (6B | 4B) 48 46 43 (6B | 4B) 4E 45 55 46 55 5E }
		$a293 = { (64 | 44) 47 49 4C (64 | 44) 41 4A 5A 49 5A 51 }
		$a294 = { (65 | 45) 46 48 4D (65 | 45) 40 4B 5B 48 5B 50 }
		$a295 = { (66 | 46) 45 4B 4E (66 | 46) 43 48 58 4B 58 53 }
		$a296 = { (67 | 47) 44 4A 4F (67 | 47) 42 49 59 4A 59 52 }
		$a297 = { (60 | 40) 43 4D 48 (60 | 40) 45 4E 5E 4D 5E 55 }
		$a298 = { (61 | 41) 42 4C 49 (61 | 41) 44 4F 5F 4C 5F 54 }
		$a299 = { (62 | 42) 41 4F 4A (62 | 42) 47 4C 5C 4F 5C 57 }
		$a300 = { (63 | 43) 40 4E 4B (63 | 43) 46 4D 5D 4E 5D 56 }
		$a301 = { (7C | 5C) 5F 51 54 (7C | 5C) 59 52 42 51 42 49 }
		$a302 = { (7D | 5D) 5E 50 55 (7D | 5D) 58 53 43 50 43 48 }
		$a303 = { (7E | 5E) 5D 53 56 (7E | 5E) 5B 50 40 53 40 4B }
		$a304 = { (7F | 5F) 5C 52 57 (7F | 5F) 5A 51 41 52 41 4A }
		$a305 = { (78 | 58) 5B 55 50 (78 | 58) 5D 56 46 55 46 4D }
		$a306 = { (79 | 59) 5A 54 51 (79 | 59) 5C 57 47 54 47 4C }
		$a307 = { (7A | 5A) 59 57 52 (7A | 5A) 5F 54 44 57 44 4F }
		$a308 = { (7B | 5B) 58 56 53 (7B | 5B) 5E 55 45 56 45 4E }
		$a309 = { (74 | 54) 57 59 5C (74 | 54) 51 5A 4A 59 4A 41 }
		$a310 = { (75 | 55) 56 58 5D (75 | 55) 50 5B 4B 58 4B 40 }
		$a311 = { (76 | 56) 55 5B 5E (76 | 56) 53 58 48 5B 48 43 }
		$a312 = { (77 | 57) 54 5A 5F (77 | 57) 52 59 49 5A 49 42 }
		$a313 = { (70 | 50) 53 5D 58 (70 | 50) 55 5E 4E 5D 4E 45 }
		$a314 = { (71 | 51) 52 5C 59 (71 | 51) 54 5F 4F 5C 4F 44 }
		$a315 = { (72 | 52) 51 5F 5A (72 | 52) 57 5C 4C 5F 4C 47 }
		$a316 = { (73 | 53) 50 5E 5B (73 | 53) 56 5D 4D 5E 4D 46 }
		$a317 = { (0C | 2C) 2F 21 24 (0C | 2C) 29 22 32 21 32 39 }
		$a318 = { (0D | 2D) 2E 20 25 (0D | 2D) 28 23 33 20 33 38 }
		$a319 = { (0E | 2E) 2D 23 26 (0E | 2E) 2B 20 30 23 30 3B }
		$a320 = { (0F | 2F) 2C 22 27 (0F | 2F) 2A 21 31 22 31 3A }
		$a321 = { (08 | 28) 2B 25 20 (08 | 28) 2D 26 36 25 36 3D }
		$a322 = { (09 | 29) 2A 24 21 (09 | 29) 2C 27 37 24 37 3C }
		$a323 = { (0A | 2A) 29 27 22 (0A | 2A) 2F 24 34 27 34 3F }
		$a324 = { (0B | 2B) 28 26 23 (0B | 2B) 2E 25 35 26 35 3E }
		$a325 = { (04 | 24) 27 29 2C (04 | 24) 21 2A 3A 29 3A 31 }
		$a326 = { (05 | 25) 26 28 2D (05 | 25) 20 2B 3B 28 3B 30 }
		$a327 = { (06 | 26) 25 2B 2E (06 | 26) 23 28 38 2B 38 33 }
		$a328 = { (07 | 27) 24 2A 2F (07 | 27) 22 29 39 2A 39 32 }
		$a329 = { (00 | 20) 23 2D 28 (00 | 20) 25 2E 3E 2D 3E 35 }
		$a330 = { (01 | 21) 22 2C 29 (01 | 21) 24 2F 3F 2C 3F 34 }
		$a331 = { (02 | 22) 21 2F 2A (02 | 22) 27 2C 3C 2F 3C 37 }
		$a332 = { (03 | 23) 20 2E 2B (03 | 23) 26 2D 3D 2E 3D 36 }
		$a333 = { (1C | 3C) 3F 31 34 (1C | 3C) 39 32 22 31 22 29 }
		$a334 = { (1D | 3D) 3E 30 35 (1D | 3D) 38 33 23 30 23 28 }
		$a335 = { (1E | 3E) 3D 33 36 (1E | 3E) 3B 30 20 33 20 2B }
		$a336 = { (1F | 3F) 3C 32 37 (1F | 3F) 3A 31 21 32 21 2A }
		$a337 = { (18 | 38) 3B 35 30 (18 | 38) 3D 36 26 35 26 2D }
		$a338 = { (19 | 39) 3A 34 31 (19 | 39) 3C 37 27 34 27 2C }
		$a339 = { (1A | 3A) 39 37 32 (1A | 3A) 3F 34 24 37 24 2F }
		$a340 = { (1B | 3B) 38 36 33 (1B | 3B) 3E 35 25 36 25 2E }
		$a341 = { (14 | 34) 37 39 3C (14 | 34) 31 3A 2A 39 2A 21 }
		$a342 = { (15 | 35) 36 38 3D (15 | 35) 30 3B 2B 38 2B 20 }
		$a343 = { (16 | 36) 35 3B 3E (16 | 36) 33 38 28 3B 28 23 }
		$a344 = { (17 | 37) 34 3A 3F (17 | 37) 32 39 29 3A 29 22 }
		$a345 = { (10 | 30) 33 3D 38 (10 | 30) 35 3E 2E 3D 2E 25 }
		$a346 = { (11 | 31) 32 3C 39 (11 | 31) 34 3F 2F 3C 2F 24 }
		$a347 = { (12 | 32) 31 3F 3A (12 | 32) 37 3C 2C 3F 2C 27 }
		$a348 = { (13 | 33) 30 3E 3B (13 | 33) 36 3D 2D 3E 2D 26 }
		$a349 = { (2C | 0C) 0F 01 04 (2C | 0C) 09 02 12 01 12 19 }
		$a350 = { (2D | 0D) 0E 00 05 (2D | 0D) 08 03 13 00 13 18 }
		$a351 = { (2E | 0E) 0D 03 06 (2E | 0E) 0B 00 10 03 10 1B }
		$a352 = { (2F | 0F) 0C 02 07 (2F | 0F) 0A 01 11 02 11 1A }
		$a353 = { (28 | 08) 0B 05 00 (28 | 08) 0D 06 16 05 16 1D }
		$a354 = { (29 | 09) 0A 04 01 (29 | 09) 0C 07 17 04 17 1C }
		$a355 = { (2A | 0A) 09 07 02 (2A | 0A) 0F 04 14 07 14 1F }
		$a356 = { (2B | 0B) 08 06 03 (2B | 0B) 0E 05 15 06 15 1E }
		$a357 = { (24 | 04) 07 09 0C (24 | 04) 01 0A 1A 09 1A 11 }
		$a358 = { (25 | 05) 06 08 0D (25 | 05) 00 0B 1B 08 1B 10 }
		$a359 = { (26 | 06) 05 0B 0E (26 | 06) 03 08 18 0B 18 13 }
		$a360 = { (27 | 07) 04 0A 0F (27 | 07) 02 09 19 0A 19 12 }
		$a361 = { (20 | 00) 03 0D 08 (20 | 00) 05 0E 1E 0D 1E 15 }
		$a362 = { (21 | 01) 02 0C 09 (21 | 01) 04 0F 1F 0C 1F 14 }
		$a363 = { (22 | 02) 01 0F 0A (22 | 02) 07 0C 1C 0F 1C 17 }
		$a364 = { (23 | 03) 00 0E 0B (23 | 03) 06 0D 1D 0E 1D 16 }
		$a365 = { (3C | 1C) 1F 11 14 (3C | 1C) 19 12 02 11 02 09 }
		$a366 = { (3D | 1D) 1E 10 15 (3D | 1D) 18 13 03 10 03 08 }
		$a367 = { (3E | 1E) 1D 13 16 (3E | 1E) 1B 10 00 13 00 0B }
		$a368 = { (3F | 1F) 1C 12 17 (3F | 1F) 1A 11 01 12 01 0A }
		$a369 = { (38 | 18) 1B 15 10 (38 | 18) 1D 16 06 15 06 0D }
		$a370 = { (39 | 19) 1A 14 11 (39 | 19) 1C 17 07 14 07 0C }
		$a371 = { (3A | 1A) 19 17 12 (3A | 1A) 1F 14 04 17 04 0F }
		$a372 = { (3B | 1B) 18 16 13 (3B | 1B) 1E 15 05 16 05 0E }
		$a373 = { (34 | 14) 17 19 1C (34 | 14) 11 1A 0A 19 0A 01 }
		$a374 = { (35 | 15) 16 18 1D (35 | 15) 10 1B 0B 18 0B 00 }
		$a375 = { (36 | 16) 15 1B 1E (36 | 16) 13 18 08 1B 08 03 }
		$a376 = { (37 | 17) 14 1A 1F (37 | 17) 12 19 09 1A 09 02 }
		$a377 = { (30 | 10) 13 1D 18 (30 | 10) 15 1E 0E 1D 0E 05 }
		$a378 = { (31 | 11) 12 1C 19 (31 | 11) 14 1F 0F 1C 0F 04 }
		$a379 = { (32 | 12) 11 1F 1A (32 | 12) 17 1C 0C 1F 0C 07 }
		$a380 = { (33 | 13) 10 1E 1B (33 | 13) 16 1D 0D 1E 0D 06 }
		$a381 = { (CC | EC) EF E1 E4 (CC | EC) E9 E2 F2 E1 F2 F9 }
		$a382 = { (CD | ED) EE E0 E5 (CD | ED) E8 E3 F3 E0 F3 F8 }
		$a383 = { (CE | EE) ED E3 E6 (CE | EE) EB E0 F0 E3 F0 FB }
		$a384 = { (CF | EF) EC E2 E7 (CF | EF) EA E1 F1 E2 F1 FA }
		$a385 = { (C8 | E8) EB E5 E0 (C8 | E8) ED E6 F6 E5 F6 FD }
		$a386 = { (C9 | E9) EA E4 E1 (C9 | E9) EC E7 F7 E4 F7 FC }
		$a387 = { (CA | EA) E9 E7 E2 (CA | EA) EF E4 F4 E7 F4 FF }
		$a388 = { (CB | EB) E8 E6 E3 (CB | EB) EE E5 F5 E6 F5 FE }
		$a389 = { (C4 | E4) E7 E9 EC (C4 | E4) E1 EA FA E9 FA F1 }
		$a390 = { (C5 | E5) E6 E8 ED (C5 | E5) E0 EB FB E8 FB F0 }
		$a391 = { (C6 | E6) E5 EB EE (C6 | E6) E3 E8 F8 EB F8 F3 }
		$a392 = { (C7 | E7) E4 EA EF (C7 | E7) E2 E9 F9 EA F9 F2 }
		$a393 = { (C0 | E0) E3 ED E8 (C0 | E0) E5 EE FE ED FE F5 }
		$a394 = { (C1 | E1) E2 EC E9 (C1 | E1) E4 EF FF EC FF F4 }
		$a395 = { (C2 | E2) E1 EF EA (C2 | E2) E7 EC FC EF FC F7 }
		$a396 = { (C3 | E3) E0 EE EB (C3 | E3) E6 ED FD EE FD F6 }
		$a397 = { (DC | FC) FF F1 F4 (DC | FC) F9 F2 E2 F1 E2 E9 }
		$a398 = { (DD | FD) FE F0 F5 (DD | FD) F8 F3 E3 F0 E3 E8 }
		$a399 = { (DE | FE) FD F3 F6 (DE | FE) FB F0 E0 F3 E0 EB }
		$a400 = { (DF | FF) FC F2 F7 (DF | FF) FA F1 E1 F2 E1 EA }
		$a401 = { (D8 | F8) FB F5 F0 (D8 | F8) FD F6 E6 F5 E6 ED }
		$a402 = { (D9 | F9) FA F4 F1 (D9 | F9) FC F7 E7 F4 E7 EC }
		$a403 = { (DA | FA) F9 F7 F2 (DA | FA) FF F4 E4 F7 E4 EF }
		$a404 = { (DB | FB) F8 F6 F3 (DB | FB) FE F5 E5 F6 E5 EE }
		$a405 = { (D4 | F4) F7 F9 FC (D4 | F4) F1 FA EA F9 EA E1 }
		$a406 = { (D5 | F5) F6 F8 FD (D5 | F5) F0 FB EB F8 EB E0 }
		$a407 = { (D6 | F6) F5 FB FE (D6 | F6) F3 F8 E8 FB E8 E3 }
		$a408 = { (D7 | F7) F4 FA FF (D7 | F7) F2 F9 E9 FA E9 E2 }
		$a409 = { (D0 | F0) F3 FD F8 (D0 | F0) F5 FE EE FD EE E5 }
		$a410 = { (D1 | F1) F2 FC F9 (D1 | F1) F4 FF EF FC EF E4 }
		$a411 = { (D2 | F2) F1 FF FA (D2 | F2) F7 FC EC FF EC E7 }
		$a412 = { (D3 | F3) F0 FE FB (D3 | F3) F6 FD ED FE ED E6 }
		$a413 = { (EC | CC) CF C1 C4 (EC | CC) C9 C2 D2 C1 D2 D9 }
		$a414 = { (ED | CD) CE C0 C5 (ED | CD) C8 C3 D3 C0 D3 D8 }
		$a415 = { (EE | CE) CD C3 C6 (EE | CE) CB C0 D0 C3 D0 DB }
		$a416 = { (EF | CF) CC C2 C7 (EF | CF) CA C1 D1 C2 D1 DA }
		$a417 = { (E8 | C8) CB C5 C0 (E8 | C8) CD C6 D6 C5 D6 DD }
		$a418 = { (E9 | C9) CA C4 C1 (E9 | C9) CC C7 D7 C4 D7 DC }
		$a419 = { (EA | CA) C9 C7 C2 (EA | CA) CF C4 D4 C7 D4 DF }
		$a420 = { (EB | CB) C8 C6 C3 (EB | CB) CE C5 D5 C6 D5 DE }
		$a421 = { (E4 | C4) C7 C9 CC (E4 | C4) C1 CA DA C9 DA D1 }
		$a422 = { (E5 | C5) C6 C8 CD (E5 | C5) C0 CB DB C8 DB D0 }
		$a423 = { (E6 | C6) C5 CB CE (E6 | C6) C3 C8 D8 CB D8 D3 }
		$a424 = { (E7 | C7) C4 CA CF (E7 | C7) C2 C9 D9 CA D9 D2 }
		$a425 = { (E0 | C0) C3 CD C8 (E0 | C0) C5 CE DE CD DE D5 }
		$a426 = { (E1 | C1) C2 CC C9 (E1 | C1) C4 CF DF CC DF D4 }
		$a427 = { (E2 | C2) C1 CF CA (E2 | C2) C7 CC DC CF DC D7 }
		$a428 = { (E3 | C3) C0 CE CB (E3 | C3) C6 CD DD CE DD D6 }
		$a429 = { (FC | DC) DF D1 D4 (FC | DC) D9 D2 C2 D1 C2 C9 }
		$a430 = { (FD | DD) DE D0 D5 (FD | DD) D8 D3 C3 D0 C3 C8 }
		$a431 = { (FE | DE) DD D3 D6 (FE | DE) DB D0 C0 D3 C0 CB }
		$a432 = { (FF | DF) DC D2 D7 (FF | DF) DA D1 C1 D2 C1 CA }
		$a433 = { (F8 | D8) DB D5 D0 (F8 | D8) DD D6 C6 D5 C6 CD }
		$a434 = { (F9 | D9) DA D4 D1 (F9 | D9) DC D7 C7 D4 C7 CC }
		$a435 = { (FA | DA) D9 D7 D2 (FA | DA) DF D4 C4 D7 C4 CF }
		$a436 = { (FB | DB) D8 D6 D3 (FB | DB) DE D5 C5 D6 C5 CE }
		$a437 = { (F4 | D4) D7 D9 DC (F4 | D4) D1 DA CA D9 CA C1 }
		$a438 = { (F5 | D5) D6 D8 DD (F5 | D5) D0 DB CB D8 CB C0 }
		$a439 = { (F6 | D6) D5 DB DE (F6 | D6) D3 D8 C8 DB C8 C3 }
		$a440 = { (F7 | D7) D4 DA DF (F7 | D7) D2 D9 C9 DA C9 C2 }
		$a441 = { (F0 | D0) D3 DD D8 (F0 | D0) D5 DE CE DD CE C5 }
		$a442 = { (F1 | D1) D2 DC D9 (F1 | D1) D4 DF CF DC CF C4 }
		$a443 = { (F2 | D2) D1 DF DA (F2 | D2) D7 DC CC DF CC C7 }
		$a444 = { (F3 | D3) D0 DE DB (F3 | D3) D6 DD CD DE CD C6 }
		$a445 = { (8C | AC) AF A1 A4 (8C | AC) A9 A2 B2 A1 B2 B9 }
		$a446 = { (8D | AD) AE A0 A5 (8D | AD) A8 A3 B3 A0 B3 B8 }
		$a447 = { (8E | AE) AD A3 A6 (8E | AE) AB A0 B0 A3 B0 BB }
		$a448 = { (8F | AF) AC A2 A7 (8F | AF) AA A1 B1 A2 B1 BA }
		$a449 = { (88 | A8) AB A5 A0 (88 | A8) AD A6 B6 A5 B6 BD }
		$a450 = { (89 | A9) AA A4 A1 (89 | A9) AC A7 B7 A4 B7 BC }
		$a451 = { (8A | AA) A9 A7 A2 (8A | AA) AF A4 B4 A7 B4 BF }
		$a452 = { (8B | AB) A8 A6 A3 (8B | AB) AE A5 B5 A6 B5 BE }
		$a453 = { (84 | A4) A7 A9 AC (84 | A4) A1 AA BA A9 BA B1 }
		$a454 = { (85 | A5) A6 A8 AD (85 | A5) A0 AB BB A8 BB B0 }
		$a455 = { (86 | A6) A5 AB AE (86 | A6) A3 A8 B8 AB B8 B3 }
		$a456 = { (87 | A7) A4 AA AF (87 | A7) A2 A9 B9 AA B9 B2 }
		$a457 = { (80 | A0) A3 AD A8 (80 | A0) A5 AE BE AD BE B5 }
		$a458 = { (81 | A1) A2 AC A9 (81 | A1) A4 AF BF AC BF B4 }
		$a459 = { (82 | A2) A1 AF AA (82 | A2) A7 AC BC AF BC B7 }
		$a460 = { (83 | A3) A0 AE AB (83 | A3) A6 AD BD AE BD B6 }
		$a461 = { (9C | BC) BF B1 B4 (9C | BC) B9 B2 A2 B1 A2 A9 }
		$a462 = { (9D | BD) BE B0 B5 (9D | BD) B8 B3 A3 B0 A3 A8 }
		$a463 = { (9E | BE) BD B3 B6 (9E | BE) BB B0 A0 B3 A0 AB }
		$a464 = { (9F | BF) BC B2 B7 (9F | BF) BA B1 A1 B2 A1 AA }
		$a465 = { (98 | B8) BB B5 B0 (98 | B8) BD B6 A6 B5 A6 AD }
		$a466 = { (99 | B9) BA B4 B1 (99 | B9) BC B7 A7 B4 A7 AC }
		$a467 = { (9A | BA) B9 B7 B2 (9A | BA) BF B4 A4 B7 A4 AF }
		$a468 = { (9B | BB) B8 B6 B3 (9B | BB) BE B5 A5 B6 A5 AE }
		$a469 = { (94 | B4) B7 B9 BC (94 | B4) B1 BA AA B9 AA A1 }
		$a470 = { (95 | B5) B6 B8 BD (95 | B5) B0 BB AB B8 AB A0 }
		$a471 = { (96 | B6) B5 BB BE (96 | B6) B3 B8 A8 BB A8 A3 }
		$a472 = { (97 | B7) B4 BA BF (97 | B7) B2 B9 A9 BA A9 A2 }
		$a473 = { (90 | B0) B3 BD B8 (90 | B0) B5 BE AE BD AE A5 }
		$a474 = { (91 | B1) B2 BC B9 (91 | B1) B4 BF AF BC AF A4 }
		$a475 = { (92 | B2) B1 BF BA (92 | B2) B7 BC AC BF AC A7 }
		$a476 = { (93 | B3) B0 BE BB (93 | B3) B6 BD AD BE AD A6 }
		$a477 = { (AC | 8C) 8F 81 84 (AC | 8C) 89 82 92 81 92 99 }
		$a478 = { (AD | 8D) 8E 80 85 (AD | 8D) 88 83 93 80 93 98 }
		$a479 = { (AE | 8E) 8D 83 86 (AE | 8E) 8B 80 90 83 90 9B }
		$a480 = { (AF | 8F) 8C 82 87 (AF | 8F) 8A 81 91 82 91 9A }
		$a481 = { (A8 | 88) 8B 85 80 (A8 | 88) 8D 86 96 85 96 9D }
		$a482 = { (A9 | 89) 8A 84 81 (A9 | 89) 8C 87 97 84 97 9C }
		$a483 = { (AA | 8A) 89 87 82 (AA | 8A) 8F 84 94 87 94 9F }
		$a484 = { (AB | 8B) 88 86 83 (AB | 8B) 8E 85 95 86 95 9E }
		$a485 = { (A4 | 84) 87 89 8C (A4 | 84) 81 8A 9A 89 9A 91 }
		$a486 = { (A5 | 85) 86 88 8D (A5 | 85) 80 8B 9B 88 9B 90 }
		$a487 = { (A6 | 86) 85 8B 8E (A6 | 86) 83 88 98 8B 98 93 }
		$a488 = { (A7 | 87) 84 8A 8F (A7 | 87) 82 89 99 8A 99 92 }
		$a489 = { (A0 | 80) 83 8D 88 (A0 | 80) 85 8E 9E 8D 9E 95 }
		$a490 = { (A1 | 81) 82 8C 89 (A1 | 81) 84 8F 9F 8C 9F 94 }
		$a491 = { (A2 | 82) 81 8F 8A (A2 | 82) 87 8C 9C 8F 9C 97 }
		$a492 = { (A3 | 83) 80 8E 8B (A3 | 83) 86 8D 9D 8E 9D 96 }
		$a493 = { (BC | 9C) 9F 91 94 (BC | 9C) 99 92 82 91 82 89 }
		$a494 = { (BD | 9D) 9E 90 95 (BD | 9D) 98 93 83 90 83 88 }
		$a495 = { (BE | 9E) 9D 93 96 (BE | 9E) 9B 90 80 93 80 8B }
		$a496 = { (BF | 9F) 9C 92 97 (BF | 9F) 9A 91 81 92 81 8A }
		$a497 = { (B8 | 98) 9B 95 90 (B8 | 98) 9D 96 86 95 86 8D }
		$a498 = { (B9 | 99) 9A 94 91 (B9 | 99) 9C 97 87 94 87 8C }
		$a499 = { (BA | 9A) 99 97 92 (BA | 9A) 9F 94 84 97 84 8F }
		$a500 = { (BB | 9B) 98 96 93 (BB | 9B) 9E 95 85 96 85 8E }
		$a501 = { (B4 | 94) 97 99 9C (B4 | 94) 91 9A 8A 99 8A 81 }
		$a502 = { (B5 | 95) 96 98 9D (B5 | 95) 90 9B 8B 98 8B 80 }
		$a503 = { (B6 | 96) 95 9B 9E (B6 | 96) 93 98 88 9B 88 83 }
		$a504 = { (B7 | 97) 94 9A 9F (B7 | 97) 92 99 89 9A 89 82 }
		$a505 = { (B0 | 90) 93 9D 98 (B0 | 90) 95 9E 8E 9D 8E 85 }
		$a506 = { (B1 | 91) 92 9C 99 (B1 | 91) 94 9F 8F 9C 8F 84 }
		$a507 = { (B2 | 92) 91 9F 9A (B2 | 92) 97 9C 8C 9F 8C 87 }
	condition:
		any of them
}

rule Misc_Suspicious_Strings
{
    meta:
        description = "Miscellaneous malware strings"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "backdoor" nocase ascii wide
        $a1 = "virus" nocase ascii wide fullword
        $a2 = "hack" nocase ascii wide fullword
        $a3 = "exploit" nocase ascii wide
        $a4 = "cmd.exe" nocase ascii wide
        $a5 = "CWSandbox" nocase wide ascii // Found in some Zeus/Citadel samples
        $a6 = "System32\\drivers\\etc\\hosts" nocase wide ascii
    condition:
        any of them
}

rule BITS_CLSID
{
    meta:
        description = "References the BITS service."
        author = "Ivan Kwiatkowski (@JusticeRage)"
        // The BITS service seems to be used heavily by EquationGroup.
    strings:
        $uuid_background_copy_manager_1_5 =     { 1F 77 87 F0 4F D7 1A 4C BB 8A E1 6A CA 91 24 EA }
        $uuid_background_copy_manager_2_0 =     { 12 AD 18 6D E3 BD 93 43 B3 11 09 9C 34 6E 6D F9 }
        $uuid_background_copy_manager_2_5 =     { D6 98 CA 03 5D FF B8 49 AB C6 03 DD 84 12 70 20 }
        $uuid_background_copy_manager_3_0 =     { A7 DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_manager_4_0 =     { 6B F5 6D BB CE CA DC 11 99 92 00 19 B9 3A 3A 84 }
        $uuid_background_copy_manager_5_0 =     { 4C A3 CC 1E 8A E8 E3 44 8D 6A 89 21 BD E9 E4 52 }
        $uuid_background_copy_manager =         { 4B D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97 }
        $uuid_ibackground_copy_manager =        { 0D 4C E3 5C C9 0D 1F 4C 89 7C DA A1 B7 8C EE 7C }
        $uuid_background_copy_qmanager =        { 69 AD 4A EE 51 BE 43 9B A9 2C 86 AE 49 0E 8B 30 }
        $uuid_ibits_peer_cache_administration = { AD DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_callback =        { C7 99 EA 97 86 01 D4 4A 8D F9 C5 B4 E0 ED 6B 22 }
    condition:
        any of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule inject_thread {
    meta:
        author = "x0r"
        description = "Code injection with CreateRemoteThread in a remote process"
	version = "0.1"
    strings:
        $c1 = "OpenProcess"
        $c2 = "VirtualAllocEx"
        $c3 = "NtWriteVirtualMemory"
        $c4 = "WriteProcessMemory"
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
        $c7 = "OpenProcess"
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c7 )
}

rule hijack_network {
    meta:
        author = "x0r"
        description = "Hijack network configuration"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Classes\\PROTOCOLS\\Handler" nocase
        $p2 = "SOFTWARE\\Classes\\PROTOCOLS\\Filter" nocase
        $p3 = "Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer" nocase
        $p4 = "software\\microsoft\\windows\\currentversion\\internet settings\\proxyenable" nocase
        $f1 = "drivers\\etc\\hosts" nocase
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

rule create_com_service {
    meta:
        author = "x0r"
        description = "Create a COM server"
	version = "0.1"
    strings:
        $c1 = "DllCanUnloadNow" nocase
        $c2 = "DllGetClassObject"
        $c3 = "DllInstall"
        $c4 = "DllRegisterServer"
        $c5 = "DllUnregisterServer"
    condition:
        all of them
}

rule network_udp_sock {
    meta:
        author = "x0r"
        description = "Communications over UDP network"
	version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
	$f2 = "System.Net" nocase
        $f3 = "wsock32.dll" nocase
        $c0 = "WSAStartup"
        $c1 = "sendto"
        $c2 = "recvfrom"
        $c3 = "WSASendTo"
        $c4 = "WSARecvFrom"
        $c5 = "UdpClient"
    condition:
        (($f1 or $f3) and 2 of ($c*)) or ($f2 and $c5)
}

rule network_tcp_listen {
    meta:
        author = "x0r"
        description = "Listen for incoming communication"
	version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
        $f2 = "Mswsock.dll" nocase
	    $f3 = "System.Net" nocase
        $f4 = "wsock32.dll" nocase
        $c1 = "bind"
        $c2 = "accept"
        $c3 = "GetAcceptExSockaddrs"
        $c4 = "AcceptEx"
        $c5 = "WSAStartup"
        $c6 = "WSAAccept"
        $c7 = "WSASocket"
        $c8 = "TcpListener"
        $c9 = "AcceptTcpClient"
        $c10 = "listen"
    condition:
        1 of ($f*) and 2 of ($c*)
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

rule network_toredo {
    meta:
        author = "x0r"
        description = "Communications over Toredo network"
	version = "0.1"
    strings:
	$f1 = "FirewallAPI.dll" nocase
        $p1 = "\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" nocase
    condition:
        all of them
}

rule network_smtp_dotNet {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$f1 = "System.Net.Mail" nocase
        $p1 = "SmtpClient" nocase
    condition:
        all of them
}

rule network_smtp_raw {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$s1 = "MAIL FROM:" nocase
        $s2 = "RCPT TO:" nocase
    condition:
        all of them
}

rule network_smtp_vb {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$c1 = "CDO.Message" nocase
        $c2 = "cdoSMTPServer" nocase
        $c3 = "cdoSendUsingMethod" nocase
        $c4 = "cdoex.dll" nocase
        $c5 = "/cdo/configuration/smtpserver" nocase
    condition:
        any of them
}

rule network_p2p_win {
    meta:
        author = "x0r"
        description = "Communications over P2P network"
	version = "0.1"
    strings:
     	$c1 = "PeerCollabExportContact"
     	$c2 = "PeerCollabGetApplicationRegistrationInfo"
     	$c3 = "PeerCollabGetEndpointName"
     	$c4 = "PeerCollabGetEventData"
     	$c5 = "PeerCollabGetInvitationResponse"
     	$c6 = "PeerCollabGetPresenceInfo"
     	$c7 = "PeerCollabGetSigninOptions"
     	$c8 = "PeerCollabInviteContact"
     	$c9 = "PeerCollabInviteEndpoint"
     	$c10 = "PeerCollabParseContact"
     	$c11 = "PeerCollabQueryContactData"
     	$c12 = "PeerCollabRefreshEndpointData"
     	$c13 = "PeerCollabRegisterApplication"
     	$c14 = "PeerCollabRegisterEvent"
     	$c15 = "PeerCollabSetEndpointName"
     	$c16 = "PeerCollabSetObject"
     	$c17 = "PeerCollabSetPresenceInfo"
     	$c18 = "PeerCollabSignout"
     	$c19 = "PeerCollabUnregisterApplication"
     	$c20 = "PeerCollabUpdateContact"
    condition:
        5 of them
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
rule network_irc {
    meta:
        author = "x0r"
        description = "Communications over IRC network"
	version = "0.1"
    strings:
        $s1 = "NICK"
        $s2 = "PING"
        $s3 = "JOIN"
        $s4 = "USER"
        $s5 = "PRIVMSG"
    condition:
        all of them
}

rule network_http {
    meta:
        author = "x0r"
        description = "Communications over HTTP"
	version = "0.1"
    strings:
        $f1 = "wininet.dll" nocase
        $c1 = "InternetConnect"
        $c2 = "InternetOpen"
        $c3 = "InternetOpenUrl"
        $c4 = "InternetReadFile"
        $c5 = "InternetWriteFile"
        $c6 = "HttpOpenRequest"
        $c7 = "HttpSendRequest"
        $c8 = "IdHTTPHeaderInfo"
    condition:
        $f1 and $c1 and ($c2 or $c3) and ($c4 or $c5 or $c6 or $c7 or $c8)
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

rule network_ssl {
    meta:
        author = "x0r"
        description = "Communications over SSL"
        version = "0.1"
    strings:
        $f1 = "ssleay32.dll" nocase
        $f2 = "libeay32.dll" nocase
        $f3 = "libssl32.dll" nocase
        $c1 = "IdSSLOpenSSL" nocase
    condition:
        any of them
}

rule network_dga {
    meta:
        author = "x0r"
        description = "Communication using dga"
	version = "0.1"
    strings:
        $dll1 = "Advapi32.dll" nocase
        $dll2 = "wininet.dll" nocase
	    $dll3 = "Crypt32.dll" nocase
        $time1 = "SystemTimeToFileTime"
        $time2 = "GetSystemTime"
        $time3 = "GetSystemTimeAsFileTime"
        $hash1 = "CryptCreateHash"
        $hash2 = "CryptAcquireContext"
        $hash3 = "CryptHashData"
        $net1 = "InternetOpen"
        $net2 = "InternetOpenUrl"
        $net3 = "gethostbyname"
        $net4 = "getaddrinfo"
    condition:
        all of ($dll*) and 1 of ($time*) and 1 of ($hash*) and 1 of ($net*)
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

rule escalate_priv {
    meta:
        author = "x0r"
        description = "Escalade priviledges"
	version = "0.1"
    strings:
        $d1 = "Advapi32.dll" nocase
        $c1 = "SeDebugPrivilege"
        $c2 = "AdjustTokenPrivileges"
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule screenshot {
    meta:
        author = "x0r"
        description = "Take screenshot"
	version = "0.1"
    strings:
        $d1 = "Gdi32.dll" nocase
        $d2 = "User32.dll" nocase
        $c1 = "BitBlt"
        $c2 = "GetDC"
    condition:
        1 of ($d*) and 1 of ($c*)
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

rule dyndns {
    meta:
        author = "x0r"
        description = "Dynamic DNS"
	version = "0.1"
    strings:
        $s1 = "SOFTWARE\\Vitalwerks\\DUC" nocase
    condition:
        any of them
}

rule lookupgeo {
    meta:
        author = "x0r"
        description = "Lookup Geolocation"
	version = "0.1"
    strings:
        $n1 = "j.maxmind.com" nocase
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


rule sniff_audio {
    meta:
        author = "x0r"
        description = "Record Audio"
        version = "0.1"
    strings:
        $f1 = "winmm.dll" nocase
        $c1 = "waveInStart"
        $c2 = "waveInReset"
        $c3 = "waveInAddBuffer"
        $c4 = "waveInOpen"
        $c5 = "waveInClose"
    condition:
        $f1 and 2 of ($c*)
}

rule cred_ff {
    meta:
        author = "x0r"
        description = "Steal Firefox credential"
	version = "0.1"
    strings:
        $f1 = "signons.sqlite"
        $f2 = "signons3.txt"
        $f3 = "secmod.db"
        $f4 = "cert8.db"
        $f5 = "key3.db"
    condition:
        any of them
}

rule cred_vnc {
    meta:
        author = "x0r"
        description = "Steal VNC credential"
	version = "0.1"
    strings:
        $s1 = "VNCPassView"
    condition:
        all of them
}

rule cred_ie7 {
    meta:
        author = "x0r"
        description = "Steal IE 7 credential"
	version = "0.1"
    strings:
        $f1 = "Crypt32.dll" nocase
        $c1 = "CryptUnprotectData"
        $s1 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" nocase
    condition:
        all of them
}

rule sniff_lan {
    meta:
        author = "x0r"
        description = "Sniff Lan network traffic"
	version = "0.1"
    strings:
        $f1 = "packet.dll" nocase
        $f2 = "npf.sys" nocase
        $f3 = "wpcap.dll" nocase
        $f4 = "winpcap.dll" nocase
    condition:
        any of them
}

rule migrate_apc {
    meta:
        author = "x0r"
        description = "APC queue tasks migration"
	version = "0.1"
    strings:
        $c1 = "OpenThread"
        $c2 = "QueueUserAPC"
    condition:
        all of them
}

rule spreading_file {
    meta:
        author = "x0r"
        description = "Malware can spread east-west file"
	version = "0.1"
    strings:
        $f1 = "autorun.inf" nocase
        $f2 = "desktop.ini" nocase
        $f3 = "desktop.lnk" nocase
    condition:
        any of them
}

rule spreading_share {
    meta:
        author = "x0r"
        description = "Malware can spread east-west using share drive"
        version = "0.1"
    strings:
        $f1 = "netapi32.dll" nocase
        $c1 = "NetShareGetInfo"
        $c2 = "NetShareEnum"
    condition:
        $f1 and 1 of ($c*)
}

rule rat_vnc {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit VNC"
	version = "0.1"
    strings:
        $f1 = "ultravnc.ini" nocase
        $c2 = "StartVNC"
        $c3 = "StopVNC"
    condition:
        any of them
}

rule rat_rdp {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable RDP"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
        $p2 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
        $p3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
        $r1 = "EnableAdminTSRemote"
        $c1 = "net start termservice"
        $c2 = "sc config termservice start"
    condition:
        any of them
}

rule rat_telnet {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable Telnet"
        version = "0.1"
    strings:
        $r1 = "software\\microsoft\\telnetserver" nocase
    condition:
        any of them
}


rule rat_webcam {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit using webcam"
        version = "0.1"
    strings:
        $f1 = "avicap32.dll" nocase
        $c1 = "capCreateCaptureWindow" nocase
    condition:
        all of them
}

rule win_mutex {
    meta:
        author = "x0r"
        description = "Create or check mutex"
    version = "0.1"
    strings:
        $c1 = "CreateMutex"
    condition:
        1 of ($c*)
}

rule win_registry {
    meta:
        author = "x0r"
        description = "Affect system registries"
    version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "RegQueryValueExA"
        $c2 = "RegOpenKeyExA"
        $c3 = "RegCloseKey"
        $c4 = "RegSetValueExA"
        $c5 = "RegCreateKeyA"
        $c6 = "RegCloseKey"
    condition:
        $f1 and 1 of ($c*)
}

rule win_token {
    meta:
        author = "x0r"
        description = "Affect system token"
    version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "DuplicateTokenEx"
        $c2 = "AdjustTokenPrivileges"
        $c3 = "OpenProcessToken"
        $c4 = "LookupPrivilegeValueA"
    condition:
        $f1 and 1 of ($c*)
}

rule win_private_profile {
    meta:
        author = "x0r"
        description = "Affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "GetPrivateProfileIntA"
        $c2 = "GetPrivateProfileStringA"
        $c3 = "WritePrivateProfileStringA"
    condition:
        $f1 and 1 of ($c*)
}

rule win_files_operation {
    meta:
        author = "x0r"
        description = "Affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "WriteFile"
        $c2 = "SetFilePointer"
        $c3 = "WriteFile"
        $c4 = "ReadFile"
        $c5 = "DeleteFileA"
        $c6 = "CreateFileA"
        $c7 = "FindFirstFileA"
        $c8 = "MoveFileExA"
        $c9 = "FindClose"
        $c10 = "SetFileAttributesA"
        $c11 = "CopyFile"

    condition:
        $f1 and 3 of ($c*)
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
// High FP rate
rule persistence_autorun {
    meta:
        author = "x0r"
        description = "Install itself for autorun at Windows startup"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $p2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $p3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase
        $p4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" nocase
        $p5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $p6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" nocase
        $p7 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" nocase
        $p8 = "SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\Windows" nocase
        $p9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler" nocase
        $p10 = "comfile\\shell\\open\\command" nocase
        $p11 = "piffile\\shell\\open\\command" nocase
        $p12 = "exefile\\shell\\open\\command" nocase
        $p13 = "txtfile\\shell\\open\\command" nocase
	$p14 = "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        $f1 = "win.ini" nocase
        $f2 = "system.ini" nocase
        $f3 = "Start Menu\\Programs\\Startup" nocase
    condition:
        any of them
}
]==]
-- #endregion

-- #region bad_rules
bad_rules = [==[
import "pe"
rule bitcoin {
    meta:
        author = "x0r"
        description = "Perform crypto currency mining"
	version = "0.1"
    strings:
        $f1 = "OpenCL.dll" nocase
        $f2 = "nvcuda.dll" nocase
        $f3 = "opengl32.dll" nocase
        $s1 = "cpuminer 2.2.2X-Mining-Extensions"
        $s2 = "cpuminer 2.2.3X-Mining-Extensions"
	    $s3 = "Ufasoft bitcoin-miner/0.20"
	    $s4 = "bitcoin" nocase
	    $s5 = "stratum" nocase
    condition:
        1 of ($f*) and 1 of ($s*)
}
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
rule apt_auriga_biscuit
{
	 meta:
		 description = "Auriga | biscuit"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "6B31344B40E2AF9C9EE3BA707558C14E"

	 strings:

	 	$pdb = "\\drizt\\projects\\auriga\\branches\\stone_~1\\server\\exe\\i386\\riodrv32.pdb"

	 condition:

	 	any of them
}
rule apt_babar_pdb
{
	 meta:
		 description = "APT Babar"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "9FFF114F15B86896D8D4978C0AD2813D"

	 strings:

	 	$pdb = "\\Documents and Settings\\admin\\Desktop\\Babar64\\Babar64\\ obj\\DllWrapper Release\\Release.pdb"

	 condition:

	 	any of them
}
rule apt_blackenergy_pdb
{
	 meta:
		 description = "APT Blackenergy PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "FD111A5496B6336B8503AE02FFA04E28"

	 strings:

	 	$pdb = "\\CB\\11X_Security\\Acrobat\\Installers\\BootStrapExe_Small\\Release\\Setup.pdb"

	 condition:

	 	any of them
}
rule apt_nix_elf_derusbi
{

    meta:

      description = "Rule to detect the APT Derusbi ELF file"
      author = "Marc Rivero | McAfee ATR Team"

    strings:
        $ = "LxMain"
        $ = "execve"
        $ = "kill"
        $ = "cp -a %s %s"
        $ = "%s &"
        $ = "dbus-daemon"
        $ = "--noprofile"
        $ = "--norc"
        $ = "TERM=vt100"
        $ = "/proc/%u/cmdline"
        $ = "loadso"
        $ = "/proc/self/exe"
        $ = "Proxy-Connection: Keep-Alive"
        $ = "Connection: Keep-Alive"
        $ = "CONNECT %s"
        $ = "HOST: %s:%d"
        $ = "User-Agent: Mozilla/4.0"
        $ = "Proxy-Authorization: Basic %s"
        $ = "Server: Apache"
        $ = "Proxy-Authenticate"
        $ = "gettimeofday"
        $ = "pthread_create"
        $ = "pthread_join"
        $ = "pthread_mutex_init"
        $ = "pthread_mutex_destroy"
        $ = "pthread_mutex_lock"
        $ = "getsockopt"
        $ = "socket"
        $ = "setsockopt"
        $ = "select"
        $ = "bind"
        $ = "shutdown"
        $ = "listen"
        $ = "opendir"
        $ = "readdir"
        $ = "closedir"
        $ = "rename"

    condition:
        (uint32(0) == 0x4464c457f) and (all of them)
}

rule apt_nix_elf_derusbi_kernelModule
{

    meta:
      description = "Rule to detect the Derusbi ELK Kernel module"
      author = "Marc Rivero | McAfee ATR Team"

    strings:
        $ = "__this_module"
        $ = "init_module"
        $ = "unhide_pid"
        $ = "is_hidden_pid"
        $ = "clear_hidden_pid"
        $ = "hide_pid"
        $ = "license"
        $ = "description"
        $ = "srcversion="
        $ = "depends="
        $ = "vermagic="
        $ = "current_task"
        $ = "sock_release"
        $ = "module_layout"
        $ = "init_uts_ns"
        $ = "init_net"
        $ = "init_task"
        $ = "filp_open"
        $ = "__netlink_kernel_create"
        $ = "kfree_skb"

    condition:
        (uint32(0) == 0x4464c457f) and (all of them)
}

rule apt_nix_elf_Derusbi_Linux_SharedMemCreation
{

    meta:
      description = "Rule to detect Derusbi Linux Shared Memory creation"
      author = "Marc Rivero | McAfee ATR Team"

    strings:
        $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

    condition:
        (uint32(0) == 0x464C457F) and (any of them)
}

rule apt_nix_elf_Derusbi_Linux_Strings
{

    meta:
      description = "Rule to detect APT Derusbi Linux Strings"
      author = "Marc Rivero | McAfee ATR Team"

    strings:
        $a1 = "loadso" wide ascii fullword
        $a2 = "\nuname -a\n\n" wide ascii
        $a3 = "/dev/shm/.x11.id" wide ascii
        $a4 = "LxMain64" wide ascii nocase
        $a5 = "# \\u@\\h:\\w \\$ " wide ascii
        $b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
        $b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
        $b3 = "ret %d" wide fullword
        $b4 = "uname -a\n\n" wide ascii
        $b5 = "/proc/%u/cmdline" wide ascii
        $b6 = "/proc/self/exe" wide ascii
        $b7 = "cp -a %s %s" wide ascii
        $c1 = "/dev/pts/4" wide ascii fullword
        $c2 = "/tmp/1408.log" wide ascii fullword

    condition:
        uint32(0) == 0x464C457F and ((1 of ($a*) and 4 of ($b*)) or (1 of ($a*) and 1 of ($c*)) or 2 of ($a*) or all of ($b*))
}

rule apt_win_exe_trojan_derusbi
{

   meta:
      description = "Rule to detect Derusbi Trojan"
      author = "Marc Rivero | McAfee ATR Team"

   strings:
        $sa_1 = "USB" wide ascii
        $sa_2 = "RAM" wide ascii
        $sa_3 = "SHARE" wide ascii
        $sa_4 = "HOST: %s:%d"
        $sa_5 = "POST"
        $sa_6 = "User-Agent: Mozilla"
        $sa_7 = "Proxy-Connection: Keep-Alive"
        $sa_8 = "Connection: Keep-Alive"
        $sa_9 = "Server: Apache"
        $sa_10 = "HTTP/1.1"
        $sa_11 = "ImagePath"
        $sa_12 = "ZwUnloadDriver"
        $sa_13 = "ZwLoadDriver"
        $sa_14 = "ServiceMain"
        $sa_15 = "regsvr32.exe"
        $sa_16 = "/s /u" wide ascii
        $sa_17 = "rand"
        $sa_18 = "_time64"
        $sa_19 = "DllRegisterServer"
        $sa_20 = "DllUnregisterServer"
        $sa_21 = { 8b [5] 8b ?? d3 ?? 83 ?? 08 30 [5] 40 3b [5] 72 } // Decode Driver
        $sb_1 = "PCC_CMD_PACKET"
        $sb_2 = "PCC_CMD"
        $sb_3 = "PCC_BASEMOD"
        $sb_4 = "PCC_PROXY"
        $sb_5 = "PCC_SYS"
        $sb_6 = "PCC_PROCESS"
        $sb_7 = "PCC_FILE"
        $sb_8 = "PCC_SOCK"
        $sc_1 = "bcdedit -set testsigning" wide ascii
        $sc_2 = "update.microsoft.com" wide ascii
        $sc_3 = "_crt_debugger_hook" wide ascii
        $sc_4 = "ue8G5" wide ascii
        $sd_1 = "NET" wide ascii
        $sd_2 = "\\\\.\\pipe\\%s" wide ascii
        $sd_3 = ".dat" wide ascii
        $sd_4 = "CONNECT %s:%d" wide ascii
        $sd_5 = "\\Device\\" wide ascii
        $se_1 = "-%s-%04d" wide ascii
        $se_2 = "-%04d" wide ascii
        $se_3 = "FAL" wide ascii
        $se_4 = "OK" wide ascii
        $se_5 = "2.03" wide ascii
        $se_6 = "XXXXXXXXXXXXXXX" wide ascii

   condition:
      (uint16(0) == 0x5A4D) and ( (all of ($sa_*)) or ((13 of ($sa_*)) and ( (5 of ($sb_*)) or (3 of ($sc_*)) or (all of ($sd_*)) or ( (1 of ($sc_*)) and (all of ($se_*)) ) ) ) )
}

rule elise_apt_pdb
{
	 meta:

	 description = "Rule to detect Elise APT based on the PDB reference"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "6F81C7AF2A17ECE3CF3EFFC130CE197A"
	 hash = "46877B923AE292C1E7C66E4F6F390AF7"
	 hash = "268A4D1679AE0DA89AB4C16A3A89A8F1"
	 hash = "A17CDAF23A84A3E410852B18BF5A47CD"
	 hash = "36BB0B614D9118679A635735E53B32AB"

	 strings:

		 $pdb = "\\lstudio\\projects\\lotus\\elise\\Release\\EliseDLL\\i386\\EliseDLL.pdb"
		 $pdb1 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\SetElise.pdb"
		 $pdb2 = "\\lstudio\\projects\\lotus\\elise\\Release\\SetElise\\i386\\SetElise.pdb"
		 $pdb3 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\Uninstaller.pdb"
		 $pdb4 = "\\lstudio\\projects\\lotus\\evora\\Release\\EvoraDLL\\i386\\EvoraDLL.pdb"

	 condition:

	 	any of them
}
rule apt_gdocupload_glooxmail
{
	 meta:
		 description = "Rule to detect the tool gdocupload based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "232D1BE2D8CBBD1CF57494A934628504"

	 strings:

	 	$pdb = "\\Project\\mm\\Webmail\\Bin\\gdocs.pdb"

	 condition:

	 	any of them
}
rule apt_hanover_pdb
{
	 meta:
	 description = "Rule to detect hanover samples based on PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "32C0785EDD5C9840F55A8D40E53ED3D9"
	 hash = "0BBE6CAB66D76BAB4B44874DC3995D8F"
	 hash = "350AD4DB3BCACF3C15117AFDDF0BD273"
	 hash = "158FF697F8E609316E2A9FBE8111E12A"
	 hash = "24874938F44D34AF71C91C011A5EBC45"
	 hash = "3166C70BF2F70018E4702673520B333B"
	 hash = "FE2CBAB386B534A10E71A5428FDE891A"
	 hash = "4A06163A8E7B8EEAE835CA87C1AB6784"
	 hash = "C7CB3EC000AC99DA19D46E008FD2CB73"
	 hash = "2D7D9CB08DA17A312B64819770098A8E"
	 hash = "74125D375B236059DC144567C9481F2A"
	 hash = "EDDD399D3A1E3A55B97665104C83143B"
	 hash = "54435E2D3369B4395A336389CF49A8BE"
	 hash = "232F616AD81F4411DD1806EE3B8E7553"
	 hash = "645801262AEB0E33D6CA1AF5DD323E25"


 strings:

	 $pdb = "\\andrew\\Key\\Release\\Keylogger_32.pdb"
	 $pdb1 = "\\BACK_UP_RELEASE_28_1_13\\General\\KG\\Release\\winsvcr.pdb"
	 $pdb2 = "\\BackUP-Important\\PacketCapAndUpload_Backup\\voipsvcr\\Release\\voipsvcr.pdb"
	 $pdb3 = "\\BNaga\\kaam\\New_FTP_2\\Release\\ftpback.pdb"
	 $pdb4 = "\\DD0\\DD\\u\\Release\\dataup.pdb"
	 $pdb5 = "\\Documents and Settings\\Admin\\Desktop\\Newuploader\\Release\\Newuploader.pdb"
	 $pdb6 = "\\Documents and Settings\\Admin\\Desktop\\Uploader Code\\Release\\Newuploader.pdb"
	 $pdb7 = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
	 $pdb8 = "\\smse\\Debug\\smse.pdb"
	 $pdb9 = "\\Users\\admin\\Documents\\Visual Studio 2008\\Projects\\DNLDR-no-ip\\Release\\DNLDR.pdb"
	 $pdb10 = "\\final exe\\check\\Release\\check.pdb"
	 $pdb11 = "\\Projects\\Elance\\AppInSecurityGroup\\FtpBackup\\Release\\Backup.pdb"
	 $pdb12 = "\\projects\\windows\\MailPasswordDecryptor\\Release\\MailPasswordDecryptor.pdb"
	 $pdb13 = "\\final project backup\\UPLODER FTP BASED\\New folder\\Tron 1.2.1(Ftp n Startup)\\Release\\Http_t.pdb"

 condition:

 	any of them
}

rule apt_hanover_appinbot_pdb
{
	 meta:

		 description = "Rule to detect hanover appinbot samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "350AD4DB3BCACF3C15117AFDDF0BD273"
		 hash = "49527C54A80E1BA698E0A8A7F7DD0A7D"
		 hash = "36B3F39E7A11636ADB29FE36BEA875C4"
		 hash = "BB9974D1C3617FCACF5D2D04D11D8C5A"
		 hash = "4F82A6F5C80943AF7FACFCAFB7985C8C"
		 hash = "4F82A6F5C80943AF7FACFCAFB7985C8C"
		 hash = "549FED3D2DD640155697DEF39F7AB819"
		 hash = "549FED3D2DD640155697DEF39F7AB819"
		 hash = "36B3F39E7A11636ADB29FE36BEA875C4"
		 hash = "3FD48F401EDF2E20F1CA11F3DAE3E2EF"
		 hash = "3FD48F401EDF2E20F1CA11F3DAE3E2EF"
		 hash = "8A4F2B2316A7D8D1938431477FEBF096"
		 hash = "5BDA43ED20EA6A061E7332E2646DDC40"

	 strings:

		 $pdb = "\\BNaga\\backup_28_09_2010\\threads tut\\pen-backup\\BB_FUD_23\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb1 = "\\BNaga\\SCode\\BOT\\MATRIX_1.2.2.0\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb2 = "\\Documents and Settings\\Admin\\Desktop\\appinbot_1.2_120308\\appinclient\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb3 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\ CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb4 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\ MATRIX_1.3.4\\CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb5 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\MATRIX_1.3.4\\ CLIENT\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb6 = "\\pen-backup\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb7 = "\\pen-backup\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb8 = "\\temp\\elance\\PROTOCOL_1.2\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb9 = "\\Users\\PRED@TOR\\Desktop\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb10 = "\\Users\\PRED@TOR\\Desktop\\MODIFIED PROJECT LAB\\admin\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb11 = "\\Desktop backup\\Copy\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb12 = "\\Datahelp\\SCode\\BOT\\MATRIX_1.3.3\\CLIENT\\Build\\Win32\\Release\\appinclient.pdb"

 	condition:

		any of them
}

rule apt_hanover_foler_pdb
{
	 meta:
		 description = "Rule to detect hanover foler samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "07DEFD4BDA646B1FB058C3ABD2E1128E"
		 hash = "01A7AF987D7B2F6F355E37C8580CB45A"
		 hash = "118716061197EBCDAE25D330AEF97267"
		 hash = "01A7AF987D7B2F6F355E37C8580CB45A"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb"
		 $pdb2 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\UsbP - u\\Release\\UsbP.pdb"
		 $pdb3 = "\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb"

	 condition:

	 	any of them
}

rule apt_hanover_linog_pdb
{
	 meta:
		 description = "Rule to detect hanover linog samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "16C140FB61B6D22E02AA2B04748B5A34"
		 hash = "8B1A208216613BF0B931252A98D5E2B8"

	 strings:

		 $pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		 $pdb1 = "\\Backup-HP-ABCD-PC\\download\\Release\\download.pdb"

	 condition:

	 	any of them
}

rule apt_hanover_ron_babylon_pdb
{
	 meta:
		 description = "apt_hanover_ron_babylon"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "4B9F8CB4D87672611F11ACBE3E204249"
		 hash = "9073B3DB88720A555AC511956A11ABF4"
		 hash = "4B9F8CB4D87672611F11ACBE3E204249"
		 hash = "81F84B1BDF6337A6E9C67BE2F51C50E0"
		 hash = "E3CF3B1D2A695B9B5046692A607C8B30"
		 hash = "80FBEBA3DA682570C4DB0482CD61B27D"
		 hash = "0F98B7D1E113E5194D62BC8F20720A6B"
		 hash = "376A0ED56366E4D35CECFCDBD70204B0"
		 hash = "33840EE0B45F31081393F4462FB7A5B6"
		 hash = "423519AE6C222AB54A2E82104FA45D12"
		 hash = "0B88F197B4266E6B78EA0DCB9B3496E9"
		 hash = "9E05D3F072469093542AFDDB1C2E874E"
		 hash = "118ED6F8AA3F01428A95AE7BA8EF195C"
		 hash = "5433804B7FC4D71C47AA2B3DA64DB77D"
		 hash = "555D401E2D41ED00BC9436E3F458B52E"
		 hash = "32D461D46D30C5D7C3F8D29DD0C8A8C4"
		 hash = "7E74334C1495A3F6E195CE590C7D42E5"
		 hash = "F6AB2B8ADBB2EB8A5D2F067841B434EF"
		 hash = "331DB34E5F49AC1E318DDA2D01633B43"
		 hash = "89D9851C162B98DB2C7A2B4F6A841B2A"
		 hash = "DE81F0BDBD0EF134525BCE20B05ED664"
		 hash = "0FBC01C38608D1B5849BF47492148588"
		 hash = "4921C4C5CDD58CA32C5E957B63CF06CD"
		 hash = "7244AAA1497D16E101AD1B6DEE05DFE3"
		 hash = "5BC2744A40A333DC089AC04B6D71154E"
		 hash = "0128F683E508C807EC76D5092EAAF22C"
		 hash = "B48C2E42514AE1395E28FC94F6C8A6F1"
		 hash = "A487E68A4C7EC11EBFF428BECC64A06C"
		 hash = "E5479FAC44383CA1998EB416AA2128F0"
		 hash = "30A920F8C9B52AA8C68501F502E128EB"
		 hash = "FC0F714D16B1A72FCC6719151E85A8F0"
		 hash = "9BCB294ECFBEBFF744E2A50B3F7099E6"
		 hash = "0E9E46D068FEA834E12B2226CC8969FD"
		 hash = "1CE331F0D11DC20A776759A60FB5B3F5"
		 hash = "26FE2770B4F0892E0A24D4DDDBBFE907"
		 hash = "C814E35D26848F910DD5106B886B9401"
		 hash = "EEEF49FDB64A03A0C932973F117F9056"
		 hash = "A8CAF03B50C424E9639580CDCC28507B"
		 hash = "A1F8595D6D191DCBED3D257301869CE9"
		 hash = "EA9BFC25FC5BDC0B1B96F7B2AF64F1AC"
		 hash = "153AC7591B9326EE63CD36180D39665E"
		 hash = "37448F390F10ECCF5745A6204947203A"
		 hash = "770FC76673C3C2DAADD54C7AA7BA7CC3"
		 hash = "BA790AC25BB9C3C6259FDFF8DCE07E5A"
		 hash = "135A18C858BFDC5FC660F15D6E1FB147"
		 hash = "D8DCF2A53505A61B5915F7A1D7440A2E"

 strings:

		 $pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		 $pdb1 = "\\26_10_2010\\demoMusic\\Release\\demoMusic.pdb"
		 $pdb2 = "\\26_10_2010\\New_FTP_HttpWithLatestfile2\\Release\\httpbackup.pdb"
		 $pdb3 = "\\26_10_2010\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\FirstBloodA1.pdb"
		 $pdb4 = "\\app\\Http_t\\Release\\Crveter.pdb"
		 $pdb5 = "\\BNaga\\kaam\\Appin SOFWARES\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb6 = "\\BNaga\\kaam\\kaam\\NEW SOFWARES\\firstblood\\Release\\FirstBloodA1.pdb"
		 $pdb7 = "\\BNaga\\kaam\\kaam\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\Ron.pdb"
		 $pdb8 = "\\BNaga\\kaam\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\FirstBloodA1.pdb"
		 $pdb9 = "\\BNaga\\My Office kaam\\Appin SOFWARES\\HTTP\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb10 = "\\Documents and Settings\\abc\\Desktop\\Dragonball 1.0.2(WITHOUT DOWNLOAD LINK)\\Release\\Ron.pdb"
		 $pdb11 = "\\Documents and Settings\\Administrator\\Desktop\\Feb 2012\\kmail(httpform1.1) 02.09\\Release\\kmail.pdb"
		 $pdb12 = "\\MNaga\\My Office kaam\\Appin SOFWARES\\HTTP\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb13 = "\\N\\kl\\Release\\winlsa.pdb"
		 $pdb14 = "\\N\\sr\\Release\\waulct.pdb"
		 $pdb15 = "\\Release\\wauclt.pdb"
		 $pdb16 = "\\Users\\neeru rana\\Desktop\\Klogger- 30 may\\Klogger- 30 may\\Release\\Klogger.pdb"
		 $pdb17 = "\\december task backup\\TRINITY PAYLOAD\\Dragonball 1.0.0(WITHOUT DOWNLOAD LINK)\\Release\\Ron.pdb"
		 $pdb18 = "\\Documents and Settings\\appin\\Desktop\\New_FTP_1\\New_FTP_1\\Release\\HTTP_MyService.pdb"
		 $pdb19 = "\\May Payload\\new keylogger\\Flashdance1.0.2\\kmail(http) 01.20\\Release\\kmail.pdb"
		 $pdb20 = "\\Monthly Task\\September 2011\\HangOver 1.3.2 (Startup)\\Release\\Http_t.pdb"
		 $pdb21 = "\\Sept 2012\\Keylogger\\Release\\Crveter.pdb"
		 $pdb22 = "\\Datahelp\\keytest1\\keytest\\taskmng.pdb"
		 $pdb23 = "\\Datahelp\\UPLO\\HTTP\\HTTP_T\\17_05_2011\\Release\\Http_t.pdb"
		 $pdb24 = "\\Datahelp\\UPLO\\HTTP\\HTTP_T\\20_05_2011\\Release\\Http_t.pdb"
		 $pdb25 = "\\June mac paylods\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\Klogger.pdb"
		 $pdb26 = "\\June mac paylods\\Keylo ger backup\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\kquant.pdb"
		 $pdb27 = "\\June mac paylods\\Keylogger backup\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\kquant.pdb"
		 $pdb28 = "\\My\\lan scanner\\Task\\HangOver 1.2.2\\Release\\Http_t.pdb"
		 $pdb29 = "\\New folder\\paylod backup\\OTHER\\Uploder\\HangOver 1.5.7 (Startup)\\HangOver 1.5.7 (Startup)\\Release\\Http_t.pdb"
		 $pdb30 = "\\keyloger\\KeyLog\\keytest1\\keytest\\taskmng.pdb"
		 $pdb31 = "\\august\\13 aug\\HangOver 1.5.7 (Startup) uploader\\Release\\Http_t.pdb"
		 $pdb32 = "\\backup E\\SourceCodeBackup\\september\\aradhana\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb33 = "\\payloads\\new backup feb\\SUNDAY\\kmail(http) 01.20\\kmail(http) 01.20\\Release\\kmail.pdb"
		 $pdb34 = "\\payloads\\ita nagar\\Uploader\\HangOver 1.5.7 (Startup)\\HangOver 1.5.7 (Startup)\\Release\\Http_t.pdb"
		 $pdb35 = "\\final project backup\\task information\\task of september\\Tourist 2.4.3 (Down Link On Resource) -L\\Release\\Ron.pdb"
		 $pdb36 = "\\final project backup\\complete task of ad downloader & usb grabber&uploader\\New folder\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb37 = "\\final project backup\\uploader version backup\\fud all av hangover1.5.4\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb38 = "\\final project backup\\uploader version backup\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb39 = "\\New folder\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb40 = "\\Http uploader limited account\\Http uploader limited account\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb41 = "\\Uploader\\HTTP\\HTTP Babylon 5.1.1\\HTTP Babylon 5.1.1\\Httpbackup\\Release\\HttpUploader.pdb"
		 $pdb42 = "\\Uploader\\HTTP\\ron uplo\\RON 2.0.0\\Release\\Ron.pdb"

 	condition:

 		any of them
}

rule apt_hanover_slidewin_pdb
{
	 meta:

		 description = "Rule to detect hanover slidewin samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "32DD4DEBED737BF2692796E6DCA7D115"
		 hash = "97BDE23AE78DDABC36A0A46A4E5B1FAE"
		 hash = "CB22FB4E06F7D02F8CAC1350D34CA0A6"
		 hash = "34B013D36146BA868E4DFA51529C47A4"

	 strings:

		 $pdb = "\\Users\\God\\Desktop\\ThreadScheduler-aapnews-Catroot2\\Release\\ThreadScheduler.pdb"
		 $pdb1 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-hostzi\\Release\\slidebar.pdb"
		 $pdb2 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-spectram\\Release\\slidebar.pdb"
		 $pdb3 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-zendossier\\Release\\slidebar.pdb"

	 condition:

	 	any of them
}
rule apt_hikit_rootkit
{
	 meta:
		 description = "Rule to detect the rootkit hikit based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"

	 strings:

		 $pdb = "\\JmVodServer\\hikit\\bin32\\RServer.pdb"
		 $pdb1 = "\\JmVodServer\\hikit\\bin32\\w7fw.pdb"
		 $pdb2 = "\\JmVodServer\\hikit\\bin32\\w7fw_2k.pdb"
		 $pdb3 = "\\JmVodServer\\hikit\\bin64\\w7fw_x64.pdb"

	 condition:

	 	any of them
}
rule karkoff_dnspionaje {

   meta:

      description = "Rule to detect the Karkoff malware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"

   strings:

      $s1 = "DropperBackdoor.Newtonsoft.Json.dll" fullword wide
      $s2 = "C:\\Windows\\Temp\\MSEx_log.txt" fullword wide
      $s3 = "DropperBackdoor.exe" fullword wide
      $s4 = "get_ProcessExtensionDataNames" fullword ascii
      $s5 = "get_ProcessDictionaryKeys" fullword ascii
      $s6 = "https://www.newtonsoft.com/json 0" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of them
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

rule lagulon_trojan_pdb
{
	 meta:
	 description = "Rule to detect trojan Lagulon based on PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "e8b1f23616f9d8493e8a1bf0ca0f512a"

 strings:

 	$pdb = "\\proj\\wndTest\\Release\\wndTest.pdb"

 condition:

 	any of them
}
rule manitsme_trojan
{
	 meta:
		 description = "Rule to detect Manitsme based on PDB"
		 author = "Marc Rivero Lopez"
		 hash = "E97EBB5B2050B86999C55797C2348BA7"

	 strings:

	 	$pdb = "\\rouji\\SvcMain.pdb"

	 condition:

	 	any of them
}
rule MiniASP_PDB
{
	 meta:
		 description = "Rule to detect MiniASP based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "026C1532DB8125FBAE0E6AA1F4033F42"
		 hash = "77FBFED235D6062212A3E43211A5706E"

	 strings:
		 $pdb = "\\Project\\mm\\Wininet\\Attack\\MiniAsp4\\Release\\MiniAsp.pdb"
		 $pdb1 = "\\XiaoME\\AiH\\20120410\\Attack\\MiniAsp3\\Release\\MiniAsp.pdb"

	 condition:

	 	any of them
}
rule Mirage_PDB
{
		 meta:
		 description = "Rule to detect Mirage samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "5FA26F410D0133F4152EA78DF3978C22"
		 hash = "1045E26819FF782015202838E2C609F7"

	 strings:

		 $pdb = "\\MF-v1.2\\Server\\Debug\\Server.pdb"
		 $pdb1 = "\\fox_1.2 20110307\\MF-v1.2\\Server\\Release\\MirageFox_Server.pdb"

	condition:

		any of them
}
rule apt_aurora_pdb_samples
{
	 meta:
	 description = "Aurora APT Malware 2006-2010"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "467EEF090DEB3517F05A48310FCFD4EE"
	 hash = "4A47404FC21FFF4A1BC492F9CD23139C"

 strings:

	 $pdb = "\\AuroraVNC\\VedioDriver\\Release\\VedioDriver.pdb"
	 $pdb1 = "\\Aurora_Src\\AuroraVNC\\Avc\\Release\\AVC.pdb"

 condition:

 	any of them
}

rule shadowspawn_utility {

   meta:

      description = "Rule to detect ShadowSpawn utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $x1 = "C:\\data\\projects\\shadowspawn\\src\\bin\\Release-W2K3\\x64\\ShadowSpawn.pdb" fullword ascii
      $op0 = { e9 34 ea ff ff cc cc cc cc 48 8d 8a 20 }
      $op1 = { 48 8b 85 e0 06 00 00 48 8d 34 00 48 8d 46 02 48 }
      $op2 = { e9 34 c1 ff ff cc cc cc cc 48 8b 8a 68 }

   condition:

      uint16(0) == 0x5a4d and filesize < 200KB and
      ( pe.imphash() == "eaae87b11d2ebdd286af419682037b4c" and all of them)
}

rule poison_ivy_softcell {

   meta:

      description = "Rule to detect Poison Ivy used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $x1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s6 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s7 = "&Enter password for the encrypted file:" fullword wide
      $s8 = "start \"\" \"%CD%\\mcoemcpy.exe\"" fullword ascii
      $s9 = "setup.bat" fullword ascii
      $s10 = "ErroraErrors encountered while performing the operation" fullword wide
      $s11 = "Please download a fresh copy and retry the installation" fullword wide
      $s12 = "antivir.dat" fullword ascii
      $s13 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
      $s14 = "=Total path and file name length must not exceed %d characters" fullword wide
      $s15 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide
      $op0 = { e8 6f 12 00 00 84 c0 74 04 32 c0 eb 34 56 ff 75 }
      $op1 = { 53 68 b0 34 41 00 57 e8 61 44 00 00 57 e8 31 44 }
      $op2 = { 56 ff 75 08 8d b5 f4 ef ff ff e8 17 ff ff ff 8d }

   condition:

      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "dbb1eb5c3476069287a73206929932fd" and all of them)
}

rule trochilus_softcell {
   meta:
      description = "Rule to detect Trochilus malware used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s1 = "Shell.dll" fullword ascii
      $s2 = "photo.dat" fullword wide
      $s3 = "VW9HxtV9H|tQ9" fullword ascii
      $s4 = "G6uEGRich7uEG" fullword ascii
      $op0 = { e8 9d ad ff ff ff b6 a8 }
      $op1 = { e8 d4 ad ff ff ff b6 94 }
      $op2 = { e8 ea ad ff ff ff b6 8c }

   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( pe.imphash() == "8e13ebc144667958722686cb04ee16f8" and ( pe.exports("Entry") and pe.exports("Main") ) and  all of them )
}

rule lg_utility_lateral_movement_softcell {
   meta:
      description = "Rule to detect the utility LG from Joeware to do Lateral Movement in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s1 = "lg \\\\comp1\\users louise -add -r comp3" fullword ascii
      $s2 = "lg \\\\comp1\\users S-1-5-567-678-89765-456 -sid -add" fullword ascii
      $s3 = "lg \\\\comp1\\users -sidsout" fullword ascii
      $s4 = "Enumerates members of localgroup users on localhost" fullword ascii
      $s5 = "Adds SID resolved at comp3 for louise to localgroup users on comp1" fullword ascii
      $s6 = "CodeGear C++ - Copyright 2008 Embarcadero Technologies" fullword ascii
      $s7 = "Lists members of localgroup users on comp1 in SID format" fullword ascii
      $s8 = "ERROR: Verify that CSV lines are available in PIPE input. " fullword ascii
      $op0 = { 89 43 24 c6 85 6f ff ff ff 00 83 7b 24 10 72 05 }
      $op1 = { 68 f8 0e 43 00 e8 8d ff ff ff 83 c4 20 68 f8 0e }
      $op2 = { 66 c7 85 74 ff ff ff 0c 00 8d 55 d8 52 e8 e9 eb }

   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "327ce3f883a5b59e966b5d0e3a321156" and all of them )
}

rule mangzamel_softcell {

   meta:

      description = "Rule to detect Mangzamel used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s1 = "Change Service Mode to user logon failure.code:%d" fullword ascii
      $s2 = "spoolsvs.exe" fullword wide
      $s3 = "System\\CurrentControlSet\\Services\\%s\\parameters\\%s" fullword ascii
      $s19 = "Please Correct [-s %s]" fullword ascii
      $s20 = "Please Correct [-m %s]" fullword ascii
      $op0 = { 59 8d 85 64 ff ff ff 50 c7 85 64 ff ff ff 94 }
      $op1 = { c9 c2 08 00 81 c1 30 34 00 00 e9 cf 9b ff ff 55 }
      $op2 = { 80 0f b6 b5 68 ff ff ff c1 e2 04 0b d6 0f b6 b5 }

   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "ef64bb4aa42ef5a8a2e3858a636bce40" and all of them )
}
rule nbtscan_utility_softcell {
   meta:
      description = "Rule to detect nbtscan utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s2 = "nbtscan 1.0.35 - 2008-04-08 - http://www.unixwiz.net/tools/" fullword ascii
      $s10 = "parse_target_cb.c" fullword ascii
      $s11 = "ranges. Ranges can be in /nbits notation (\"192.168.12.0/24\")" fullword ascii
      $s12 = "or with a range in the last octet (\"192.168.12.64-97\")" fullword ascii
      $op0 = { 52 68 d4 66 40 00 8b 85 58 ff ff ff 50 ff 15 a0 }
      $op1 = { e9 1c ff ff ff 8b 45 fc 8b e5 5d c3 cc cc cc cc }
      $op2 = { 59 59 c3 8b 65 e8 ff 75 d0 ff 15 34 60 40 00 ff }

   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( pe.imphash() == "2fa43c5392ec7923ababced078c2f98d" and all of them )
}

rule mimikatz_utility_softcell {
   meta:
      description = "Rule to detect Mimikatz utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"

   strings:
      $x1 = "livessp.dll" fullword wide
      $x2 = "\\system32\\tapi32.dll" fullword wide
      $s3 = " * Process Token : " fullword wide
      $s4 = "lsadump" fullword wide
      $s5 = "-nl - skip lsa dump..." fullword wide
      $s6 = "lsadump::sam" fullword wide
      $s7 = "lsadump::lsa" fullword wide
      $s8 = "* NL$IterCount %u, %u real iter(s)" fullword wide
      $s9 = "* Iter to def (%d)" fullword wide
      $s10 = " * Thread Token  : " fullword wide
      $s11 = " * RootKey  : " fullword wide
      $s12 = "lsadump::cache" fullword wide
      $s13 = "sekurlsa::logonpasswords" fullword wide
      $s14 = "(commandline) # %s" fullword wide
      $s15 = ">>> %s of '%s' module failed : %08x" fullword wide
      $s16 = "UndefinedLogonType" fullword wide
      $s17 = " * Username : %wZ" fullword wide
      $s18 = "logonPasswords" fullword wide
      $s19 = "privilege::debug" fullword wide
      $s20 = "token::elevate" fullword wide
      $op0 = { e8 0b f5 00 00 90 39 35 30 c7 02 00 75 34 48 8b }
      $op1 = { eb 34 48 8b 4d cf 48 8d 45 c7 45 33 c9 48 89 44 }
      $op2 = { 48 3b 0d 34 26 01 00 74 05 e8 a9 31 ff ff 48 8b }

   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "169e02f00c6fb64587297444b6c41ff4" and all of them )
}

rule sfx_winrar_plugx {

   meta:

      description = "Rule to detect the SFX WinRAR delivering a possible Plugx sample"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $x1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s2 = "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide
      $s3 = "mcutil.dll" fullword ascii
      $s4 = "Unexpected end of archiveThe file \"%s\" header is corrupt%The archive comment header is corrupt" fullword wide
      $s5 = "mcoemcpy.exe" fullword ascii
      $s6 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s7 = "&Enter password for the encrypted file:" fullword wide
      $s8 = "start \"\" \"%CD%\\mcoemcpy.exe\"" fullword ascii
      $s9 = "setup.bat" fullword ascii
      $s10 = "ErroraErrors encountered while performing the operation" fullword wide
      $s11 = "Please download a fresh copy and retry the installation" fullword wide
      $s12 = "antivir.dat" fullword ascii
      $s13 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
      $s14 = "=Total path and file name length must not exceed %d characters" fullword wide
      $s15 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide
      $s16 = "folder is not accessiblelSome files could not be created." fullword wide
      $s17 = "Packed data CRC failed in %s" fullword wide
      $s18 = "DDTTDTTDTTDTTDTTDTTDTTDTTDTQ" fullword ascii
      $s19 = "File close error" fullword wide
      $s20 = "CRC failed in %s" fullword wide
      $op0 = { e8 6f 12 00 00 84 c0 74 04 32 c0 eb 34 56 ff 75 }
      $op1 = { 53 68 b0 34 41 00 57 e8 61 44 00 00 57 e8 31 44 }
      $op2 = { 56 ff 75 08 8d b5 f4 ef ff ff e8 17 ff ff ff 8d }

   condition:

      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "dbb1eb5c3476069287a73206929932fd" and all of them)
}

rule troy_malware_campaign_pdb
{
	 meta:

		 description = "Rule to detect the Operation Troy based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "3456f42bba032cff5518a5e5256cc433"
		 hash = "ebc7741e6e0115c2cf992860a7c7eae7"

	 strings:

		 $pdb = "\\Work\\Make Troy\\Concealment Troy\\Exe_Concealment_Troy(Winlogon_Shell)\\SetKey_WinlogOn_Shell_Modify\\BD_Installer\\Release\\BD_Installer.pdb"
		 $pdb1 = "\\Work\\Make Troy\\Concealment Troy\\Exe_Concealment_Troy(Winlogon_Shell)\\Dll\\Concealment_Troy(Dll)\\Release\\Concealment_Troy.pdb"

	 condition:

	 	any of them
}
rule shadowHammer
{

      meta:
      description = "Rule to detect ShadowHammer using the fake domain of asus and binary (overlay and not overlay, disk and memory)"
      author = "Alex Mundo | McAfee ATR Team"

   strings:

       $d = { 68 6F 74 66 }
       $d1 = { 61 73 75 73 }
       $d2 = { 69 78 2E 63 }
       $binary = { 44 3A 5C 43 2B 2B 5C 41 73 75 73 53 68 65 6C 6C 43 6F 64 65 5C 52 65 6C 65 61 73 65 5C 41 73 75 73 53 68 65 6C 6C 43 6F 64 65 2E 70 64 62 }

   condition:
       all of ($d*) or $binary
}
rule APT_Turla_PDB
{
	 meta:

		 description = "Rule to detect a component of the APT Turla"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "cb1b68d9971c2353c2d6a8119c49b51f"

	 strings:

	 	$pdb = "\\Workshop\\Projects\\cobra\\carbon_system\\x64\\Release\\carbon_system.pdb"

	 condition:

	 	any of them
}
rule enfal_pdb
{
	 meta:

		 description = "Rule to detect Enfal malware"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "D1B8DC41EFE4208191C766B303793D15"
		 hash = "A36CD4870446B513E70F903A77754B4F"
		 hash = "E7F93C894451EF1FDEFA81C6B229852C"
		 hash = "A3A6B5867A48DB969ABA90DD39771370"
		 hash = "01A0C09E9B3013C00009DA8D4E9E2B2B"
		 hash = "7A1D4CBA9CE2A28EF586C27689B5AEA7"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\DllServiceTrojan.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\ServiceDll.pdb"
		 $pdb2 = "\\Release\\ServiceDll.pdb"
		 $pdb3 = "\\muma\\0511\\Release\\ServiceDll.pdb"
		 $pdb4 = "\\programs\\LuridDownLoader\\LuridDownloader for Falcon\\ServiceDll\\Release\\ServiceDll.pdb"

	 condition:

	 	any of them
}
rule Flamer_PDB
{
	 meta:
	 description = "Rule to detect Flamer based on the PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "581F2EF2E3BA164281B562E435882EB5"

	 strings:

	 	$pdb = "\\Projects\\Jimmy\\jimmydll_v2.0\\JimmyForClan\\Jimmy\\bin\\srelease\\jimmydll\\indsvc32.pdb"

	 condition:

		 any of them
}
rule Gauss_PDB
{
	 meta:
		 description = "Rule to detect Gauss based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "EF6451FDE3751F698B49C8D4975A58B5"

	 strings:

		 $pdb = "\\projects\\gauss\\bin\\release\\winshell.pdb"

	 condition:

	 	any of them
}
rule ixeshe_bled_malware_pdb
{
	 meta:
		 description = "Rule to detect Ixeshe_bled malware based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "E658B571FD1679DABFC2232991F712B0"

	 strings:

	 	$pdb = "\\code\\Blade2009.6.30\\Blade2009.6.30\\EdgeEXE_20003OC\\Debug\\EdgeEXE.pdb"

	 condition:

	 	any of them
}
rule Dridex_P2P_pdb
{
	 meta:

		 description = "Rule to detect Dridex P2P based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "114DB69A015077A71908BFFF4E126863"

	 strings:

	 	$pdb = "\\c0da\\j.pdb"

	 condition:

	 	any of them
}
rule Alina_POS_PDB
{
	 meta:
		 description = "Rule to detect Alina POS"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "4C754150639AA3A86CA4D6B6342820BE"

	 strings:

	 	$pdb = "\\Users\\dice\\Desktop\\SRC_adobe\\src\\grab\\Release\\Alina.pdb"

	 condition:

	 	any of them
}
rule havex_backdoor_pdb
{
	 meta:
		 description = "Rule to detect backdoor Havex based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "7B28D8A54FC15A96B8DA49DD3FCC1DAE"
		 hash = "D610B84DEF0F32E139CD4E852F34882F"

 	strings:

		 $pdb = "\\Workspace\\PhalangX 3D\\Src\\Build\\Release\\Phalanx-3d.ServerAgent.pdb"
		 $pdb1 = "\\Workspace\\PhalangX 3D\\Src\\Build\\Release\\Tmprovider.pdb"

	condition:

 		any of them
}
rule backdoor_kankan_pdb
{
	 meta:
		 description = "Rule to detect kankan PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "a95f467b05f590b73647dbe705d14fd8"
		 hash = "bf07aa43bc810629c2ea68fd84c1117"
		 hash = "01e3c4b437945b2d58bdc2e0bb81f0d5"

 	strings:

		 $pdb = "\\Projects\\OfficeAddin\\INPEnhSvc\\Release\\INPEnhSvc.pdb"
		 $pdb1 = "\\Projects\\OfficeAddin\\OfficeAddin\\Release\\INPEn.pdb"
		 $pdb2 = "\\Projects\\OfficeAddinXJ\\VOCEnhUD\\Release\\VOCEnhUD.pdb"

	condition:

 		any of them
}
rule kartoxa_malware_pdb
{
	 meta:
		 description = "Rule to detect Kartoxa POS based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "255daa6722de6ad03545070dfbef3330"

	 strings:

		$pdb = "\\vm\\devel\\dark\\mmon\\Release\\mmon.pdb"

	condition:
		any of them
}
rule blackPOS_pdb
{
	 meta:
		 description = "BlackPOS PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "F45F8DF2F476910EE8502851F84D1A6E"

	 strings:

	 	$pdb = "\\Projects\\Rescator\\MmonNew\\Debug\\mmon.pdb"

	 condition:

	 	any of them
}
rule Browser_Fox_Adware
{
	 meta:
		 description = "Browser_Fox_Adware"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "ca7bcde15e93c132954bc335a2715502"

	 strings:

	 	$pdb = "\\Utilities\\130ijkfv.o4g\\Desktop\\Desktop.OptChecker\\bin\\Release\\ BooZaka.Opt"

	 condition:

	 	any of them
}
rule chikdos_malware_pdb
{
	 meta:

		 description = "Chikdos PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "10E7876FD639EA81767315CD178873C0"

	 strings:

	 	$pdb = "\\IntergrateCHK\\Release\\IntergrateCHK.pdb"

	 condition:

	 	any of them
}
rule cutwail_pdb
{
	 meta:
	 description = "Rule to detect cutwail based on the PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "C1B5AFCAD390B4A4F8530ABEB97F9546"

	 strings:

	 	$pdb = "\\0bulknet\\FLASH\\Release\\flashldr.pdb"

	 condition:

	 	any of them
}
rule downloader_darkmegi_pdb
{
	 meta:
	 description = "Rule to detect DarkMegi downloader based on PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "E7AB13A24081BFFA21272F69FFD32DBF"

 	strings:

 		$pdb = "\\RKTDOW~1\\RKTDRI~1\\RKTDRI~1\\objchk\\i386\\RktDriver.pdb"

 	condition:

 		any of them
}
rule dropper_demekaf_pdb_
{
	 meta:
	 description = "Rule to detect Demekaf dropper based on PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "8F9BC5A1621CCD39BDE9F8AC8F507D9E"

 	 strings:

 		$pdb = "\\vc\\res\\fake1.19-jpg\\fake\\Release\\fake.pdb"

 	 condition:

 		any of them
}
rule festi_botnet_pdb
{
	 meta:
	 description = "Rule to detect the Festi botnet based on PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "8c0a5c07bb13a7d82c0f420299c07476"

	 strings:

	 	$pdb = "\\eclipse\\botnet\\drivers\\Bin\\i386\\kernel.pdb"

	 condition:

	 	any of them
}
rule inabot_worm
{
	 meta:
		 description = "Rule to detect inabot worm based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "B93529F9949F79292FB12015A374E181"
		 hash = "29671A04CB2F72BC689F232EED95180C"
		 hash = "774A146E245A6953BC9D47219E9D64C6"
		 hash = "4CE026C2037DDF19E26E06E0C84041E9"

	 strings:

		 $pdb = "\\trasser\\portland.pdb"
		 $pdb1 = "\\mainstream\\archive.pdb"

 condition:

 	any of them
}
rule kelihos_botnet_pdb
{
	 meta:
		 description = "Rule to detect Kelihos malware based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "61841B1DC54EA0BAF95ACC02767EE1B1"
		 hash = "883C3CEE9B5C443562A48F10E1541810"

	 strings:

		 $pdb = "\\Only\\Must\\Not\\And.pdb"
		 $pdb1 = "\\To\\Access\\Do.pdb"

	 condition:

	 	any of them
}
rule likseput_backdoor_pdb
{
	 meta:
		 description = "Rule to detect Likseput backdoor based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "3A1E294DA327503ABAF63D310E0F03B9"

	 strings:

	 	$pdb = "\\work\\code\\2008-7-8muma\\mywork\\winInet_winApplication2009-8-7\\mywork\\aaaaaaa\\Release\\aaaaaaa.pdb"

	 condition:

	 	any of them
}
rule Mangzamel_trojan
{
	 meta:
		 description = "Rule to detect Mangzamel  trojan based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "F9BF6377DF8FCE8FB0E7636D58FA4FF0"
		 hash = "0ABEEE16C33073C7E2716F476F3BB3C5"

	 strings:

		 $pdb = "\\svn\\sys\\binary\\i386\\agony.pdb"
		 $pdb1 = "\\Windows\\i386\\ndisdrv.pdb"

	condition:
		any of them
}
rule Medfos
{
	 meta:
		 description = "Rule to detect Medfos trojan based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "0512E73000BCCCE5AFD2E9329972208A"

	 strings:

		 $pdb = "\\som\\bytguqne\\jzexsaf\\gyin.pdb"

	 condition:

	 	any of them
}
rule msworldexploit_builder_doc {

   meta:

      description = "Rule to detect RTF/Docs files created by MsWordExploit Builder"
      author = "Marc Rivero | McAfee ATR Team"

  strings:

      $s1 = "68 74 74 70 3a 2f 2f 61 70 69 2e 6d 73 77 6f 72 64 65 78 70 6c 6f 69 74 2e 63 6f 6d"  ascii
      $s2 = "{\\*\\generator mswordexploit 6.3.9600}" fullword ascii

   condition:

      any of them
}
rule NionSpy
{

meta:

	description = "Triggers on old and new variants of W32/NionSpy file infector"
	reference = "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector"

strings:

	$variant2015_infmarker = "aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT"
	$variant2013_infmarker = "ad6af8bd5835d19cc7fdc4c62fdf02a1"
	$variant2013_string = "%s?cstorage=shell&comp=%s"

condition:

	uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 1 of ($variant*)
}
rule rietspoof_loader {
   meta:
      description = "Rule to detect the Rietspoof loader"
      author = "Marc Rivero | McAfee ATR Team"

   strings:
      $x1 = "\\Work\\d2Od7s43\\techloader\\loader" fullword ascii

   condition:
      uint16(0) == 0x5a4d and all of them
}
rule rovnix_downloader
{
	meta:

		author="Intel Security"
		description="Rovnix downloader with sinkhole checks"
		reference = "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/"

	strings:

			$sink1= "control"
			$sink2 = "sink"
			$sink3 = "hole"
			$sink4= "dynadot"
			$sink5= "block"
			$sink6= "malw"
			$sink7= "anti"
			$sink8= "googl"
			$sink9= "hack"
			$sink10= "trojan"
			$sink11= "abuse"
			$sink12= "virus"
			$sink13= "black"
			$sink14= "spam"
			$boot= "BOOTKIT_DLL.dll"
			$mz = { 4D 5A }

	condition:

		$mz in (0..2) and all of ($sink*) and $boot
}
rule screenlocker_5h311_1nj3c706 {

   meta:

      description = "Rule to detect the screenlocker 5h311_1nj3c706"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://twitter.com/demonslay335/status/1038060120461266944"

   strings:

      $s1 = "C:\\Users\\Hoang Nam\\source\\repos\\WindowsApp22\\WindowsApp22\\obj\\Debug\\WindowsApp22.pdb" fullword ascii
      $s2 = "cmd.exe /cREG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop /v NoChangingWallPaper /t REG_DWOR" wide
      $s3 = "C:\\Users\\file1.txt" fullword wide
      $s4 = "C:\\Users\\file2.txt" fullword wide
      $s5 = "C:\\Users\\file.txt" fullword wide
      $s6 = " /v Wallpaper /t REG_SZ /d %temp%\\IMG.jpg /f" fullword wide
      $s7 = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" fullword wide
      $s8 = "All your file has been locked. You must pay money to have a key." fullword wide
      $s9 = "After we receive Bitcoin from you. We will send key to your email." fullword wide

   condition:

      ( uint16(0) == 0x5a4d and filesize < 200KB ) and all of them
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

rule BadBunny {

   meta:

      description = "Bad Rabbit Ransomware"
      author = "Christiaan Beek"
      reference = "BadRabbit"
      date = "2017-10-24"
      hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"

   strings:

      $x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $x2 = "need to do is submit the payment and get the decryption password." fullword ascii
      $s3 = "If you have already got the password, please enter it below." fullword ascii
      $s4 = "dispci.exe" fullword wide
      $s5 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
      $s6 = "Run DECRYPT app at your desktop after system boot" fullword ascii
      $s7 = "Enter password#1: " fullword wide
      $s8 = "Enter password#2: " fullword wide
      $s9 = "C:\\Windows\\cscc.dat" fullword wide
      $s10 = "schtasks /Delete /F /TN %ws" fullword wide
      $s11 = "Password#1: " fullword ascii
      $s12 = "\\AppData" fullword wide
      $s13 = "Disk decryption completed" fullword wide
      $s14 = "Files decryption completed" fullword wide
      $s15 = "http://diskcryptor.net/" fullword wide
      $s16 = "Your personal installation key#1:" fullword ascii
      $s17 = ".3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc.cer.cfg.conf.cpp.crt.cs.ctl.cxx.dbf.der.dib.disk.djvu.doc.docx.dwg." wide
      $s18 = "Disable your anti-virus and anti-malware programs" fullword wide
      $s19 = "bootable partition not mounted" fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "94f57453c539227031b918edd52fc7f1" and ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule badrabbit_ransomware {
   meta:
      description = "Rule to detect Bad Rabbit Ransomware"
      author = "Marc Rivero | McAfee ATR Team"

   strings:
      $s1 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\" -id %u && exit\"" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\" fullword wide
      $s3 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s4 = "need to do is submit the payment and get the decryption password." fullword wide
      $s5 = "schtasks /Create /SC once /TN drogon /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $s6 = "rundll32 %s,#2 %s" fullword ascii
      $s7 = " \\\"C:\\Windows\\%s\\\" #1 " fullword wide
      $s8 = "Readme.txt" fullword wide
      $s9 = "wbem\\wmic.exe" fullword wide
      $s10 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide

      $og1 = { 39 74 24 34 74 0a 39 74 24 20 0f 84 9f }
      $og2 = { 74 0c c7 46 18 98 dd 00 10 e9 34 f0 ff ff 8b 43 }
      $og3 = { 8b 3d 34 d0 00 10 8d 44 24 28 50 6a 04 8d 44 24 }

      $oh1 = { 39 5d fc 0f 84 03 01 00 00 89 45 c8 6a 34 8d 45 }
      $oh2 = { e8 14 13 00 00 b8 ff ff ff 7f eb 5b 8b 4d 0c 85 }
      $oh3 = { e8 7b ec ff ff 59 59 8b 75 08 8d 34 f5 48 b9 40 }

      $oj4 = { e8 30 14 00 00 b8 ff ff ff 7f 48 83 c4 28 c3 48 }
      $oj5 = { ff d0 48 89 45 e0 48 85 c0 0f 84 68 ff ff ff 4c }
      $oj6 = { 85 db 75 09 48 8b 0e ff 15 34 8f 00 00 48 8b 6c }

      $ok1 = { 74 0c c7 46 18 c8 4a 40 00 e9 34 f0 ff ff 8b 43 }
      $ok2 = { 68 f8 6c 40 00 8d 95 e4 f9 ff ff 52 ff 15 34 40 }
      $ok3 = { e9 ef 05 00 00 6a 10 58 3b f8 73 30 8b 45 f8 85 }


   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (all of ($s*) and all of ($og*)) or all of ($oh*) or all of ($oj*) or all of ($ok*)
}
rule bitpaymer_ransomware {

   meta:
      description = "Rule to detect BitPaymer Ransomware"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s1 = "IEncrypt.dll" fullword wide
      $op0 = { e8 5f f3 ff ff ff b6 e0 }
      $op1 = { e8 ad e3 ff ff 59 59 8b 75 08 8d 34 f5 38 eb 42 }
      $op2 = { e9 45 ff ff ff 33 ff 8b 75 0c 6a 04 e8 c1 d1 ff }

      $pdb = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword ascii
      $oj0 = { 39 74 24 34 75 53 8d 4c 24 18 e8 b8 d1 ff ff ba }
      $oj1 = { 5f 8b c6 5e c2 08 00 56 8b f1 8d 4e 34 e8 91 af }
      $oj2 = { 8b cb 8d bd 50 ff ff ff 8b c1 89 5f 04 99 83 c1 }

      $t1 = ".C:\\aaa_TouchMeNot_.txt" fullword wide
      $ok0 = { e8 b5 34 00 00 ff 74 24 18 8d 4c 24 54 e8 80 39 }
      $ok1 = { 8b 5d 04 33 ff 8b 44 24 34 89 44 24 5c 85 db 7e }
      $ok2 = { 55 55 ff 74 24 20 8d 4c 24 34 e8 31 bf 00 00 55 }

      $random = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+" fullword ascii
      $oi0 = { a1 04 30 ac 00 8b ce 0f af c2 03 c0 99 8b e8 89 }
      $oi1 = { e8 64 a2 ff ff 85 c0 74 0c 8d 4d d8 51 ff 35 64 }
      $oi2 = { c7 03 d4 21 ac 00 e8 86 53 00 00 89 73 10 89 7b }
      $ou0 = { e8 64 a2 ff ff 85 c0 74 0c 8d 4d d8 51 ff 35 60 }
      $ou1 = { a1 04 30 04 00 8b ce 0f af c2 03 c0 99 8b e8 89 }
      $ou2 = { 8d 4c 24 10 e8 a0 da ff ff 68 d0 21 04 00 8d 4c }
      $oa1 = { 56 52 ba 00 10 0c 00 8b f1 e8 28 63 00 00 8b c6 }
      $oa2 = { 81 3d 50 30 0c 00 53 c6 d2 43 56 8b f1 75 23 ba }
      $oy0 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oy1 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oy2 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oh1 = { e8 74 37 00 00 a3 00 30 fe 00 8d 4c 24 1c 8d 84 }
      $oh2 = { 56 52 ba 00 10 fe 00 8b f1 e8 28 63 00 00 8b c6 }

   condition:
      (uint16(0) == 0x5a4d and filesize < 1000KB) and ($s1 and all of ($op*)) or ($pdb and all of ($oj*)) or ($t1 and all of ($ok*)) or ($random and all of ($oi*)) or ($random and all of ($ou*)) or ($random and all of ($oa*) and $ou0) or ($random and all of ($oy*)) or ($random and all of ($oh*)) or ($random and $ou0) or ($random and $oi1)
}
rule buran_ransomware
{
      meta:

            description = "Rule to detect Buran ransomware"
            author = "Marc Rivero | McAfee ATR Team"


      strings:

            $s1 = { 5? 8B ?? 81 C? ?? ?? ?? ?? 5? 5? 5? 33 ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 ?? 5? 68 ?? ?? ?? ?? 64 ?? ?? 64 ?? ?? C6 ?? ?? ?? ?? ?? ?? 33 ?? 5? 68 ?? ?? ?? ?? 64 ?? ?? 64 ?? ?? 8D ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 8B ?? ?? E8 ?? ?? ?? ?? 5? E8 ?? ?? ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 85 }
            $s2 = { 4? 33 ?? 8D ?? ?? 0F B6 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? 8B ?? FF 5? ?? FF 7? ?? 8D ?? ?? 0F B6 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 5? 8D ?? ?? 0F B6 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? 0F B6 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 5? E8 ?? ?? ?? ?? 85 ?? 74 }
            $s3 = { A1 ?? ?? ?? ?? 99 5? 5? A1 ?? ?? ?? ?? 99 5? 5? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 5? 5? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 03 ?? ?? 13 ?? ?? ?? 83 ?? ?? E8 ?? ?? ?? ?? 5? 5? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 03 ?? ?? 13 ?? ?? ?? 83 ?? ?? 89 ?? ?? 89 ?? ?? A1 ?? ?? ?? ?? 99 5? 5? 8B ?? ?? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8B ?? ?? 03 ?? ?? ?? 13 ?? ?? ?? 89 ?? ?? 89 ?? ?? A1 ?? ?? ?? ?? 4? 99 89 ?? ?? 89 ?? ?? FF 7? ?? FF 7? ?? 8B ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 3B ?? ?? 75 }
            $s4 = { 5? 5? 5? 5? 8B ?? 33 ?? 5? 68 ?? ?? ?? ?? 64 ?? ?? 64 ?? ?? 68 ?? ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? 89 ?? ?? 8D ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? ?? 0F 84 }
            $s5 = { 5? 8B ?? 83 ?? ?? 5? 5? 5? 89 ?? ?? 8B ?? 89 ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 83 ?? ?? 83 ?? ?? 5? 5? A1 ?? ?? ?? ?? 99 E8 ?? ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? 8B ?? 8B ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? 8B ?? ?? 8B ?? E8 ?? ?? ?? ?? 8B ?? ?? 8B ?? E8 ?? ?? ?? ?? 8B ?? ?? 2B ?? 8B ?? 4? 5? 8B ?? ?? 8B ?? 83 ?? ?? B9 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 83 ?? ?? 0F 8C }


      condition:

           uint16(0) == 0x5a4d and all of them
}
rule clop_ransom_note {

   meta:

      description = "Rule to detect Clop Ransomware Note"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s1 = "If you want to restore your files write to emails" fullword ascii
      $s2 = "All files on each host in the network have been encrypted with a strong algorithm." fullword ascii
      $s3 = "Shadow copies also removed, so F8 or any other methods may damage encrypted data but not recover." fullword ascii
      $s4 = "You will receive decrypted samples and our conditions how to get the decoder." fullword ascii
      $s5 = "DO NOT RENAME OR MOVE the encrypted and readme files." fullword ascii
      $s6 = "(Less than 6 Mb each, non-archived and your files should not contain valuable information" fullword ascii
      $s7 = "We exclusively have decryption software for your situation" fullword ascii
      $s8 = "Do not rename encrypted files." fullword ascii
      $s9 = "DO NOT DELETE readme files." fullword ascii
      $s10 = "Nothing personal just business" fullword ascii
      $s11 = "eqaltech.su" fullword ascii

   condition:
      ( uint16(0) == 0x6f59) and filesize < 10KB and all of them
}

rule CryptoLocker_set1
{

meta:

	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-13"
	description = "Detection of Cryptolocker Samples"

strings:

	$string0 = "static"
	$string1 = " kscdS"
	$string2 = "Romantic"
	$string3 = "CompanyName" wide
	$string4 = "ProductVersion" wide
	$string5 = "9%9R9f9q9"
	$string6 = "IDR_VERSION1" wide
	$string7 = "  </trustInfo>"
	$string8 = "LookFor" wide
	$string9 = ":n;t;y;"
	$string10 = "        <requestedExecutionLevel level"
	$string11 = "VS_VERSION_INFO" wide
	$string12 = "2.0.1.0" wide
	$string13 = "<assembly xmlns"
	$string14 = "  <trustInfo xmlns"
	$string15 = "srtWd@@"
	$string16 = "515]5z5"
	$string17 = "C:\\lZbvnoVe.exe" wide

condition:

	12 of ($string*)
}

rule CryptoLocker_rule2
{

meta:

	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-14"
	description = "Detection of CryptoLocker Variants"

strings:

	$string0 = "2.0.1.7" wide
	$string1 = "    <security>"
	$string2 = "Romantic"
	$string3 = "ProductVersion" wide
	$string4 = "9%9R9f9q9"
	$string5 = "IDR_VERSION1" wide
	$string6 = "button"
	$string7 = "    </security>"
	$string8 = "VFileInfo" wide
	$string9 = "LookFor" wide
	$string10 = "      </requestedPrivileges>"
	$string11 = " uiAccess"
	$string12 = "  <trustInfo xmlns"
	$string13 = "last.inf"
	$string14 = " manifestVersion"
	$string15 = "FFFF04E3" wide
	$string16 = "3,31363H3P3m3u3z3"

condition:

	12 of ($string*)
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
rule SVG_LoadURL {

	meta:

		description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
		author = "Florian Roth"
		reference = "http://goo.gl/psjCCc"
		date = "2015-05-24"
		hash1 = "ac8ef9df208f624be9c7e7804de55318"
		hash2 = "3b9e67a38569ebe8202ac90ad60c52e0"
		hash3 = "7e2be5cc785ef7711282cea8980b9fee"
		hash4 = "4e2c6f6b3907ec882596024e55c2b58b"
		score = 50

	strings:

		$s1 = "</svg>" nocase
		$s2 = "<script>" nocase
		$s3 = "location.href='http" nocase

	condition:

		all of ($s*) and filesize < 600
}

rule BackdoorFCKG_CTB_Locker_Ransomware
{

meta:

	author = "ISG"
	date = "2015-01-20"
	reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
	description = "CTB_Locker"

strings:

	$string0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$stringl = "RNDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string2 = "keme132.DLL"
	$string3 = "klospad.pdb"

condition:

	3 of them
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

rule ransom_note_kraken_cryptor_ransomware {

   meta:

      description = "Rule to detect the ransom note delivered by Kraken Cryptor Ransomware"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s1 = "No way to recovery your files without \"KRAKEN DECRYPTOR\" software and your computer \"UNIQUE KEY\"!" fullword ascii
      $s2 = "Are you want to decrypt all of your encrypted files? If yes! You need to pay for decryption service to us!" fullword ascii
      $s3 = "The speed, power and complexity of this encryption have been high and if you are now viewing this guide." fullword ascii
      $s4 = "Project \"KRAKEN CRYPTOR\" doesn't damage any of your files, this action is reversible if you follow the instructions above." fullword ascii
      $s5 = "https://localBitcoins.com" fullword ascii
      $s6 = "For the decryption service, we also need your \"KRAKEN ENCRYPTED UNIQUE KEY\" you can see this in the top!" fullword ascii
      $s7 = "-----BEGIN KRAKEN ENCRYPTED UNIQUE KEY----- " fullword ascii
      $s8 = "All your files has been encrypted by \"KRAKEN CRYPTOR\"." fullword ascii
      $s9 = "It means that \"KRAKEN CRYPTOR\" immediately removed form your system!" fullword ascii
      $s10 = "After your payment made, all of your encrypted files has been decrypted." fullword ascii
      $s11 = "Don't delete .XKHVE files! there are not virus and are your files, but encrypted!" fullword ascii
      $s12 = "You can decrypt one of your encrypted smaller file for free in the first contact with us." fullword ascii
      $s13 = "You must register on this site and click \"BUY Bitcoins\" then choose your country to find sellers and their prices." fullword ascii
      $s14 = "-----END KRAKEN ENCRYPTED UNIQUE KEY-----" fullword ascii
      $s15 = "DON'T MODIFY \"KRAKEN ENCRYPT UNIQUE KEY\"." fullword ascii
      $s16 = "# Read the following instructions carefully to decrypt your files." fullword ascii
      $s17 = "We use best and easy way to communications. It's email support, you can see our emails below." fullword ascii
      $s18 = "DON'T USE THIRD PARTY, PUBLIC TOOLS/SOFTWARE TO DECRYPT YOUR FILES, THIS CAUSE DAMAGE YOUR FILES PERMANENTLY." fullword ascii
      $s19 = "https://en.wikipedia.org/wiki/Bitcoin" fullword ascii
      $s20 = "Please send your message with same subject to both address." fullword ascii
   condition:

      ( uint16(0) == 0x4120 and filesize < 9KB ) and all of them
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

rule SAmSAmRansom2016 {

   meta:

      author = "Christiaan Beek"
      date = "2018-01-25"
      hash1 = "45e00fe90c8aa8578fce2b305840e368d62578c77e352974da6b8f8bc895d75b"
      hash2 = "946dd4c4f3c78e7e4819a712c7fd6497722a3d616d33e3306a556a9dc99656f4"
      hash3 = "979692a34201f9fc1e1c44654dc8074a82000946deedfdf6b8985827da992868"
      hash4 = "939efdc272e8636fd63c1b58c2eec94cf10299cd2de30c329bd5378b6bbbd1c8"
      hash5 = "a763ed678a52f77a7b75d55010124a8fccf1628eb4f7a815c6d635034227177e"
      hash6 = "e682ac6b874e0a6cfc5ff88798315b2cb822d165a7e6f72a5eb74e6da451e155"
      hash7 = "6bc2aa391b8ef260e79b99409e44011874630c2631e4487e82b76e5cb0a49307"
      hash8 = "036071786d7db553e2415ec2e71f3967baf51bdc31d0a640aa4afb87d3ce3050"
      hash9 = "ffef0f1c2df157e9c2ee65a12d5b7b0f1301c4da22e7e7f3eac6b03c6487a626"
      hash10 = "89b4abb78970cd524dd887053d5bcd982534558efdf25c83f96e13b56b4ee805"
      hash11 = "7aa585e6fd0a895c295c4bea2ddb071eed1e5775f437602b577a54eef7f61044"
      hash12 = "0f2c5c39494f15b7ee637ad5b6b5d00a3e2f407b4f27d140cd5a821ff08acfac"
      hash13 = "58ef87523184d5df3ed1568397cea65b3f44df06c73eadeb5d90faebe4390e3e"

   strings:

      $x1 = "Could not list processes locking resource. Failed to get size of result." fullword wide
      $s2 = "Could not list processes locking resource." fullword wide
      $s3 = "samsam.del.exe" fullword ascii
      $s4 = "samsam.exe" fullword wide
      $s5 = "RM_UNIQUE_PROCESS" fullword ascii
      $s6 = "KillProcessWithWait" fullword ascii
      $s7 = "killOpenedProcessTree" fullword ascii
      $s8 = "RM_PROCESS_INFO" fullword ascii
      $s9 = "Exception caught in process: {0}" fullword wide
      $s10 = "Could not begin restart session.  Unable to determine file locker." fullword wide
      $s11 = "samsam.Properties.Resources.resources" fullword ascii
      $s12 = "EncryptStringToBytes" fullword ascii
      $s13 = "recursivegetfiles" fullword ascii
      $s14 = "RSAEncryptBytes" fullword ascii
      $s15 = "encryptFile" fullword ascii
      $s16 = "samsam.Properties.Resources" fullword wide
      $s17 = "TSSessionId" fullword ascii
      $s18 = "Could not register resource." fullword wide
      $s19 = "<recursivegetfiles>b__0" fullword ascii
      $s20 = "create_from_resource" fullword ascii

      $op0 = { 96 00 e0 00 29 00 0b 00 34 23 }
      $op1 = { 96 00 12 04 f9 00 34 00 6c 2c }
      $op2 = { 72 a5 0a 00 70 a2 06 20 94 }

   condition:

      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them ) and all of ($op*)) or ( all of them )
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
rule unpacked_shiva_ransomware {

   meta:

      description = "Rule to detect an unpacked sample of Shiva ransopmw"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://twitter.com/malwrhunterteam/status/1037424962569732096"

   strings:

      $s1 = "c:\\Users\\sys\\Desktop\\v 0.5\\Shiva\\Shiva\\obj\\Debug\\shiva.pdb" fullword ascii
      $s2 = "This email will be as confirmation you are ready to pay for decryption key." fullword wide
      $s3 = "Your important files are now encrypted due to a security problem with your PC!" fullword wide
      $s4 = "write.php?info=" fullword wide
      $s5 = " * Do not try to decrypt your data using third party software, it may cause permanent data loss." fullword wide
      $s6 = " * Do not rename encrypted files." fullword wide
      $s7 = ".compositiontemplate" fullword wide
      $s8 = "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us." fullword wide
      $s9 = "\\READ_IT.txt" fullword wide
      $s10 = ".lastlogin" fullword wide
      $s11 = ".logonxp" fullword wide
      $s12 = " * Decryption of your files with the help of third parties may cause increased price" fullword wide
      $s13 = "After payment we will send you the decryption tool that will decrypt all your files." fullword wide

   condition:

      ( uint16(0) == 0x5a4d and filesize < 800KB ) and all of them
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

rule Sodinokobi
{
    /*
      This rule detects Sodinokobi Ransomware in memory in old samples and perhaps future.
    */
    meta:
        author      = "McAfee ATR team"
        version     = "1.0"
        description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
    strings:
        $a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
        $b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }
    condition:
        all of them
}
rule rat_comrat
{
	 meta:
		 description = "Rule to detect the ComRAT RAT"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "28dc1ca683d6a14d0d1794a68c477604"

	 strings:

	 	$pdb = "\\projects\\ChinckSkx64\\Debug\\Chinch.pdb"

	 condition:

	 	any of them
}
rule DarkcometRAT_PDB
{
	 meta:
	 description = "Rle to detect an old DarkcometRAT based on the PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "6A659FB586F243C5FB12B780F5F00BFE"

	 strings:

	 	$pdb = "\\Users\\MY\\AppData\\Local\\TemporaryProjects\\Chrome\\obj\\x86\\Debug\\Chrome.pdb"

	 condition:

	 	any of them
}
rule LostdoorRAT_pdb
{
	 meta:
		 description = "Rule to detect LostdoorRAT based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "FB1B0536B4660E67E8AA7BAB17994A7C"

	 strings:

	 	$pdb = "\\Users\\Aegis\\Documents\\Visual Studio 2008\\Projects\\stub1\\Release\\stub.pdb"

	 condition:

	 	any of them
}
rule SpyGate_v2_9
{
	meta:

		date = "2014/09"
		maltype = "Spygate v2.9 Remote Access Trojan"
		filetype = "exe"
		reference = "https://blogs.mcafee.com/mcafee-labs/middle-east-developer-spygate-struts-stuff-online"

	strings:

		$1 = "shutdowncomputer" wide
		$2 = "shutdown -r -t 00" wide
		$3 = "blockmouseandkeyboard" wide
		$4 = "ProcessHacker"
		$5 = "FileManagerSplit" wide

	condition:
		all of them
}
rule CredStealESY
{

 meta:

	description = "Generic Rule to detect the CredStealer Malware"
	author = "IsecG ??? McAfee Labs"
	date = "2015/05/08"

strings:

$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide //malware trying to get keyboard layout
$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8} //specific decryption module

condition:

	$my_hex_string and $my_hex_string2
}
rule EmiratesStatement
{
	meta:

		Author 		= "Christiaan Beek"
		Date 		= "2013-06-30"
		Description = "Credentials Stealing Attack"
		Reference 	= "https://blogs.mcafee.com/mcafee-labs/targeted-campaign-steals-credentials-in-gulf-states-and-caribbean"

		hash0 = "0e37b6efe5de1cc9236017e003b1fc37"
		hash1 = "a28b22acf2358e6aced43a6260af9170"
		hash2 = "6f506d7adfcc2288631ed2da37b0db04"
		hash3 = "8aebade47dc1aa9ac4b5625acf5ade8f"

	strings:

		$string0 = "msn.klm"
		$string1 = "wmsn.klm"
		$string2 = "bms.klm"

	condition:

		all of them
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

-- Scan all paths with Yara signatures
for path, i in pairs(paths) do
    print('[i] Scanning ' .. path)
    for _, signature in pairs(yara_bad:scan(path)) do
        if not hash then
            hash = hunt.hash.sha1(path)
        end
        hunt.log('[BAD] Yara matched [' .. signature .. '] in file: ' .. path .. " <"..hash..">")
        bad = true
    end
    for _, signature in pairs(yara_suspicious:scan(path)) do
        if not hash then
            hash = hunt.hash.sha1(path)
        end
        hunt.log('[SUSPICIOUS] Yara matched [' .. signature .. '] in file: ' .. path .. " <"..hash..">")
        suspicious = true
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
