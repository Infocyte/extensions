--[[
    Infocyte Extension
    Name: Evidence Collector
    Type: Collection
    Description: | Collects event logs, .dat files, etc. from system and forwards
        them to your Recovery point. Loads Powerforensics to bypass file locks
        Currently only works on Windows |
    Author: Infocyte
    Guid: e07252a1-4aea-47e4-80e8-c7ea8c558aed
    Created: 20191018
    Updated: 20200318 (Gerritz)
--]]


--[[ SECTION 1: Inputs --]]

-- S3 Bucket (mandatory)
s3_user = nil
s3_pass = nil
s3_region = 'us-east-2' -- 'us-east-2'
s3_bucket = 'test-extensions' -- 'test-extensions'
s3path_modifier = "evidence" -- /filename will be appended
--S3 Path Format: <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>


-- Proxy (optional)
proxy = nil -- "myuser:password@10.11.12.88:8888"

-- Evidence Collections
use_powerforensics = true
MFT = false -- this is a big job
SecurityEvents = true
IEHistory = true
FireFoxHistory = true
ChromeHistory = true
OutlookPSTandAttachments = true
UserDat = true
USBHistory = true


debug = false


--[[ SECTION 2: Functions --]]

function reg_usersids()
    local output = {}
    -- Iterate through each user profile's and list their keyboards
    local user_sids = hunt.registry.list_keys("\\Registry\\User")
    for _,user_sid in pairs(user_sids) do
        table.insert(output, "\\Registry\\User\\"..user_sid)
    end
    return output
end

function userfolders()
    local paths = {}
    local u = {}
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        if (userfolder:full()):match("Users") then
            if not u[userfolder:full()] then
                -- filter out links like "Default User" and "All Users"
                u[userfolder:full()] = true
                table.insert(paths, userfolder)
            end
        end
    end
    return paths
end

function path_exists(path)
    -- Check if a file or directory exists in this path
    -- add '/' on end to test if it is a folder
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

-- Infocyte Powershell Functions
posh = {}
function posh.run_cmd(command)
    --[[
        Input:  [String] Small Powershell Command
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
        throw "Powershell not found."
    end

    if not command or (type(command) ~= "string") then 
        hunt.error("Required input [String]command not provided.")
        throw "Required input [String]command not provided."
    end

    print("Initiatializing Powershell to run Command: "..command)
    cmd = ('powershell.exe -nologo -nop -command "& {'..command..'}"')
    pipe = io.popen(cmd, "r")
    output = pipe:read("*a") -- string output
    ret = pipe:close() -- success bool
    return ret, output
end

function posh.run_script(psscript)
    --[[
        Input:  [String] Powershell script. Ideally wrapped between [==[ ]==] to avoid possible escape characters.
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
        throw "Powershell not found."
    end

    if not psscript or (type(psscript) ~= "string") then 
        hunt.error("Required input [String]script not provided.")
        throw "Required input [String]script not provided."
    end

    print("Initiatializing Powershell to run Script")
    tempfile = os.getenv("systemroot").."\\temp\\icpowershell.log"

    -- Pipeline is write-only so we'll use transcript to get output
    script = '$Temp = [System.Environment]::GetEnvironmentVariable("TEMP","Machine")\n'
    script = script..'Start-Transcript -Path "'..tempfile..'" | Out-Null\n'
    script = script..psscript
    script = script..'\nStop-Transcript\n'

    pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
    pipe:write(script)
    ret = pipe:close() -- success bool

    -- Get output
    file, err = io.open(tempfile, "r")
    if file then
        output = file:read("*all") -- String Output
        file:close()
        os.remove(tempfile)
    else 
        print("Powershell script failed to run: "..err)
    end
    return ret, output
end

function posh.install_powerforensics()
    --[[
        Checks for NuGet and installs Powerforensics
        Output: [bool] Success
    ]]
    if not posh then 
        hunt.error("Infocyte's posh lua functions are not available. Add Infocyte's posh.* functions.")
        throw "Error"
    end
    script = [==[
        # Download/Install PowerForensics
        $n = Get-PackageProvider -name NuGet
        if ($n.version.major -lt 2) {
            if ($n.version.minor -lt 8) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
            }
        }
        if (-NOT (Get-Module -ListAvailable -Name PowerForensics)) {
            Write-Host "Installing PowerForensics"
            Install-Module -name PowerForensics -Scope CurrentUser -Force
        }
    ]==]
    ret, output = posh.run_script(script)
    if ret then 
        hunt.debug("Powershell Succeeded:\n"..output)
    else 
        hunt.error("Powershell Failed:\n"..output)
    end
    return ret
end


--[[ SECTION 3: Collection --]]

-- Check required inputs
if not s3_region or not s3_bucket then
    hunt.error("s3_region and s3_bucket not set")
    return
end

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows code

    -- Make tempdir
    os.execute("mkdir "..os.getenv("temp").."\\ic")

    if (use_powerforensics or MFT) and hunt.env.has_powershell() then
        posh.install_powerforensics()
    end

    -- Record LocalTimeZone
    regtz = hunt.registry.list_values("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation")
    for n,v in pairs(regtz) do
        if n:match("TimeZoneKeyName") then
            name = v
        elseif n:match("ActiveTimeBias") then
            bias = tonumber(v) or "Error"
            if type(bias) == "number" then
                bias = string.format("%d", (bias/60))
            end
        end
    end
    tz = name.." ("..bias..")"
    hunt.log("Local Timezone: "..tz)


    paths = {}

    -- Security Event Logs
    if SecurityEvents then
        paths["SecurityEvents"] = [[C:\Windows\System32\winevt\Logs\Security.evtx]]
    end

    -- IEHistory for each user
    if IEHistory then
        for _, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(userfolder:path().."\\AppData\\Local\\Microsoft\\Windows\\WebCache", {"files"})) do
                n = 1
                if (path:name()):match("WebCacheV*.dat") then
                    paths["IEHistory_"..userfolder:name()..n] = path:path()
                    n = n + 1
                end
            end
        end
    end

    -- FireFoxHistory for each user
    -- AppData\Roaming\Mozilla\Firefox\Profiles\<random text>.default\places.sqlite
    if FireFoxHistory then
        for _, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(userfolder:path().."\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\", {"files", "recurse"})) do
                n = 1
                if (path:name()):match("places.sqlite") or (path:name()):match("downloads.sqlite")then
                    paths["FireFoxHistory_"..userfolder:name()..n] = path:path()
                    n = n + 1
                end
            end
        end
    end

    -- Chrome History for each user
    --%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\History
    if ChromeHistory then
        for i, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(userfolder:path().."\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", {"files"})) do
                paths["ChromeHistory_"..userfolder:name()] = path:path()
            end
        end
    end

    -- Outlook Evidence
    -- %USERPROFILE%\AppData\Local\Microsoft\Outlook
    if OutlookPSTandAttachments then
        for _, userfolder in pairs(userfolders()) do
            for _, path in pairs(hunt.fs.ls(userfolder:path().."\\AppData\\Local\\Microsoft\\Outlook", {"files"})) do
                paths["OutlookAttachments_"..userfolder:name()] = path:path()
            end
        end
    end

    -- User Dat Files
    if UserDat then
        for _, userfolder in pairs(userfolders()) do
            paths["NTUserDat_"..userfolder:name()] = userfolder:path().."\\ntuser.dat"
            paths["UsrclassDat_"..userfolder:name()] = userfolder:path().."\\AppData\\Local\\Microsoft\\Windows\\usrclass.dat"
        end
    end

    -- USB History
    if USBHistory then
        paths["USBHistory"] = [[C:\Windows\inf\setupapi.dev.log]]
    end

    if MFT and hunt.env.has_powershell()  then
        temppath = os.getenv("TEMP").."\\ic\\icmft.csv"
        outpath = os.getenv("TEMP").."\\ic\\icmft.zip"
        logfile = os.getenv("TEMP").."\\ic\\pslog.log"

        cmd = 'Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '..temppath..' -Force'
        hunt.debug("Getting MFT with PowerForensics and exporting to "..temppath)
        hunt.debug("Executing Powershell command: "..cmd)
        local pipe = io.popen('powershell.exe -noexit -nologo -nop -command "'..cmd..'" >> '..logfile, 'r')
        print(pipe:read('*a'))
        r = pipe:close()
        if debug then
            local file,msg = io.open(logfile, "r")
            if file then
                hunt.debug("Powershell Output (success="..tostring(r).."):\n"..file:read("*all"))
            end
            file:close()
            os.remove(logfile)
        end

        -- Compress results
        if path_exists(temppath) then
            hash = hunt.hash.sha1(temppath)
            hunt.log("Compressing (gzip) " .. temppath .. " (sha1=".. hash .. ") to " .. outpath)
            hunt.gzip(temppath, outpath, nil)
            os.remove(temppath)
            file = hunt.fs.ls(outpath)
            if #file > 0 then
                paths["MFT"] = file[1]:path()
            else
                hunt.error("Compression on MFT failed.")
            end
        else
            hunt.error("PowerForensics MFT Dump failed.")
        end
    end


--elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


--elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code

else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Upload Evidence
instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
s3 = hunt.recovery.s3(s3_user, s3_pass, s3_region, s3_bucket)
s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier

for name,path in pairs(paths) do
    f = hunt.fs.ls(path)
    if #f > 0 then
        -- If file is being used or locked, this copy will get passed it (usually)
        outpath = os.getenv("temp").."\\ic\\"..f[1]:name()
        infile, err = io.open(path, "rb")
        if not infile and hunt.env.has_powershell() then
            -- Assume file locked by kernel, use powerforensics to copy
            cmd = 'Copy-ForensicFile -Path '..path..' -Destination '..outpath
            hunt.debug("File Locked ["..err.."]. Executing: "..cmd)
            ret, out = posh.run_cmd(cmd)
            hunt.debug("Powerforensics output: "..out)
        else
           -- Copy file to temp path
           data = infile:read("*all")
           infile:close()
           outfile = io.open(outpath, "wb")
           outfile:write(data)
           outfile:flush()
           outfile:close()
        end

        -- hash file
        hash, err = hunt.hash.sha1(outpath)
        if not hash then
            hunt.debug("Error hashing file: "..outpath..", error: "..err)
            goto continue
        end

        -- Upload file to S3
        s3path = s3path_preamble.."/"..name.."_"..f[1]:name()
        link = "https://"..s3_bucket..".s3."..s3_region..".amazonaws.com/" .. s3path
        s3:upload_file(outpath, s3path)
        hunt.log("Uploaded "..name.." - "..path.." (size= "..string.format("%.2f", (f[1]:size()/1000)).."KB, sha1=".. hash .. ") to S3 bucket " .. link)

        os.remove(outpath)
        ::continue::
    else
        hunt.debug(name.." failed. "..path.." does not exist.")
    end
end

-- Cleanup
os.execute("RMDIR /S/Q "..os.getenv("temp").."\\ic")

hunt.status.good()


--[[
Win2k3/XP: \%SystemRoot%\System32\Config\*.evt
Win2k8/Vista+: \%SystemRoot%\System32\winevt\Logs\*.evtx
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security | select File
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System | select File

    4624 [Security] - Successful Logon (Network Type 3 Logon)
    4720 [Security] - A user account was created
    4732/4728 [Security] - A member was added to a security-enabled group
    7045 [System] - Service Creation
    4688 [Security] - A new process has been created (Win2012R2+ has CLI)
    4014 [Powershell] - Script Block Logging
--]]
