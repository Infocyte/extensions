--[[
    Infocyte Extension
    Name: PowerForensics MFT
    Type: Collection
    Description: | Deploy PowerForensics and gathers forensic data to Recovery
        Location. 
        This extension requires definition of a Recovery Location (S3, SMB Share, or FTP) |
    Author: Infocyte
    Guid: 0989cd2f-a781-4cea-8f43-fcc3092144a1
    Created: 20190919
    Updated: 20191025 (Gerritz)
--]]


--[[ SECTION 1: Inputs --]]
debug = true

-- Upload Options. S3 Bucket (Mandatory)
s3_user = nil -- Optional for authenticated uploads
s3_pass = nil -- Optional for authenticated uploads
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'



--S3 Path Format: <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>
s3path_modifier = "evidence"


--[[ SECTION 2: Functions --]]

-- Infocyte Powershell Functions
posh = {}

function posh.run_cmd(command)
    --[[
    Input: [String] Small Powershell Command
    Output: [Bool] Success
            [String] Output
    ]]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
        return nil
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
    Input: [String] Small Powershell Command
    Output: [Bool] Success
            [String] Output
    ]]
    if not hunt.env.has_powershell() then
        hunt.error("Powershell not found.")
        return nil
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
    file, output = io.open(tempfile, "r")
    if file then
        output = file:read("*all") -- String Output
        file:close()
        os.remove(tempfile)
    else 
        print("Powershell script failed to run: "..output)
    end
    return ret, output
end

function install_powerforensic()
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
    ret, output = posh.execute_script(psscript)
    if ret then 
        hunt.debug("Powershell Succeeded:\n"..output)
    else 
        hunt.error("Powershell Failed:\n"..output)
    end
    return ret
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

--[[ SECTION 3: Collection --]]

-- Check required inputs
if not s3_region or not s3_bucket then
    hunt.error("s3_region and s3_bucket not set. Cannot upload MFT.")
    return
end

host_info = hunt.env.host_info()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if not hunt.env.is_windows() or not hunt.env.has_powershell() then
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    return
end

-- Setup temp folder
tmp = os.getenv("TEMP").."\\ic"
if not path_exists(tmp) then 
    os.execute("mkdir "..tmp)
end
temppath = tmp.."\\icmft.csv"
outpath = tmp.."\\icmft.zip"

-- Install PowerForensics
install_powerforensic()

-- Get MFT w/ Powerforensics
cmd = 'Get-ForensicFileRecord | Export-Csv -NoTypeInformation -Path '..temppath..' -Force'
hunt.debug("Getting MFT with PowerForensics and exporting to "..temppath)
hunt.debug("Executing Powershell command: "..cmd)
ret, output = posh.run_cmd(cmd)
if not ret then 
    hunt.error("Failed to run Get-ForensicFileRecord: "..output)
end

-- Compress results
file = hunt.fs.ls(temppath)
if #file > 0 then
    hunt.debug("Compressing (gzip) " .. temppath .. " to " .. outpath)
    hunt.gzip(temppath, outpath, nil)
else
    hunt.error("PowerForensics MFT Dump failed.")
    return
end

file = hunt.fs.ls(outpath)
if #file > 0 then
    hash = hunt.hash.sha1(temppath)
else
    hunt.error("Compression failed.")
    return
end


-- Recover evidence to S3
instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
recovery = hunt.recovery.s3(s3_user, s3_pass, s3_region, s3_bucket)
s3path_preamble = instancename..'/'..os.date("%Y%m%d")..'/'..host_info:hostname().."/"..s3path_modifier
s3path = s3path_preamble .. '/mft.zip'
hunt.debug("Uploading gzipped MFT (size= "..string.format("%.2f", (file[1]:size()/1000000)).."MB, sha1=".. hash .. ") to S3 bucket " .. s3_region .. ":" .. s3_bucket .. "/" .. s3path)
recovery:upload_file(outpath, s3path)
hunt.log("MFT successfully uploaded to S3.")
hunt.status.good()

-- Cleanup
os.remove(temppath)
os.remove(outpath)
os.remove(logfile)
