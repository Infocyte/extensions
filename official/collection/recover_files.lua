--[=[
name: Recover Files
filetype: Infocyte Extension
type: Collection
description: |
    Recover custom list of files and folders to your recovery point (S3). 
    S3 Path Format= <s3bucket>:<instancename>/<date>/<hostname>/<s3path_modifier>/<filename>
    Loads Powerforensics to bypass file locks. Currently only works on Windows
author: Infocyte
guid: 55f3d0f0-476a-44fe-a583-21e110c74541
created: 2019-11-23
updated: 2020-12-14


# Global variables
globals:
- s3_keyid:
    description: S3 Bucket key Id for uploading
    type: string

- s3_secret:
    description: S3 Bucket key Secret for uploading
    type: secret

- s3_region:
    description: S3 Bucket key Id for uploading. Example='us-east-2'
    type: string
    required: true

- s3_bucket:
    description: S3 Bucket name for uploading
    type: string
    required: true

- proxy:
    description: Proxy info. Example='myuser:password@10.11.12.88:8888'
    type: string
    required: false

- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false

- disable_powershell:
    description: Does not use powershell
    type: boolean
    default: false
    required: false


# Runtime arguments
args:
- path:
    description: | 
        Path(s) to recover. Accepts comma-seperated list of files and/or folders to recover.
        Acceptable formats (escape backslashes)
            String literal (file)= [[c:/bad.exe]],
            Escaped string (file)= "c:/users/adama/ntuser.dat", 
            Escaped folder (folder)= "c:\\windows\\temp\\"
    type: string
    required: true

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

-- Provide paths below (full file path or folders). Folders will take everything
-- in the folder.
-- Format them any of the following ways
-- NOTE: '\' needs to be escaped unless you make a explicit string like this: [[string]])

path = hunt.arg.string("path", true)

-- Powerforensics can be used to bypass file locks
use_powerforensics = not hunt.global.boolean("disable_powershell", false, false)

local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, true)
proxy = hunt.global.string("proxy", false)
s3_keyid = hunt.global.string("s3_keyid", false)
s3_secret = hunt.global.string("s3_secret", false)
s3_region = hunt.global.string("s3_region", true)
s3_bucket = hunt.global.string("s3_bucket", true)
s3path_modifier = "evidence"


--[=[ SECTION 2: Functions ]=]


function string_to_list(str)
    -- Converts a comma seperated list to a lua list object
    local newlist = {}
    for line in string.gmatch(str, '([^,]+)') do
        local l = line:gsub("^%s*(.-)%s*$", "%1")
        table.insert(newlist, l)
    end
    return newlist
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

-- Infocyte Powershell Functions --

-- PowerForensics (optional)
function install_powerforensics()
    --[=[
        Checks for NuGet and installs Powerforensics
        Output: [bool] Success
    ]=]
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
    out, err = hunt.env.run_powershell(script)
    if out then 
        hunt.log(f"Powershell Succeeded: ${out}")
        return true
    else 
        hunt.error(f"Powershell Failed: ${err}")
        return false
    end
end

--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

-- Make tempdir
logfolder = os.getenv("temp").."\\ic"
if not path_exists(logfolder) then os.execute("mkdir "..logfolder) end

if use_powerforensics and hunt.env.has_powershell() then
    installed = install_powerforensics()
    hunt.log(f"PowerForensics was installed: ${installed}")
end


instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
s3 = hunt.recovery.s3(s3_keyid, s3_secret, s3_region, s3_bucket)
s3path_preamble = f"${instancename}/${os.date('%Y%m%d')}/${host_info:hostname()}/${s3path_modifier}"

paths = string_to_list(path)

hunt.log("Uploaded evidence can be accessed here:")
hunt.log(f"https://s3.console.aws.amazon.com/s3/buckets/${s3_bucket}/${s3path_preamble}/?region=${s3_region}&tab=overview")

for i, p in pairs(paths) do
    hunt.log(f"Finding file: ${p}")
    files = hunt.fs.ls(p)
    if files and #files > 0 then 
        for _, p2 in pairs(files) do
            path = p2
            -- If file is being used or locked, this copy will get passed it (usually)
            outpath = os.getenv("temp").."\\ic\\"..path:name()
            infile, err = io.open(path:path(), "rb")
            if not infile and use_powerforensics and hunt.env.has_powershell() then
                -- Assume file locked by kernel, use powerforensics to copy
                cmd = f"Copy-ForensicFile -Path '${path:path()}' -Destination '${outpath}'"
                hunt.log(f"File Locked. Executing: ${cmd}")
                ret, out = powershell.run_cmd(cmd)
                hunt.log(f"Powerforensics output: ${out}")
            elseif not infile then
                hunt.error(f"Could not open ${path:path()} [${err}].\nTry enabling powerforensics to bypass file lock.")
                goto continue
            else
                data = infile:read("*all")
                infile:close()

                outfile = io.open(outpath, "wb")
                outfile:write(data)
                outfile:flush()
                outfile:close()
            end

            -- Hash the file copy
            if path_exists(outpath) then
                hash = hunt.hash.sha1(outpath)
                s3path = s3path_preamble.."/"..path:name().."-"..hash
                link = f"https://${s3_bucket}.s3.${s3_region}.amazonaws.com/${s3path}"

                -- Upload to S3
                success, err = s3:upload_file(outpath, s3path)
                if success then
                    hunt.log(f"Uploaded ${path:path()} (sha1=${hash}) to S3 at:")
                    hunt.log(link)
                else
                    hunt.error(f"Error on s3 upload of ${path:path()}: ${err}")
                end

                os.remove(outpath)
            else
                hunt.error(f"File read/copy failed on ${path:path()}")
            end
            ::continue::
        end
    else
        hunt.warn(f"No files found at: ${p}")
    end
end
os.execute(f"RMDIR /S/Q ${os.getenv('temp')}\\ic")
