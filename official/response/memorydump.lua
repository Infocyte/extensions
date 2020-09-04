--[=[
filetype = "Infocyte Extension"

[info]
name = "Memory Extraction"
type = "Response"
description = """Uses winpmem/linpmem to dump full physical memory and
       stream it to an S3 bucket, ftp server, or smb share. If output path not
       specified, will dump to local temp folder.
       Source:
       https://github.com/Velocidex/c-aff4/releases/tag/v3.3.rc3
       http://releases.rekall-forensic.com/v1.5.1/linpmem-2.1.post4
       http://releases.rekall-forensic.com/v1.5.1/osxpmem-2.1.post4.zip
       Instructions:
       https://holdmybeersecurity.com/2017/07/29/rekall-memory-analysis-framework-for-windows-linux-and-mac-osx/"""
author = "Infocyte"
guid = "89abebc6-d0db-4eba-b771-6a2652033581"
created = "2019-9-19"
updated = "2020-07-27"

## GLOBALS ##
# Global variables
# -> hunt.global(name = string, default = <type>, isRequired = boolean) 

    [[globals]]
    name = "s3_keyid"
    description = "S3 Bucket key Id for uploading"
    type = "string"

    [[globals]]
    name = "s3_secret"
    description = "S3 Bucket key Secret for uploading"
    type = "secret"

    [[globals]]
    name = "s3_region"
    description = "S3 Bucket key Id for uploading. Example: 'us-east-2'"
    type = "string"
    required = true

    [[globals]]
    name = "s3_bucket"
    description = "S3 Bucket name for uploading"
    type = "string"
    required = true

    [[globals]]
    name = "proxy"
    description = "Proxy info. Example: myuser:password@10.11.12.88:8888"
    type = "string"
    required = false

    [[globals]]
    name = "debug"
    description = "Print debug information"
    type = "boolean"
    default = false
    required = false

## ARGUMENTS ##
# Runtime arguments
# -> hunt.arg(name = string, default = <type>, isRequired = boolean) 

    [[args]]


]=]

--[=[ SECTION 1: Inputs ]=]


hash_image = false -- set to true if you need the sha1 of the memory image
timeout = 6*60*60 -- 6 hours to upload?

local debug = hunt.global.boolean("debug", false, false)
proxy = hunt.global.string("proxy", false)
s3_keyid = hunt.global.string("s3_keyid", false)
s3_secret = hunt.global.string("s3_secret", false)
s3_region = hunt.global.string("s3_region", true)
s3_bucket = hunt.global.string("s3_bucket", true)
s3path_modifier = "memory"

--[=[ SECTION 2: Functions ]=]

function tempfolder()
    -- Returns OS-specific temp folder
    if hunt.env.is_macos() then
        tempfolder = os.getenv("TMPDIR")
    else
        -- works on windows
        tempfolder = os.getenv("temp")
    end
    if tempfolder then
        return tempfolder
    else
        -- default to /tmp if nil
        return '/tmp'
    end
end


--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

-- Download os-specific pmem
mempath = tempfolder().."/physmem.map"
pmempath = tempfolder().. '/pmem.exe'

if hunt.env.is_windows() then
    -- Insert your Windows code
    url = "https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/winpmem_v3.3.rc3.exe"

    -- Download pmem
    client = hunt.web.new(url)
    if proxy then
        client:proxy(proxy)
    end
    client:download_file(pmempath)

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code
    -- url = "https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip"
    -- url = "https://github.com/Velocidex/c-aff4/releases/download/3.2/osxpmem_3.2.zip"
    url = "https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/osxpmem_3.2.zip"
    pmemzippath = tempfolder() .. '/pmem.zip'
    -- Download pmem
    client = hunt.web.new(url)
    if proxy then
        client:proxy(proxy)
    end
    client:download_file(pmemzippath)
    os.execute(f"unzip ${pmemzippath}")
    pmempath = "./osxpmem.app/osxpmem"
    os.execute("kextutil -t osxpmem.app/MacPmem.kext/")
    os.execute("chown -R root:wheel osxpmem.app/")
    os.remove(pmemzippath)

elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code
    -- url = "https://github.com/google/rekall/releases/download/v1.5.1/linpmem-2.1.post4"
    -- url = "https://github.com/Velocidex/c-aff4/releases/download/v3.3.rc1/linpmem-v3.3.rc1"
    url = "https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/linpmem-v3.3.rc1"
    -- Download pmem
    client = hunt.web.new(url)
    if proxy then
        client:proxy(proxy)
    end
    client:download_file(pmempath)
    os.execute("chmod +x "..pmempath)

else
    hunt.warn(f"WARNING: Not a compatible operating system for this extension [${host_info:os()}]")
    return
end


-- Dump Memory to disk
hunt.debug(f"Memory dump on ${host_info:os()} host started to local path ${mempath}")
-- os.execute("winpmem.exe --output - --format map | ")    --split 1000M
result = os.execute(f"${pmempath} --output ${mempath} --format map --split 500M")
if not result then
  hunt.error(f"Winpmem driver failed. [Error: ${result}]")
  exit()
end


-- Scans have 1 hour timeouts currently so we're gunna spawn a background task to
-- upload it in case it takes a few hours.
if s3_keyid then
    script = f"recovery = hunt.recovery.s3('${s3_keyid}', '${s3_secret}', '${s3_region}','${s3_bucket}')\n"
else
    script = f"recovery = hunt.recovery.s3(nil, nil, '${s3_region}','${s3_bucket}')\n"
end

instance = hunt.net.api()
if instance == '' then
    instancename = 'offline'
elseif instance:match("infocyte") then
    -- get instancename
    instancename = instance:match("(.+).infocyte.com")
end
s3path_preamble = f"${instancename}/${os.date('%Y%m%d')}/${host_info:hostname()}/${s3path_modifier}"

for _, path in pairs(hunt.fs.ls(tempfolder())) do
    if (path:path()):match("physmem") then
        if hash_image then
            hash = hunt.hash.sha1(mempath)
        else
            hash = 'Hashing Skipped'
        end
        s3path = s3path_preamble.."/"..path:name()
        link = "https://${s3_bucket}.s3.${s3_region}.amazonaws.com/${s3path}"
        hunt.log("Scheduling the Upload of Memory Dump ${s3path} (sha1=${hash}) to S3 at ${link}")
        script = script .. f"recovery:upload_file([[${path:path()}]], '${s3path}')\n"
        script = script .. f"os.remove([[${path:path()}]])\n"
    end
end


-- Schedule Background Task to Recover Memory to S3
if hunt.env.is_windows() then
    -- write background extension
    scriptpath = tempfolder().."\\upload.lua"
    scriptfile = io.open(scriptpath, "w")
    scriptfile:write(script)
    scriptfile:close()
    -- Retain survey for background task
    bgsurveypath = 'C:\\windows\\temp\\survey2.exe'
    os.execute('Powershell.exe -nologo -nop -command "Copy-Item C:\\windows\\temp\\s1.exe  -Destination '..bgsurveypath..' -Force')

    -- Use Scheduled Tasks
    os.execute('SCHTASKS /CREATE /SC ONCE /RU "SYSTEM" /TN "Infocyte\\Upload" /TR "cmd.exe /c '..bgsurveypath..' -r '..timeout..' --only-extensions --extensions '..scriptpath..'" /ST 23:59 /F')
    os.execute('SCHTASKS /RUN /TN "Infocyte\\Upload"')

else
    -- write background extension
    scriptpath = tempfolder().."/upload.lua"
    scriptfile = io.open(scriptpath, "w")
    scriptfile:write(script)
    scriptfile:close()

    -- Retain survey for background task
    bgsurveypath = '/tmp/survey2.bin'
    os.execute("sudo chmod +x "..bgsurveypath)

    if hunt.env.is_macos() then
        -- Enable at command
        os.execute("atrun_plist=/System/Library/LaunchDaemons/com.apple.atrun.plist")
        os.execute("sudo sed -i '' 's/true/false/g' $atrun_plist")
        os.execute("sudo launchctl unload -F $atrun_plist")
        os.execute("sudo launchctl load -F $atrun_plist")

    elseif hunt.env.is_linux() or hunt.env.has_sh() then
        -- Enable at command
        if not os.execute('dpkg -s at | grep Status') then
            os.execute('sudo apt-get install at')
        end

    end
    -- use at command
    os.execute('#!/bin/sh\n"'..bgsurveypath..' -r '..timeout..' --only-extensions --extensions '..scriptpath..'" > /tmp/icat.sh')
    os.execute('sudo at now +1 minutes -f /tmp/icat.sh')
end

os.remove(pmempath)
hunt.status.good()
