--[=[
filetype = "Infocyte Extension"

[info]
name = "Deploy MSDaRT Toolset"
type = "Response"
description = """Deploys Microsoft DaRT tools"""
author = "Coherent Cyber"
guid = "2d34e7d7-86c4-42cd-9fa6-d50605e70bf0"
created = "2020-05-15"
updated = "2020-05-15"

## GLOBALS ##
# Global variables
# -> hunt.global(name = string, default = <type>, isRequired = boolean) 

    [[globals]]

## ARGUMENTS ##
# Runtime arguments
# -> hunt.arg(name = string, default = <type>, isRequired = boolean) 

    [[args]]

]=]

--[=[ SECTION 1: Inputs ]=]

s3path = hunt.global.string("s3_path", false)
if not s3path then
    smbpath = hunt.global.string("smb_path", false, "//10.200.10.13/scannersource/DeployIRTK.zip")
end

tmp = os.getenv("temp")
zippath = tmp.."\\DeployIRTK.zip"
cmdpath = tmp.."\\ScannerSource\\DeployIRTK.cmd"

--[=[ SECTION 2: Functions ]=]

-- FileSystem Functions --
function path_exists(path)
    --[=[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]=] 
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code
    
    -- Download
    out, err = hunt.env.run_powershell(f"Copy-Item -Path '${smbpath}' -Destination '${zippath}'")
    if out or path_exists(zippath) then 
        sha1 = hunt.hash.sha1(zippath)
    else
        hunt.error(f"Could not download files: ${err}")
        --return
    end

    hunt.debug(f"Unzipping ${zippath} to ${tmp}\\..." )
    args = '$ZipPath = "'..zippath..'"\n'
    args = args..'$Tmp = "'..tmp..'"\n'
    unzip_script = args..[=[

        #Unzip
        $shell = new-object -com shell.application
        $zip = $shell.NameSpace($ZipPath)
        foreach($item in $zip.items())
        {
            $shell.Namespace("$Tmp\").copyhere($item)
        }
    ]=]
    hunt.debug("Executing Script:\n"..unzip_script)

    out, err = hunt.env.run_powershell(unzip_script)
    if out or path_exists(cmdpath) then
        hunt.debug(f"Executing ${cmdpath}...")
        os.execute(f"cmd /c ${cmdpath}")
        hunt.log(f"Successfully executed ${path} [zip_sha1=${sha1}]")
        hunt.status.good()
    else
        hunt.error(f"Could not unzip files [zip_sha1=${sha1}]: ${output}")
    end

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code


else
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
end

hunt.debug("Result: Extension successfully executed.")
