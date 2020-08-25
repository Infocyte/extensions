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
# Global variables -> hunt.global('name')

    [[globals]]

## ARGUMENTS ##
# Runtime arguments -> hunt.arg('name')

    [[args]]

]=]

--[=[ SECTION 1: Inputs ]=]
-- validate_arg(arg, obj_type, var_type, is_required, default)
function validate_arg(arg, obj_type, var_type, is_required, default)
    -- Checks arguments (arg) or globals (global) for validity and returns the arg if it is set, otherwise nil

    obj_type = obj_type or "string"
    if var_type == "global" then 
        obj = hunt.global(arg)
    else if var_type == "arg" then
        obj = hunt.arg(arg)
    else 
        hunt.error("ERROR: Incorrect var_type provided. Must be 'global' or 'arg' -- assuming arg")
        error("ERROR: Incorrect var_type provided. Must be 'global' or 'arg' -- assuming arg")
    end

    if is_required and obj == nil then
        msg = "ERROR: Required argument '"..arg.."' was not provided"
        hunt.error(msg); error(msg) 
    end
    if obj ~= nil and type(obj) ~= obj_type then
        msg = "ERROR: Invalid type ("..type(obj)..") for argument '"..arg.."', expected "..obj_type
        hunt.error(msg); error(msg)
    end
    
    if default ~= nil and type(default) ~= obj_type then
        msg = "ERROR: Invalid type ("..type(default)..") for default to '"..arg.."', expected "..obj_type
        hunt.error(msg); error(msg)
    end
    hunt.debug("INPUT[global="..tostring(is_global or false).."]: "..arg.."["..obj_type.."]"..tostring(obj).."; Default="..tostring(default))
    if obj ~= nil and obj ~= '' then
        return obj
    else
        return default
    end
end

s3path = validate_arg("s3_path","string", "global", false)
if not s3path then
    smbpath = validate_arg("smb_path","string", "global", false, "//10.200.10.13/scannersource/DeployIRTK.zip")
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
hostname = host_info:hostname()
if host_info:domain() then 
    hostname = hostname.."."..host_info:domain()
end
hunt.debug("Starting Extention. Hostname: " .. hostname .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
    -- Insert your Windows Code
    
    -- Download
    out, err = hunt.env.run_powershell('Copy-Item -Path "'..smbpath..'" -Destination "'..zippath..'"')
    if out or path_exists(zippath) then 
        sha1 = hunt.hash.sha1(zippath)
    else
        hunt.error("Could not download files: "..err)
        --return
    end

    hunt.debug("Unzipping "..zippath.." to "..tmp.."\\..." )
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
        hunt.debug("Executing "..cmdpath.."...")
        os.execute("cmd /c "..cmdpath)
        hunt.log("Successfully executed "..path.." [zip_sha1="..sha1.."]")
        hunt.status.good()
    else
        hunt.error("Could not unzip files [zip_sha1="..sha1.."]: "..output)
    end

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX-compatible (linux) Code


else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end

hunt.debug("Result: Extension successfully executed.")
