
--[[
    Infocyte Extension
    Name: Deploy MSDaRT Toolset
    Type: Action
    Description: | Deploys Microsoft DaRT tools |
    Author: Infocyte
    Guid: 2d34e7d7-86c4-42cd-9fa6-d50605e70bf0
    Created: 20200515
    Updated: 20200515
--]]


--[[ SECTION 1: Inputs --]]

s3path = nil
--OR
smbpath = "//10.200.10.13/scannersource/DeployIRTK.zip"

tmp = os.getenv("temp")
zippath = tmp.."\\DeployIRTK.zip"
cmdpath = tmp.."\\ScannerSource\\DeployIRTK.cmd"


--[[ SECTION 2: Functions --]]

-- FileSystem Functions --
function path_exists(path)
    --[[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]] 
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

--[[ SECTION 3: Actions --]]

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
