--[[
    Useful functions you may want to include in your scripts:

    1. Powershell Library [powershell.*] -- Powershell functions to make it easier to execute PS commands and scripts.
    2. Filesystem -- functions to simplify common filesystem tasks
    3. Registry -- functions to simplify common windows registry lookups and tasks

]]

-- Infocyte Powershell Functions --
powershell = {}
function powershell.run_command(command)
    --[[
        Input:  [String] Small Powershell Command
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        throw "Powershell not found."
    end

    if not command or (type(command) ~= "string") then 
        throw "Required input [String]command not provided."
    end

    print("[PS] Initiatializing Powershell to run Command: "..command)
    cmd = ('powershell.exe -nologo -nop -command "& {'..command..'}"')
    pipe = io.popen(cmd, "r")
    output = pipe:read("*a") -- string output
    ret = pipe:close() -- success bool
    return ret, output
end

function powershell.run_script(psscript)
    --[[
        Input:  [String] Powershell script. Ideally wrapped between [==[ ]==] to avoid possible escape characters.
        Output: [Bool] Success
                [String] Output
    ]]
    debug = debug or true
    if not hunt.env.has_powershell() then
        throw "Powershell not found."
    end

    if not psscript or (type(psscript) ~= "string") then 
        throw "Required input [String]script not provided."
    end

    os.execute("mkdir "..os.getenv("systemroot").."\\temp\\ic")
    print("Initiatializing Powershell to run Script")

    local tempfile = os.getenv("systemroot").."\\temp\\ic"..os.tmpname().."script.ps1"
    local f = io.open(tempfile, 'w')
    script = "# Ran via Infocyte Powershell Extension\n"..psscript
    f:write(script) -- Write script to file
    f:close()

    -- Feed script to Invoke-Expression to execute
    -- This method bypasses translation issues with popen's cmd -> powershell -> cmd -> lua shinanigans
    local cmd = 'powershell.exe -nologo -nop -command "gc '..tempfile..' | Out-String | iex'
    print("Executing: "..cmd)
    local pipe = io.popen(cmd, "r")
    local output = pipe:read("*a") -- string output
    if debug then 
        for line in string.gmatch(output,'[^\n]+') do
            if line ~= '' then print("[PS]: "..line) end
        end
    end
    local ret = pipe:close() -- success bool
    os.remove(tempfile)
    if ret and string.match( output, 'FullyQualifiedErrorId' ) then
        ret = false
    end
    return ret, output
end

-- PowerForensics (optional)
function powershell.install_powerforensics()
    --[[
        Checks for NuGet and installs Powerforensics
        Output: [bool] Success
    ]]
    if not powershell then 
        hunt.error("Infocyte's powershell lua functions are not available. Add Infocyte's powershell.* functions.")
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
        } else {
            Write-Host "Powerforensics Already Installed. Continuing."
        }
    ]==]
    ret, output = powershell.run_script(script)
    if ret then 
        hunt.debug("[install_powerforensics] Succeeded:\n"..output)
    else 
        hunt.error("[install_powerforensics] Failed:\n"..output)
    end
    return ret
end

function powershell.list_to_pslist(list)
    --[[
        Converts a lua list (table) into a stringified powershell array that can be passed to Powershell
        Input:  [list]list -- Any list with (_, val) format
        Output: [string] -- Example = '@("Value1","Value2","Value3")'
    ]] 
    psarray = "@("
    for _,value in ipairs(list) do
        -- print("Param: " .. tostring(value))
        psarray = psarray .. "\"".. tostring(value) .. "\"" .. ","
    end
    psarray = psarray:sub(1, -2) .. ")"
    return psarray
end

-- Python Functions --
py = {}
function py.run_command(command)
    --[[
        Execute a python command
        Input:  [string] python command
        Output: [bool] Success    
                [string] Results
    ]]
    os.execute("python -q -u -c \"" .. cmd.. "\"" )
end
function py.run_script(pyscript)
    --[[
        Execute a python command
        Input:  [string] python script
        Output: [bool] Success
                [string] Results
    ]]
    
    tempfile = os.getenv("tmp").."/icpython_"..os.tmpname()..".log"

    io.popen("python -q -c - > "..tempfile, "w")
    pipe:write(pyscript)
    ret = pipe:close() -- success bool

    -- Get output
    file, output = io.open(tempfile, "r")
    if file then
        output = file:read("*all") -- String Output
        file:close()
        os.remove(tempfile)
    else 
        print("Python script failed to run: "..output)
    end
    return ret, output
end


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

function is_executable(path)
    --[[
        Check if a file is an executable (PE or ELF) by magic number. 
        Input:  [string]path
        Output: [bool] Is Executable
    ]] 
    magicnumbers = {
        "MZ",
        ".ELF"
    }
    local f,msg = io.open(path, "rb")
    if not f then
        hunt.error(msg)
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

function userfolders()
    --[[
        Returns a list of userfolders to iterate through
        Output: [list]ret -- List of userfolders (_, path)
    ]]
    local paths = {}
    local u = {}
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        if (userfolder:full()):match("Users") then
            if not u[userfolder:full()] then
                -- filter out links like "Default User" and "All Users"
                u[userfolder:full()] = true
                table.insert(paths, userfolder:path())
            end
        end
    end
    return paths
end


-- Registry functions --
reg = {}
function reg.usersids()
    --[[
        Returns all the userSIDs in the registry to aid in iterating through registry user profiles
        Output: [list] Usersid strings -- A list of usersids in format: (_, '\\registry\user\<usersid>')
    ]] 
    local output = {}
    -- Iterate through each user profile's and list their keyboards
    user_sids = hunt.registry.list_keys("\\Registry\\User")
    for _,user_sid in pairs(user_sids) do
        table.insert(output, user_sid)
    end
    return output
end

function reg.search(path, indent)
    --[[
        Returns all the userSIDs in the registry to aid in iterating through registry user profiles
        Input:  [string] Registry path -- \\registry\machine\key
                [int] (do not use manually) indent spaces for recursive printing of sub keys
        Output: [list]  -- A list of keys that the string was found in. format = (key, string)
    ]] 
    indent = indent or 0
    local output = {}
    values = hunt.registry.list_values(path)
    print(string.rep("=", indent) .. path)
    for name,value in pairs(values) do
        print(string.rep(" ", indent) .. name .. ": " .. value)
        table.insert(output, value)
    end
    subkeys = hunt.registry.list_keys(path)
    if subkeys then
        for _,subkey2 in pairs(subkeys) do
            r = registry_search(path .. "\\" .. subkey2, indent + 2)
            for _,val in pairs(r) do
                table.insert(output, val)
            end
        end
    end
    return output
end


-- Lua Debug Helpers --

function print_table(tbl, indent)
    --[[
        Prints a table -- used for debugging table contents
        Input:  [list] table/list
                [int] (do not use manually) indent spaces for recursive printing of sub lists
        Output: [string]  -- stringified version of the table
    ]] 
    if not indent then indent = 0 end
    local toprint = ""
    if not tbl then return toprint end
    if type(tbl) ~= "table" then 
        print("print_table error: Not a table. "..tostring(tbl))
        return toprint
    end
    for k, v in pairs(tbl) do
        toprint = toprint .. string.rep(" ", indent)
        toprint = toprint .. tostring(k) .. ": "
        if (type(v) == "table") then
            toprint = toprint .. print_table(v, indent + 2) .. "\r\n"
        else
            toprint = toprint .. tostring(v) .. "\r\n"
        end
    end
    print(toprint)
    return toprint
end


-- Infocyte Agent Functions --
function is_agent_installed()
    --[[
    Determines if infocyte agent is installed
    Output: [bool]ret -- true or false
    ]]
	if hunt.env.is_windows() then
		key = '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\HUNTAgent'
		if hunt.registry.list_values(key) then
			return true
		else
			return false
		end

	elseif hunt.env.is_macos() then
		installpath = [[/bin/infocyte/agent.exe]]
		if path_exists(installpath) then
			return true
		else
			return false
		end
	elseif hunt.env.is_linux() or hunt.env.has_sh() then
		installpath = [[/bin/infocyte/agent.exe]]
		if path_exists(installpath) then
			return true
		else
			return false
		end
	else
		return false
	end
end


-- FTP Recovery Option --
ftp = {}
function ftp.upload(path, address, username, password)
    --[[
        Upload a file to FTP address
        Input:  [string]path -- Path to file (i.e. "C:\\windows\\temp\\asdf.zip")
                [string]address -- FTP Address (i.e. "ftp://ftp.infocyte.com/folder/asdf.zip")
                [string]username -- ftp user
                [string]password -- ftp pass
        Output: [bool]ret -- Success bool
                [string]output -- Output message
    ]]
    if hunt.env.has_powershell() then 
        script = '$Path = "'..path..'"\n'
        script = script..'$address = "'..address..'"\n' -- "ftp://localhost/me.png"
        script = script..'$username = "'..username..'"\n' -- "anonymous"
        script = script..'$password = "'..password..'"\n' -- "joe@bob.com"
        script = script..[==[
            # create the FtpWebRequest and configure it
            $ftp = [System.Net.FtpWebRequest]::Create($address)
            $ftp = [System.Net.FtpWebRequest]$FTP
            $ftp.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
            $ftp.Credentials = new-object System.Net.NetworkCredential($Username, $Password)
            $ftp.UseBinary = $true
            $ftp.UsePassive = $true

            # Read the File for Upload
            $FileContent = [System.IO.File]::ReadAllBytes($Path)
            $ftp.ContentLength = $FileContent.Length
            
            # Get Stream Request by bytes
            try {
                $Run = $ftp.GetRequestStream()
                $Run.Write($FileContent, 0, $FileContent.Length)
            }
            catch {
                Return "Failure: Could not upload to ftp. $($_.Message)"
            }
            finally {
                # Cleanup
                $Run.Close()
                $Run.Dispose()
            }
        ]==]
        ret, output = powershell.run_script(script)
        if not ret then 
            print("Failure: "..output)
        end
        return ret
    end
end

function ftp.download(path, address, username, password)
    --[[
        Download a file to FTP address
        Input:  [string]path -- Local save path (i.e. "C:\\windows\\temp\\asdf.zip")
                [string]address -- FTP Address of file (i.e. "ftp://ftp.infocyte.com/folder/asdf.zip")
                [string]username -- ftp user
                [string]password -- ftp pass
        Output: [bool]ret -- Success bool
                [string]output -- Output message
    ]]
    if hunt.env.has_powershell() then 
        script = '$Path = "'..path..'"\n'
        script = script..'$address = "'..address..'"\n' -- "ftp://localhost/me.png"
        script = script..'$username = "'..username..'"\n' -- "anonymous"
        script = script..'$password = "'..password..'"\n' -- "joe@bob.com"
        script = script..[==[
            # create the FtpWebRequest and configure it
            $ftp = [System.Net.FtpWebRequest]::Create($address)
            $ftp = [System.Net.FtpWebRequest]$FTP
            $ftp.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
            $ftp.Credentials = new-object System.Net.NetworkCredential($Username, $Password)
            $ftp.UseBinary = $true
            $ftp.KeepAlive = $false

           
            try {
                # Send the ftp request
                $FTPResponse = $FTPRequest.GetResponse()
                # Get a download stream from the server response
                $ResponseStream = $FTPResponse.GetResponseStream()
            }
            catch {
                Return "Failure: Could not download from ftp. $($_.Message)"
            }
           
            # Create the target file on the local system and the download buffer
            $LocalFileFile = New-Object IO.FileStream ($Path,[IO.FileMode]::Create)
            [byte[]]$ReadBuffer = New-Object byte[] 1024
            # Loop through the download
            do {
                $ReadLength = $ResponseStream.Read($ReadBuffer,0,1024)
                $LocalFileFile.Write($ReadBuffer,0,$ReadLength)
            }
            while ($ReadLength -ne 0)
            return true              
        ]==]
        ret, output = powershell.run_script(script)
        if not ret then 
            print("Failure: "..output)
        end
        return ret
    end
end


-- Misc Helpers

function parse_csv(path, sep)
    --[[
        Parses a CSV on disk into a lua list.
        Input:  [string]path -- Path to csv on disk
                [string]sep -- CSV seperator to use. defaults to ','
        Output: [list]
    ]] 
    tonum = true
    sep = sep or ','
    local csvFile = {}
    local file,msg = io.open(path, "r")
    if not file then
        hunt.error("CSV Parser failed: ".. msg)
        return nil
    end
    local header = {}
    for line in file:lines() do
        local n = 1
        local fields = {}
        if not line:match("^#TYPE") then 
            for str in string.gmatch(line, "([^"..sep.."]+)") do
                s = str:gsub('"(.+)"', "%1")
                if not s then 
                    hunt.debug(line)
                    hunt.debug('column: '..v)
                end
                if #header == 0 then
                    fields[n] = s
                else
                    v = header[n]
                    fields[v] = tonumber(s) or s
                end
                n = n + 1
            end
            if #header == 0 then
                header = fields
            else
                table.insert(csvFile, fields)
            end
        end
    end
    file:close()
    return csvFile
end


--[[ TESTS ]]
-- Test lua functions
if not path_exists("C:\\windows\\temp\\test.csv") then

end

print("======= Testing useful lua functions ==========")
print(powershell.run_command('Get-Process'))
script = [==[
$a = Get-Process | where { $_.name -eq 'svchost' }
$a | export-csv "C:\windows\temp\test.csv"
]==]
print(powershell.run_script(script))

print('filename: '..get_filename("C:\\windows\\temp\\test.csv"))
print('file extension: '..get_fileextension("C:\\windows\\temp\\test.csv"))
file = io.open("C:\\windows\\temp\\test.csv", "r")
print(file:read("a*"))
file:close()

csv = parse_csv("C:\\windows\\temp\\test.csv")
for _, p in pairs(csv) do 
    print_table(p)
    break
end

for k, p in pairs(userfolders()) do 
    print("Userfolder["..k.."]: "..tostring(p))
end

if (path_exists("C:\\windows\\system32\\calc.exe")) then
    print("Is calc.exe executable: "..is_executable("C:\\windows\\system32\\calc.exe"))
end

for k, val in pairs(reg.get_usersids()) do
    print("UserSID["..k.."]:"..val)
end

--services = reg.search("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\services", "LanmanServer")

