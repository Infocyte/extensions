--[=[
    Useful functions you may want to include in your scripts:

]=]


-- PowerForensics (optional)
function install_powerforensics()
    --[=[
        Checks for NuGet and installs Powerforensics
        Output: [bool] Success
    ]=]
    script = [=[
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
    ]=]
    out, err = hunt.env.run_powershell(script)
    if out then 
        hunt.log(f"[install_powerforensics] Succeeded:\n${out}")
        return true
    else 
        hunt.error(f"[install_powerforensics] Failed:\n${err}")
        return false
    end
end

function list_to_pslist(list)
    --[=[
        Converts a lua list (table) into a stringified powershell array that can be passed to Powershell
        Input:  [list]list -- Any list with (_, val) format
        Output: [string] -- Example = '@("Value1","Value2","Value3")'
    ]=] 
    psarray = "@("
    for _,value in ipairs(list) do
        -- print("Param: " .. tostring(value))
        psarray = psarray .. "\"".. tostring(value) .. "\"" .. ","
    end
    psarray = psarray:sub(1, -2) .. ")"
    return psarray
end

-- Python functions --
python = {}
function python.run_command(command)
    --[=[
        Execute a python command
        Input:  [string] python command
        Output: [bool] Success    
                [string] Results
    ]=]
    os.execute("python -q -u -c \"" .. command.. "\"" )
end
function python.run_script(pyscript)
    --[=[
        Execute a python command
        Input:  [string] python script
        Output: [bool] Success
                [string] Results
    ]=]
    
    tempfile = os.getenv("tmp").."/icpython_"..os.tmpname()..".log"

    pipe = io.popen("python -q -c - > "..tempfile, "w")
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


-- FileSystem functions --
function path_exists(path)
    --[=[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]=] 

   ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end


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
    f,msg = io.open(path, "rb")
    if not f then
        hunt.error(msg)
        return nil
    end
    bytes = f:read(4)
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
    --[=[
        Returns a list of userfolders to iterate through
        Output: [list]ret -- List of userfolders (_, path)
    ]=]
    paths = {}
    u = {}
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
    --[=[
        Returns all the userSIDs in the registry to aid in iterating through registry user profiles
        Output: [list] Usersid strings -- A list of usersids in format: (_, '\\registry\user\<usersid>')
    ]=] 
    output = {}
    -- Iterate through each user profile's and list their keyboards
    user_sids = hunt.registry.list_keys("\\Registry\\User")
    for _,user_sid in pairs(user_sids) do
        table.insert(output, user_sid)
    end
    return output
end

function reg.search(path, indent)
    --[=[
        Returns all the userSIDs in the registry to aid in iterating through registry user profiles
        Input:  [string] Registry path -- \\registry\machine\key
                [int] (do not use manually) indent spaces for recursive printing of sub keys
        Output: [list]  -- A list of keys that the string was found in. format = (key, string)
    ]=] 
    indent = indent or 0
    output = {}
    values = hunt.registry.list_values(path)
    print(string.rep("=", indent) .. path)
    for name,value in pairs(values) do
        print(string.rep(" ", indent) .. name .. ": " .. value)
        table.insert(output, value)
    end
    subkeys = hunt.registry.list_keys(path)
    if subkeys then
        for _,subkey2 in pairs(subkeys) do
            r = reg.search(path .. "\\" .. subkey2, indent + 2)
            for _,val in pairs(r) do
                table.insert(output, val)
            end
        end
    end
    return output
end


-- Lua Debug Helpers --

function print_table(tbl, indent)
    --[=[
        Prints a table -- used for debugging table contents
        Input:  [list] table/list
                [int] (do not use manually) indent spaces for recursive printing of sub lists
        Output: [string]  -- stringified version of the table
    ]=] 
    indent = indent or 0
    toprint = ""
    if not tbl then return toprint end
    if type(tbl) ~= "table" then 
        print(f"print_table error: Not a table. ${tbl}")
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


-- Infocyte Agent functions --
function is_agent_installed()
    --[=[
    Determines if infocyte agent is installed
    Output: [bool]ret -- true or false
    ]=]
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
    --[=[
        Upload a file to FTP address
        Input:  [string]path -- Path to file (i.e. "C:\\windows\\temp\\asdf.zip")
                [string]address -- FTP Address (i.e. "ftp://ftp.infocyte.com/folder/asdf.zip")
                [string]username -- ftp user
                [string]password -- ftp pass
        Output: [bool]ret -- Success bool
                [string]output -- Output message
    ]=]
    if hunt.env.has_powershell() then 
        script = '$Path = "'..path..'"\n'
        script = script..'$address = "'..address..'"\n' -- "ftp://localhost/me.png"
        script = script..'$username = "'..username..'"\n' -- "anonymous"
        script = script..'$password = "'..password..'"\n' -- "joe@bob.com"
        script = script..[=[
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
        ]=]
        out, err = hunt.env.run_powershell(script)
        if not out then 
            hunt.error(f"Failure: ${err}")
            return false
        end
        return true
    end
end

function ftp.download(path, address, username, password)
    --[=[
        Download a file to FTP address
        Input:  [string]path -- save path (i.e. "C:\\windows\\temp\\asdf.zip")
                [string]address -- FTP Address of file (i.e. "ftp://ftp.infocyte.com/folder/asdf.zip")
                [string]username -- ftp user
                [string]password -- ftp pass
        Output: [bool]ret -- Success bool
                [string]output -- Output message
    ]=]
    if hunt.env.has_powershell() then 
        script = '$Path = "'..path..'"\n'
        script = script..'$address = "'..address..'"\n' -- "ftp://localhost/me.png"
        script = script..'$username = "'..username..'"\n' -- "anonymous"
        script = script..'$password = "'..password..'"\n' -- "joe@bob.com"
        script = script..[=[
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
           
            # Create the target file on the system and the download buffer
            $LocalFileFile = New-Object IO.FileStream ($Path,[IO.FileMode]::Create)
            [byte[]]$ReadBuffer = New-Object byte[] 1024
            # Loop through the download
            do {
                $ReadLength = $ResponseStream.Read($ReadBuffer,0,1024)
                $LocalFileFile.Write($ReadBuffer,0,$ReadLength)
            }
            while ($ReadLength -ne 0)
            return true
        ]=]
        out, err = hunt.env.run_powershell(script)
        if not out then 
            hunt.error("Failure: "..err)
            return false
        end
        return true
    end
end


-- Misc Helpers

function parse_csv(path, sep)
    --[=[
        Parses a CSV on disk into a lua list.
        Input:  [string]path -- Path to csv on disk
                [string]sep -- CSV seperator to use. defaults to ','
        Output: [list]
    ]=] 
    sep = sep or ','
    csvFile = {}
    file,msg = io.open(path, "r")
    if not file then
        hunt.error(f"CSV Parser failed: ${msg}")
        return nil
    end
    header = {}
    for line in file:lines() do
        n = 1
        fields = {}
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


