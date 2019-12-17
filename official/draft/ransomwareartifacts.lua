--[[
	Infocyte Extension
	Name: Ransomware Artifacts
	Type: Collection
	Description: Searches the hard drive for office documents with specified
		keywords. Returns a csv with a list of files.
        https://docs.google.com/spreadsheets/u/1/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml
	Author: Infocyte
	Created: 20191024
	Updated: 20191024 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)

-- Will recurse these paths
paths = [==[
C:\Users
]==]

--[[
Check file magic number and entropy as second step verification
.{5,} = Any 5 digit or longer extension

]]--
suspicious_file_extensions = [==[
.{5,}|[^a-zA-Z\d\s:]
]==]

--[[
[^a-zA-Z\d\s:] = non-alphanumeric characters
]]--
knownbad_file_extensions = [==[
[^a-zA-Z\d\s:]|enc|R5A|R4A|clf|lock|scl|code|ctbl|ha3|cry|btc|kkk|fun|gws|oor|RDM|RRK|net|cry|enc|vvv|ecc|exx|ezz|abc|aaa|zzz|xyz|biz|xxx|ttt|enc|pzdc|good|0x0|CTBL|CTB2
]==]

filename_regex = [==[

]==]



----------------------------------------------------
-- SECTION 2: Functions

function lines_to_array(text)
    local strarray = {}
    for line in text:gmatch'([^\n]*)([\n]*)' do
        if line ~= nil and line ~= '' then
            table.insert(strarray, line)
        end
    end
    return strarray
end

function make_psstringarray(list)
    -- Converts a lua list (table) into a stringified powershell array
    psarray = "@("
    for _,value in ipairs(list) do
        print("Adding search param: " .. tostring(value))
        psarray = psarray .. "\"".. tostring(value) .. "\"" .. ","
    end
    psarray = psarray:sub(1, -2) .. ")"
    return psarray
end

-- #region initscript
initscript = [==[
#Requires -Version 3.0
function Get-FileSignature {
    [CmdletBinding()]
    Param(
       [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [Alias("PSPath","FullName")]
       [string[]]$Path,
       [parameter()]
       [Alias('Filter')]
       [string]$HexFilter = "*",
       [parameter()]
       [int]$ByteLimit = 2,
       [parameter()]
       [Alias('OffSet')]
       [int]$ByteOffset = 0
    )
    Begin {
        #Determine how many bytes to return if using the $ByteOffset
        $TotalBytes = $ByteLimit + $ByteOffset

        #Clean up filter so we can perform a regex match
        #Also remove any spaces so we can make it easier to match
        [regex]$pattern = ($HexFilter -replace '\*','.*') -replace '\s',''
    }
    Process {
        ForEach ($item in $Path) {
            Try {
                $item = Get-Item -LiteralPath (Convert-Path $item) -Force -ErrorAction Stop
            } Catch {
                Write-Warning "$($item): $($_.Exception.Message)"
                Return
            }
            If (Test-Path -Path $item -Type Container) {
                Write-Warning ("Cannot find signature on directory: {0}" -f $item)
            } Else {
                Try {
                    If ($Item.length -ge $TotalBytes) {
                        #Open a FileStream to the file; this will prevent other actions against file until it closes
                        $filestream = New-Object IO.FileStream($Item, [IO.FileMode]::Open, [IO.FileAccess]::Read)

                        #Determine starting point
                        [void]$filestream.Seek($ByteOffset, [IO.SeekOrigin]::Begin)

                        #Create Byte buffer to read into and then read bytes from starting point to pre-determined stopping point
                        $bytebuffer = New-Object "Byte[]" ($filestream.Length - ($filestream.Length - $ByteLimit))
                        [void]$filestream.Read($bytebuffer, 0, $bytebuffer.Length)

                        #Create string builder objects for hex and ascii display
                        $hexstringBuilder = New-Object Text.StringBuilder
                        $stringBuilder = New-Object Text.StringBuilder

                        #Begin converting bytes
                        For ($i=0;$i -lt $ByteLimit;$i++) {
                            If ($i%2) {
                                [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                            } Else {
                                If ($i -eq 0) {
                                    [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                                } Else {
                                    [void]$hexstringBuilder.Append(" ")
                                    [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                                }
                            }
                            If ([char]::IsLetterOrDigit($bytebuffer[$i])) {
                                [void]$stringBuilder.Append([char]$bytebuffer[$i])
                            } Else {
                                [void]$stringBuilder.Append(".")
                            }
                        }
                        If (($hexstringBuilder.ToString() -replace '\s','') -match $pattern) {
                            $object = [pscustomobject]@{
                                Name = ($item -replace '.*\\(.*)','$1')
                                FullName = $item
                                HexSignature = $hexstringBuilder.ToString()
                                ASCIISignature = $stringBuilder.ToString()
                                Length = $item.length
                                Extension = $Item.fullname -replace '.*\.(.*)','$1'
                            }
                            $object.pstypenames.insert(0,'System.IO.FileInfo.Signature')
                            Write-Output $object
                        }
                    } ElseIf ($Item.length -eq 0) {
                        Write-Warning ("{0} has no data ({1} bytes)!" -f $item.name,$item.length)
                    } Else {
                        Write-Warning ("{0} size ({1}) is smaller than required total bytes ({2})" -f $item.name,$item.length,$TotalBytes)
                    }
                } Catch {
                    Write-Warning ("{0}: {1}" -f $item,$_.Exception.Message)
                }

                #Close the file stream so the file is no longer locked by the process
                $FileStream.Close()
            }
        }
    }
}

function Get-Entropy {
<#
.SYNOPSIS

    Calculates the entropy of a file or byte array.

    PowerSploit Function: Get-Entropy
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.PARAMETER ByteArray

    Specifies the byte array containing the data from which entropy will be calculated.

.PARAMETER FilePath

    Specifies the path to the input file from which entropy will be calculated.

.EXAMPLE

    C:\PS>Get-Entropy -FilePath C:\Windows\System32\kernel32.dll

.EXAMPLE

    C:\PS>ls C:\Windows\System32\*.dll | % { Get-Entropy -FilePath $_ }

.EXAMPLE

    C:\PS>$RandArray = New-Object Byte[](10000)
    C:\PS>foreach ($Offset in 0..9999) { $RandArray[$Offset] = [Byte] (Get-Random -Min 0 -Max 256) }
    C:\PS>$RandArray | Get-Entropy

    Description
    -----------
    Calculates the entropy of a large array containing random bytes.

.EXAMPLE

    C:\PS> 0..255 | Get-Entropy

    Description
    -----------
    Calculates the entropy of 0-255. This should equal exactly 8.

.OUTPUTS

    System.Double

    Get-Entropy outputs a double representing the entropy of the byte array.

.LINK

    http://www.exploit-monday.com
#>

    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $ByteArray,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [IO.FileInfo]
        $FilePath
    )

    BEGIN
    {
        $FrequencyTable = @{}
        $ByteArrayLength = 0
    }

    PROCESS
    {
        if ($PsCmdlet.ParameterSetName -eq 'File')
        {
            $ByteArray = [IO.File]::ReadAllBytes($FilePath.FullName)
        }

        foreach ($Byte in $ByteArray)
        {
            $FrequencyTable[$Byte]++
            $ByteArrayLength++
        }
    }

    END
    {
        $Entropy = 0.0

        foreach ($Byte in 0..255)
        {
            $ByteProbability = ([Double] $FrequencyTable[[Byte]$Byte]) / $ByteArrayLength
            if ($ByteProbability -gt 0)
            {
                $Entropy += -$ByteProbability * [Math]::Log($ByteProbability, 2)
            }
        }

        Write-Output $Entropy
    }
}

Function Get-RansomwareArtifacts {
	param (
		[string]$path = $env:systemroot,
		[string[]]$Strings,
        [string]$Temppath
	)
    $results = @()

}

]==]
-- #endregion

----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() and hunt.env.has_powershell() then
	-- Insert your Windows Code
	hunt.debug("Operating on Windows")
    tempfile = [[c:\windows\temp\icext.csv]]
	-- Create powershell process and feed script/commands to its stdin
	local pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
	pipe:write(initscript) -- load up powershell functions and vars
	pipe:write('Get-RansomwareArtifacts -Temppath ' .. tempfile .. ' -Path ' .. searchpath .. ' -Strings ' .. make_psstringarray(strings))
	r = pipe:close()
	-- hunt.debug("Powershell Returned: "..tostring(r))

	file = io.open(tempfile, "r") -- r read mode
	if file then
        output = file:read("*all") -- *a or *all reads the whole file
        if output then
            hunt.log(output) -- send to Infocyte
            os.remove(temp)
        end
        file:close()
    end

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code

elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end


if output then
    hunt.status.bad()
else
    hunt.status.good()
end


----------------------------------------------------
