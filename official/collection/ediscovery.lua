--[[
	Infocyte Extension
	Name: E-Discovery
	Type: Collection
	Description: Proof of Concept. Searches the hard drive for office documents
        with specified keywords. Returns a csv with a list of files.
	Author: Infocyte
	Created: 20190919
	Updated: 20190919 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)
strings = {'Gerritz', 'test'}
searchpath = [[C:\Users]]



----------------------------------------------------
-- SECTION 2: Functions

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

Function Get-StringsMatch {
	param (
		[string]$path = $env:systemroot,
		[string[]]$Strings,
        [string]$Temppath,
		[int]$charactersAround = 30
	)
    $results = @()
	try {
		$application = New-Object -comobject word.application
	} catch {
		throw "Error opening com object"
	}
    $application.visible = $False
    $files = Get-Childitem $path -recurse -filter *.doc |
            Get-FileSignature | where { $_.HexSignature -match "504B|D0CF" }
    # Loop through all *.doc files in the $path directory
    Foreach ($file In $files) {
		try {
			$document = $application.documents.open($file.FullName,$false,$true)
		} catch {
			Write-Warning "Could not open $($file.FullName)"
            $properties = @{
               File = $file.FullName
               Filesize = $Null
               Match = "ERROR: Could not open file"
               TextAround = $Null
            }
            $results += New-Object -TypeName PsCustomObject -Property $properties
			continue
		}
        $range = $document.content
		$filesize = [math]::Round((Get-Item $file.FullName).length/1kb)

		foreach ($String in $Strings) {
			If($range.Text -match ".{0,$($charactersAround)}$($String).{0,$($charactersAround)}"){
				 $properties = @{
					File = $file.FullName
					Filesize = $filesize
					Match = $String
					TextAround = $Matches[0]
				 }
				 $results += New-Object -TypeName PsCustomObject -Property $properties
			}
		}
        $document.close()
    }

    $application.quit()
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($application)
    If($results){
        $results | Export-Csv $Temppath -NoTypeInformation -Encoding ASCII
        # return $results
    }
}

]==]
-- #endregion

function make_psstringarray(list)
    -- Converts a lua list (table) into a string powershell list
    psarray = "@("
    for _,value in ipairs(list) do
        print("Adding search param: " .. tostring(value))
        psarray = psarray .. "\"".. tostring(value) .. "\"" .. ","
    end
    psarray = psarray:sub(1, -2) .. ")"
    return psarray
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection

host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if hunt.env.is_windows() and hunt.env.has_powershell() then
	-- Insert your Windows Code
	hunt.debug("Operating on Windows")
    tempfile = [[c:\windows\temp\icext.csv]]

	-- Create powershell process and feed script/commands to its stdin
	local pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
	pipe:write(initscript) -- load up powershell functions and vars
	pipe:write('Get-StringsMatch -Temppath ' .. tempfile .. ' -Path ' .. searchpath .. ' -Strings ' .. make_psstringarray(strings))
	r = pipe:close()
	hunt.verbose("Powershell Returned: "..tostring(r))

    -- read output file from powershell
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


----------------------------------------------------
-- SECTION 4: Results
--	Set threat status to aggregate and stack results in the Infocyte app:
--		Good, Low Risk, Unknown, Suspicious, or Bad

if output then
    hunt.suspicious()
else
    hunt.good()
end

----------------------------------------------------
