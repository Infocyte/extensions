--[[
	Infocyte Extension
	Name: E-Discovery
	Type: Collection
	Description: Searches the hard drive for office documents with specified
		keywords. Returns a csv with a list of files.
	Author: Infocyte
	Created: 20190919
	Updated: 20190919 (Gerritz)
]]--

----------------------------------------------------
-- SECTION 1: Variables
----------------------------------------------------
strings = {'Gerritz', 'test'}
searchpath = [[C:\Users]]

outpath = [[c:\windows\temp\edisco.csv]]

----------------------------------------------------
-- SECTION 2: Functions
----------------------------------------------------

psscript = "$output = \"" .. outpath .. "\"\n"
psscript = psscript .. [==[
Function Get-StringsMatch {
	param (
		[string]$path = $env:systemroot,
		[string[]]$Strings,
		[int]$charactersAround = 30
	)
    $results = @()
	try {
		$application = New-Object -comobject word.application
	} catch {
		throw "Error opening com object"
	}
    $application.visible = $False
    $files = Get-Childitem $path -Include *.docx,*.doc -Recurse | Where-Object { !($_.psiscontainer) }
    # Loop through all *.doc files in the $path directory
    Foreach ($file In $files) {
		try {
			$document = $application.documents.open($file.FullName,$false,$true)
		} catch {
			Write-Error "Could not open $($file.FullName)"
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
	[System.GC]::Collect()
    If($results){
        $results | Export-Csv $output -NoTypeInformation
        return $results
    }
}
]==]

function make_psstringarray(list)
	-- Converts a lua list (table) into a string powershell list
	psarray = "@("
	for _,value in ipairs(list)
	do
	print("Adding search param: " .. tostring(value))
	psarray = psarray .. "\"".. tostring(value) .. "\"" .. ","
	end
	psarray = psarray:sub(1, -2) .. ")"
	return psarray
end

----------------------------------------------------
-- SECTION 3: Collection / Inspection
----------------------------------------------------

host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if hunt.env.is_windows() and hunt.env.has_powershell() then
	-- Insert your Windows Code
	hunt.debug("Operating on Windows")

	-- Create powershell process and feed script/commands to its stdin
	local pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
	pipe:write(psscript) -- load up powershell functions and vars
	pipe:write('Get-StringsMatch -Path ' .. searchpath .. ' -Strings ' .. make_psstringarray(strings))
	r = pipe:close()
	hunt.verbose("Powershell Returned: "..tostring(r))

	local file = io.open(outpath, "r") -- r read mode
	if file ~= nil then
		output = file:read("*all") -- *a or *all reads the whole file
	 	file:close()
	  	os.remove(outpath)
	  	hunt.log(output) -- send to Infocyte
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
----------------------------------------------------

-- Mandatory: set the returned threat status of the host
if output then
	hunt.suspicious()
else
	hunt.good()
end
