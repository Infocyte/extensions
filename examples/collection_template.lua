--[[
    Infocyte Extension
    Name: Template
    Type: Collection
    Description: Example script show format, style, and options for gathering
     additional data from a host.
    Author: Infocyte
    Created: 20190919
    Updated: 20190919 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)


----------------------------------------------------
-- SECTION 2: Functions


-- You can define shell scripts here if using any.
ps_script = [==[

]==]

python_cmd = [==[

]==]

----------------------------------------------------
-- SECTION 3: Collection / Inspection

-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())



-- All OS-specific instructions should be behind an 'if' statement
if hunt.env.is_windows() then
  -- Insert your Windows code

  -- Create powershell process and feed script/commands to its stdin
  -- local pipe = io.popen("powershell.exe -noexit -nologo -nop -command -", "w")
  -- pipe:write(initscript) -- load up powershell functions and vars
  -- pipe:write('Get-StringsMatch -Temppath ' .. tempfile .. ' -Path ' .. searchpath .. ' -Strings ' .. make_psstringarray(strings))
  -- r = pipe:close()

elseif hunt.env.is_macos() then
    -- Insert your MacOS Code


elseif hunt.env.is_linux() or hunt.env.has_sh() then
    -- Insert your POSIX (linux) Code

    -- os.execute("python -u -c \"" .. python_script.. "\"" )

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end



----------------------------------------------------
-- SECTION 4: Results
--  Threat status is a set of static results used to aggregate and stack
--  results:
--      Good, Low Risk, Unknown, Suspicious, or Bad
--    Include any host-side processing and analysis necessary to report the
--   appropriate status.

result = "Test" -- filler [DELETE ME]

-- Set the returned threat status of the host based on the extension results
if string.find(result, "test") then
  hunt.status.good()
elseif string.find(result, "bad") then
  hunt.status.bad()
else
  hunt.status.unknown()
end

-- one or more log statements can be used to send resulting data or messages in
-- text format to your Infocyte instance
hunt.log("Result: Extension successfully executed on " .. hostname)

----------------------------------------------------
