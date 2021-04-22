--[[
    Infocyte Extension
    Name: Linux Hardening Check
    Type: Collection
    Description: | Example of leveraging a 3rd party tool
      along with extensions to conduct an audit
      operation of a Linux Asset |
    Author: Unknown
    Guid: 986de437-64fb-4003-86e7-3b8eba8c1580
    Created: 20191115
    Updated 20191115
--]]


if hunt.env.is_linux() or hunt.env.has_sh() then

    hunt.log("Running Linux Hardening Check")
    os.execute("git clone https://github.com/CISOfy/lynis")
    os.execute("cd lynis && ./lynis audit system")
    handle = assert(io.popen('grep strength: /var/log/lynis.log', 'r'))
    output = assert(handle:read('*a'))
    handle:close()
    hunt.log("Removing Hardening Checker...")
    os.execute("rm -rf lynis")
    hunt.log("Hardening Results " .. output)

else
    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
end

--[[
    What else could I do?
    This 3rd party tool creates a log file of the results
    It also creates a .dat file of all the findings
    I could easily use extensions to take the log file and push it to
    an offline location for analysis later (like S3, an FTP, etc)
--]]
