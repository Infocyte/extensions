--[[
    Infocyte Extension
    Name: Terminate Process
    Type: Action
    Description: Kills a process
    Author: Infocyte
    Id: 5a2e94d9-fa88-4ffe-8aa9-ef53660b3a53
    Created: 20200123
    Updated: 20200123 (Gerritz)
]]--

-- SECTION 1: Inputs (Variables)
processname = "calc.exe"

----------------------------------------------------
-- SECTION 2: Functions


----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
osversion = host_info:os()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

-- List running processes
procs = hunt.process.list()

-- Kill processes
for _, pid in pairs(hunt.process.kill_process(procname)) do
    hunt.log("Killed "..procname.." running as " .. tostring(pid))
end
