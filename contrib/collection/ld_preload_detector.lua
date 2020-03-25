--[[
    Infocyte Extension
    Name: ld.so.preload Rootkit Detector
    Type: Collection
    Description: Analyzes any references in ld.so.preload (always suspicious
        cause programs launched can intercept system calls)
    Author: Infocyte
    Guid: 0153a459-c36b-4542-940e-e4c81ab1eb63
    Created: 20191216
    Updated: 20191216 (Gerritz)
--]]

--[[ SECTION 1: Inputs --]]


--[[ SECTION 2: Functions --]]


--[[ SECTION 3: Collection --]]

host_info = hunt.env.host_info()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

if hunt.env.is_linux() or hunt.env.has_sh() or hunt.env.is_macos() then

    path = '/etc/ld.so.preload'
    ld = hunt.fs.ls(path)
    if ld then
        hunt.log("ld.se.preload found! This is not normal.")
        hunt.status.suspicious()

        -- Read the file
        file, err = io.open(path, "r")
        if file then
            for line in file:lines() do
                hunt.log("Analyzing: "..line)
                -- Add to artifacts and send file through Infocyte analysis pipeline
                autostart = hunt.survey.autostart()
                autostart:exe(line)
                autostart:type("ld.so.preload")
                hunt.survey.add(autostart)
            end
        else
            hunt.error("Could not read "..path..": ".. err)
            return nil
        end
    else
        hunt.status.good()
    end
else
    hunt.warn("Not a compatible operating system for this extension [" .. host_info:os() .. "]")
    hunt.status.good()
end
