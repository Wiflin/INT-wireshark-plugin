
-- --
-- -- Output window
-- --
-- local function statistics_win()
--     -- Declare the window we will use
--     win = TextWindow.new("IFA Residense Time")
    
--     local function remove()
--         -- this way we remove the listener that otherwise will remain running indefinitely
--         tap:remove();
--     end
    
--     win:set_atclose(remove)
-- end

-- --
-- -- Display plugin message. This will either go to the
-- -- GUI text window or just print to stdout.
-- --



------------------------------------
--
-- Here start of the plugin
--
------------------------------------
local f_ts = Field.new('frame.time_relative')
local f_residense = Field.new('t_residence_nano')

local function init_listener()
    local filter = "ifa && !icmp"
    local tap = Listener.new(nil, filter)
    
    local file = io.open("stats.txt", 'w')
    local win = TextWindow.new("IFA Residense Time")
    win:set_atclose(function() 
        tap:remove() 
        file:close()
    end)
    
    function message(message)
        -- handle either gui or non gui mode
        if win ~= nil then
            win:append(message .. '\n')
        end
    end

    function filemsg(message)
        if file ~= nil then
            file:write(message .. '\n')
        end
    end
    
    -- trigger per packet
    local pkts = 0
    function tap.packet(pkt, tvb, tapinfo)
        local s_ts = tostring(f_ts())
        local s_residense = (tonumber(tostring(f_residense())) - 1000000000 )
        filemsg(s_ts .. '\t' .. s_residense)
        -- message(string.format("Loop begins for #fs_ts: %d, #fs_residense %d", #fs_ts, #fs_residense))
        pkts = pkts + 1
    end
    
    -- draw while finishing calculating
    function tap.draw()
        message("pkts: " .. pkts)
    end
    
    -- reset
    function tap.reset()
        pkts = 0
    end

    retap_packets()
end


register_menu("Statistics/IFA", init_listener, MENU_TOOLS_UNSORTED)
-- if gui_enabled() == true then
--     -- Starting in GUI mode
--     register_menu("Statistics/IFA", init_listener, MENU_TOOLS_UNSORTED)
--     -- Call the init function to get things started.
-- else
--     -- Call the init function to get things started.
--     init_listener()
--     message("Starting in command-line mode")
-- end


