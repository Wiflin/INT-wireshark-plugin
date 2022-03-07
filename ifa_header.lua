--
-- @author wikkizhang@tencent.com
--

do
    local p_IFA_HDR = Proto("IFA","IFAv2 Header")

    local f_version = ProtoField.new("Ver+GNS", "version", ftypes.UINT8)
    -- local f_gns = ProtoField.new("GNS", "gns", ftypes.UINT8)
    local f_proto = ProtoField.new("Protocol", "proto", ftypes.UINT8)
    local f_flags = ProtoField.new("Flags", "flags", ftypes.UINT8)
    local f_maxLen = ProtoField.new("MaxLength", "maxlen", ftypes.UINT8)
   
    p_IFA_HDR.fields = {f_version, f_gns, f_proto, f_flags, f_maxLen}

    local data_dis = Dissector.get("data")

    local function IFA_dissector(buf, pkt, root)
        local buf_len = buf:len()
        if buf_len < 24 then return false end

        local v_version = buf(0, 1)
        -- local v_gns = buf(4, 4)
        local v_proto = buf(1, 1)
        local v_flags = buf(2, 1)
        local v_maxLen = buf(3, 1)

        local t = root:add(p_IFA_HDR, buf)
        pkt.cols.protocol = "IFAv2 Header"

        t:add(f_version, v_version)
        -- t:add(f_gns, v_gns)
        t:add(f_proto, v_proto)
        t:add(f_flags, v_flags)
        t:add(f_maxLen, v_maxLen)

        local raw_data = buf(4, buf:len()-4)
        Dissector.get("udp"):call(raw_data:tvb(), pkt, root)
        pkt.cols.protocol:append("-IFAv2")
        return true
    end

    function p_IFA_HDR.dissector(buf, pkt, root) 
        if IFA_dissector(buf, pkt, root) then

        else
            data_dis:call(buf, pkt, root)
        end
    end
    
    local ip_ver_table = DissectorTable.get("ip.proto")
    ip_ver_table:add(253, p_IFA_HDR)
end