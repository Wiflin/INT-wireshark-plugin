--
-- @author wikkizhang@tencent.com
--

-- IFA MD Header .name and .description
local p_IFA_MD_STACK = Proto("IFA-MD-Stack", "IFAv2 Metadata Stack")

-- IFA Metadata Header Fields
local f_mdh_reqv = ProtoField.uint8("requestVec", "Request Vector", base.DEC)   -- Request Vector
local f_mdh_actv = ProtoField.uint8("actionVec", "Action Vector", base.DEC)     -- Action Vector
local f_mdh_hopl = ProtoField.uint8("hopLimit", "Hop Limit", base.DEC)          -- Hop Limit
local f_mdh_curl = ProtoField.uint8("curLength", "Current Length", base.DEC)    -- Current Length
p_IFA_MD_STACK.fields = {f_mdh_reqv, f_mdh_actv, f_mdh_hopl, f_mdh_curl}

-- IFA MD Header Dissector
function p_IFA_MD_STACK.dissector(buf, pkt, root)
    local length = buf:len()
    if length == 0 then return end
    if length < 4 then return false end

    -- pkt.cols.protocol = "IFA Metadata"

    -- add metadata header
    local mdtree = root:add(p_IFA_MD_STACK, buf)
    mdtree:add(f_mdh_reqv, buf(0,1))
    mdtree:add(f_mdh_actv, buf(1,1))
    mdtree:add(f_mdh_hopl, buf(2,1))
    mdtree:add(f_mdh_curl, buf(3,1))

    -- add metadata stack
    local stack_len = buf(3,1):uint()
    local stack_cnt = 0

    buf = buf(4, buf:len()-4):tvb()
    while stack_len > 7 do 
        stack_len = stack_len - 8
        stack_cnt = stack_cnt + 1

        if IFA_Metadata_Dis(buf, pkt, mdtree, stack_cnt) then
            buf = buf(32, buf:len()-32):tvb()
        end
    end

    if stack_len ~= 0 then
        warn("Metadata Length Not Aligned: " .. stack_len)
    end

    Dissector.get("data"):call(buf, pkt, root)
end

-- bind port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(0x8081, p_IFA_MD_STACK)  --0x8081


-----------------------------------------------------------------------
-----------------------------------------------------------------------
-----------------------------------------------------------------------
-----------------------------------------------------------------------
-----------------------------------------------------------------------
-----------------------------------------------------------------------


-- IFA Metadata .name and .description
local p_IFA_Metadata = Proto("IFA-Metadata", "IFAv2 Metadata")

-- IFA Metadata Fields
local f_md_word1 = ProtoField.uint32("qword1", "Quad Word 1", base.HEX)
local f_md_lns = ProtoField.uint8("lns", "Local Namespace", base.HEX)
local f_md_devid = ProtoField.uint32("devid", "Device ID", base.DEC)
local f_md_ipttl = ProtoField.uint8("ipttl", "IP TTL", base.HEX)

local f_md_word2 = ProtoField.uint32("qword2", "Quad Word 2", base.HEX)
local f_md_egress_speed = ProtoField.uint8("egress_speed", "Egress Port Speed", base.DEC)
local f_md_congestion = ProtoField.uint8("congestion", "Congestion", base.HEX)
local f_md_queueid = ProtoField.uint8("queueid", "Queue ID", base.DEC)
local f_md_rx_sec = ProtoField.uint32("t_rx_sec", "Time RX Sec", base.DEC)

-- local f_md_word3 = ProtoField.uint32("word3", "word3", base.HEX)
local f_md_egress = ProtoField.uint16("egress_port", "Egress System Port", base.DEC)
local f_md_ingress = ProtoField.uint16("ingress_port", "Ingress System Port", base.DEC)

local f_md_word4 = ProtoField.uint32("t_rx_nano", "Time RX Nano Sec", base.DEC)
local f_md_word5 = ProtoField.uint32("t_residence_nano", "Time Residence Nano Sec", base.DEC)
local f_md_word6 = ProtoField.uint32("opaque_1", "Opaque Data 1", base.HEX)
local f_md_word7 = ProtoField.uint32("opaque_2", "Opaque Data 2", base.HEX)
local f_md_word8 = ProtoField.uint32("opaque_3", "Opaque Data 3", base.HEX)
p_IFA_Metadata.fields = {f_md_word1, f_md_lns, f_md_devid, f_md_ipttl,
                            f_md_word2, f_md_egress_speed, f_md_congestion, f_md_queueid, f_md_rx_sec,
                            f_md_egress, f_md_ingress,
                            f_md_word4, f_md_word5, 
                            f_md_word6, f_md_word7, f_md_word8}

-- IFA Metadata Dissector
function IFA_Metadata_Dis(buf, pkt, root, level)
    local length = buf:len()
    if length < 32 then return false end

    md_node = root:add(p_IFA_Metadata, buf(0,32), "IFA Metadata -- " .. level)
    p_IFA_Metadata.dissector(buf, pkt, md_node)
    return true
end

function p_IFA_Metadata.dissector(buf, pkt, root)
    require "bit32"
    qword1_node = root:add(f_md_word1, buf(0,4))
    local qword1 = buf(0,4):uint()
    qword1_node:add(f_md_lns, bit32.rshift(qword1, 28))
    qword1_node:add(f_md_devid, bit32.rshift(bit32.lshift(qword1, 4), 12))
    qword1_node:add(f_md_ipttl, bit32.rshift(bit32.lshift(qword1, 24), 24))

    qword2_node = root:add(f_md_word2, buf(4,4))
    local qword2 = buf(4,4):uint()
    qword2_node:add(f_md_egress_speed, bit32.rshift(qword2, 28))
    qword2_node:add(f_md_congestion, bit32.rshift(bit32.lshift(qword2, 4), 30) )
    qword2_node:add(f_md_queueid, bit32.rshift(bit32.lshift(qword2, 6), 26) )
    qword2_node:add(f_md_rx_sec, bit32.rshift(bit32.lshift(qword2, 12), 12))
    
    -- egress id, ingress id
    root:add(f_md_egress, buf(8,2))
    root:add(f_md_ingress, buf(10,2))
    
    root:add(f_md_word4, buf(12,4))
    root:add(f_md_word5, buf(16,4))
    root:add(f_md_word6, buf(20,4))
    root:add(f_md_word7, buf(24,4))
    root:add(f_md_word8, buf(28,4))
end