local nettlp_proto = Proto("NetTLP", "NetTLP Packet")
local nt_f = nettlp_proto.fields

-- PCIe TLP capture header: Byte 6
--  2               1             0B
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |           Sequence            |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |           Timestamp           |
-- |                               |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Sequence: 16bit, Clock_source:PCIe_clock
-- Timestamp: 32bit, default:0, Clock_source:PCIe_clock
-- 
nt_f.nettlp_sequence = ProtoField.uint16("nettlp.sequence", "Sequence", base.HEX)
nt_f.nettlp_tstamp   = ProtoField.uint32("nettlp.timestamp", "Timestamp", base.DEC)


---------------------------------------------------
local tlp_proto = Proto("PCIeTLP", "PCI Express Transaction Layer Packet")

local tlp_f = tlp_proto.fields

-- PCI Express TLP Common Header
-- |       0       |       1       |       2       |       3       |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- | FMT |   Type  |R| TC  |   R   |T|E|Atr| R |       Length      |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

local TLPPacketFmtType = {
	[0x00] =  "MRd",
	[0x20] =  "MRd",
	[0x01] =  "MRdLk",
	[0x21] =  "MRdLk",
	[0x40] =  "MWr",
	[0x60] =  "MWr",
	[0x02] =  "IORd",
	[0x42] =  "IOWr",
	[0x04] =  "CfgRd0",
	[0x44] =  "CfgWr0",
	[0x05] =  "CfgRd1",
	[0x45] =  "CfgWr1",
	[0x1b] =  "TCfgRd",
	[0x5b] =  "TCfgWr",
	[0x30] =  "Msg",
	[0x70] =  "MsgD",
	[0x0a] =  "Cpl",
	[0x4a] =  "CplD",
	[0x0b] =  "CplLk",
	[0x4b] =  "CplDLk",
	[0x4c] =  "FetchAdd",
	[0x6c] =  "FetchAdd",
	[0x4d] =  "Swap",
	[0x6d] =  "Swap",
	[0x4e] =  "CAS",
	[0x6e] =  "CAS",
	[0x80] =  "LPrfx",
	[0x90] =  "EPrfx"
}
tlp_f.tlp_fmttype = ProtoField.uint8("nettlp.tlp.ftmtype", "Packet Format Type", base.HEX, TLPPacketFmtType)

local TLPPacketFormat = {
	[0x0] = "3DW_WO_DATA",
	[0x1] = "4DW_WO_DATA",
	[0x2] = "3DW_DATA",
	[0x3] = "4DW_DATA",
	[0x4] = "TLP_Prefix"
}
tlp_f.tlp_fmt = ProtoField.uint8("nettlp.tlp.fmttype.format", "Packet Format", base.HEX, TLPPacketFormat, 0xe)

local TLPPacketType = {
	[0x00] = "MRd or MWr",
	[0x01] = "MRdLk",
	[0x02] = "IORd or IOWr",
	[0x04] = "CfgRd0 or CfgWr0",
	[0x05] = "CfgRd1 or CfgWr1",
	[0x1b] = "TCfgRd or TCfgWR",
	[0x10] = "Msg or MsgD",
	[0x0a] = "Cpl or CplD",
	[0x0b] = "CplLk or CplDLk",
	[0x0c] = "FetchAdd",
	[0x0d] = "Swap",
	[0x0e] = "CAS"
}
tlp_f.tlp_pkttype = ProtoField.uint8("nettlp.tlp.fmttype.pkttype", "Packet Type", base.HEX, TLPPacketType, 0x1f)

tlp_f.tlp_rsvd0 = ProtoField.uint8("nettlp.tlp.reserved1", "Reserved0", nil, nil, 0x80)
tlp_f.tlp_tclass = ProtoField.uint8("nettlp.tlp.tclass", "Tclass", base.HEX, nil, 0x70)
tlp_f.tlp_rsvd1 = ProtoField.uint8("nettlp.tlp.reserved2", "Reserved1", nil, nil, 0xf)

tlp_f.tlp_digest = ProtoField.uint16("nettlp.tlp.digest", "Digest", base.HEX, nil, 0x8000)
tlp_f.tlp_poison = ProtoField.uint16("nettlp.tlp.poison", "Poison", base.HEX, nil, 0x4000)
tlp_f.tlp_attr = ProtoField.uint16("nettlp.tlp.attr", "Attr", base.HEX, nil, 0x3000)
tlp_f.tlp_rsvd2 = ProtoField.uint16("nettlp.tlp.reserved3", "Reserved2", nil, nil, 0xc00)
tlp_f.tlp_length = ProtoField.uint16("nettlp.tlp.length", "Length", base.HEX, nil, 0x3ff)

tlp_f.tlp_payload = ProtoField.bytes("nettlp.tlp.payload", "TLP Payload")

tlp_f.tlp_reqid = ProtoField.uint16("nettlp.tlp.reqid", "Requester ID", base.HEX)
tlp_f.tlp_cplid = ProtoField.uint16("nettlp.tlp.cplid", "Completer ID", base.HEX)

tlp_f.tlp_busnum = ProtoField.uint16("nettlp.tlp.busnum", "Bus Number", base.HEX)
tlp_f.tlp_devnum = ProtoField.uint16("nettlp.tlp.devnum", "Device Number", base.HEX)
tlp_f.tlp_funcnum = ProtoField.uint16("nettlp.tlp.funcnum", "Function Number", base.HEX)


-- PCI Express TLP Memory Request 3DW Header (32 bit address):
-- |       0       |       1       |       2       |       3       |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- | FMT |   Type  |R| TC  |   R   |T|E|Atr| R |       Length      |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |           Request ID          |      Tag      |LastBE |FirstBE|
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |                           Address                         | R |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- or, TLP 4DW header (64 bit address):
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |                            Address                            |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |                            Address                        | R |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

tlp_f.mr_tag = ProtoField.uint8("nettlp.tlp.mr_tag", "Tag", base.HEX)

tlp_f.mr_lastbe = ProtoField.uint8("nettlp.tlp.mr_lastbe", "LastBE", base.HEX, nil, 0xf0)
tlp_f.mr_firstbe = ProtoField.uint8("nettlp.tlp.mr_firstbe", "FirstBE", base.HEX, nil, 0xf)

tlp_f.mr_addr32 = ProtoField.uint32("nettlp.tlp.mr_addr32", "Address 32 bit", base.HEX, nil, 0xfffffffc)
tlp_f.mr_addr32_rsvd = ProtoField.uint32("nettlp.tlp.mr_addr32_rsvd", "Reserved_32b", nil, nil, 0x3)

tlp_f.mr_addr64 = ProtoField.uint64("nettlp.tlp.mr_addr64", "Address 64 bit", base.HEX, nil, 0xfffffffffffffffc)
tlp_f.mr_addr64_rsvd = ProtoField.uint64("nettlp.tlp.mr_addr64_rsvd", "Reserved_64b", nil, nil, 0x3)

-- 
-- PCI Express TLP Completion Header
-- |       0       |       1       |       2       |       3       |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |R|Fmt|  Type   |R| TC  |   R   |T|E|Atr| R |      Length       |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |          Completer ID         |CplSt|B|      Byte Count       |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |          Requester ID         |      Tag      |R| Lower Addr  |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

tlp_f.cpl_cplid = ProtoField.uint16("nettlp.tlp.cpl_cplid", "Completer ID", base.HEX)

local TLPCompletionStatus = {
	[0x0] = "Successful Completion (SC)",
	[0x1] = "Unsupported Request (UR)",
	[0x2] = "Configuration Reqeust Retry Status (CRS)",
	[0x3] = "Completer Abort (CA)"
}
tlp_f.cpl_cplstat = ProtoField.uint16("nettlp.tlp.cpl_cplstat", "Completion Status", base.HEX, TLPCompletionStatus, 0xe000)
tlp_f.cpl_bcm = ProtoField.uint16("nettlp.tlp.cpl_bcm", "Byte Count Modified", nil, nil, 0x1000)
tlp_f.cpl_bytecnt = ProtoField.uint16("nettlp.tlp.cpl_bytecnt", "Byte Count", nil, nil, 0xfff)

tlp_f.cpl_reqid = ProtoField.uint16("nettlp.tlp.cpl_reqid", "Requester ID", base.HEX)

tlp_f.cpl_tag = ProtoField.uint8("nettlp.tlp.cpl_tag", "Tag", base.HEX)

tlp_f.cpl_rsvd0 = ProtoField.uint8("nettlp.tlp.cpl_revd0", "Reserved0", base.HEX, nil, 0x80)
tlp_f.cpl_lowaddr = ProtoField.uint8("nettlp.tlp.cpl_lowaddr", "Lower Address", base.HEX, nil, 0x7f)

function nettlp_proto.dissector(buffer, pinfo, tree)
	if buffer:len() == 0 then return end

	-- tree
	local subtree = tree:add(nettlp_proto, buffer(0, buffer:len()))

	local nettlp_subtree = subtree:add(buffer(0,6), "NetTLP Header")
	nettlp_subtree:add(nt_f.nettlp_sequence, buffer(0,2))
	nettlp_subtree:add(nt_f.nettlp_tstamp, buffer(2,4))

	local tlp_subtree = subtree:add(buffer(6, buffer:len()-6), "PCIe Transaction Layer Packet")
	-- TLP common header
	fmttype = buffer(6,1):uint()

	tlp_subtree:add(tlp_f.tlp_fmttype, buffer(6,1))

	tlp_subtree:add(tlp_f.tlp_rsvd0,   buffer(7,1))
	tlp_subtree:add(tlp_f.tlp_tclass,  buffer(7,1))
	tlp_subtree:add(tlp_f.tlp_rsvd1,   buffer(7,1))

	tlp_subtree:add(tlp_f.tlp_digest,  buffer(8,2))
	tlp_subtree:add(tlp_f.tlp_poison,  buffer(8,2))
	tlp_subtree:add(tlp_f.tlp_attr,    buffer(8,2))
	tlp_subtree:add(tlp_f.tlp_rsvd2,   buffer(8,2))
	tlp_subtree:add(tlp_f.tlp_length,  buffer(8,2))  -- 6-9
	--- End: TLP common header

	-- TLP memory request packet
	if fmttype == 0x00 then  -- MRd_3DW
		local reqid_subtree = tlp_subtree:add(tlp_f.tlp_reqid, buffer(10,2))
			-- reqid tree
			reqid_subtree:add(tlp_f.tlp_busnum, buffer(10,2), buffer(10,2):bitfield(0, 8))
			reqid_subtree:add(tlp_f.tlp_devnum, buffer(10,2), buffer(10,2):bitfield(8, 4))
			reqid_subtree:add(tlp_f.tlp_funcnum, buffer(10,2), buffer(10,2):bitfield(12, 4))
		tlp_subtree:add(tlp_f.mr_tag,         buffer(12,1))
		tlp_subtree:add(tlp_f.mr_lastbe,      buffer(13,1))
		tlp_subtree:add(tlp_f.mr_firstbe,     buffer(13,1))
		tlp_subtree:add(tlp_f.mr_addr32,      buffer(14,4))
		tlp_subtree:add(tlp_f.mr_addr32_rsvd, buffer(14,4))
	elseif fmttype == 0x20 then  -- MRd_4DW
		local reqid_subtree = tlp_subtree:add(tlp_f.tlp_reqid, buffer(10,2))
			-- reqid tree
			reqid_subtree:add(tlp_f.tlp_busnum, buffer(10,2), buffer(10,2):bitfield(0, 8))
			reqid_subtree:add(tlp_f.tlp_devnum, buffer(10,2), buffer(10,2):bitfield(8, 4))
			reqid_subtree:add(tlp_f.tlp_funcnum, buffer(10,2), buffer(10,2):bitfield(12, 4))
		tlp_subtree:add(tlp_f.mr_tag,         buffer(12,1))
		tlp_subtree:add(tlp_f.mr_lastbe,      buffer(13,1))
		tlp_subtree:add(tlp_f.mr_firstbe,     buffer(13,1))
		tlp_subtree:add(tlp_f.mr_addr64,      buffer(14,8))
		tlp_subtree:add(tlp_f.mr_addr64_rsvd, buffer(14,8))
	elseif fmttype == 0x40 then  -- MWr_3DW
		local reqid_subtree = tlp_subtree:add(tlp_f.tlp_reqid, buffer(10,2))
			-- reqid tree
			reqid_subtree:add(tlp_f.tlp_busnum, buffer(10,2), buffer(10,2):bitfield(0, 8))
			reqid_subtree:add(tlp_f.tlp_devnum, buffer(10,2), buffer(10,2):bitfield(8, 4))
			reqid_subtree:add(tlp_f.tlp_funcnum, buffer(10,2), buffer(10,2):bitfield(12, 4))
		tlp_subtree:add(tlp_f.mr_tag,         buffer(12,1))
		tlp_subtree:add(tlp_f.mr_lastbe,      buffer(13,1))
		tlp_subtree:add(tlp_f.mr_firstbe,     buffer(13,1))
		tlp_subtree:add(tlp_f.mr_addr32,      buffer(14,4))
		tlp_subtree:add(tlp_f.mr_addr32_rsvd, buffer(14,4))
		tlp_subtree:add(tlp_f.tlp_payload,    buffer(18))
	elseif fmttype == 0x60 then  -- MWr_4DW
		local reqid_subtree = tlp_subtree:add(tlp_f.tlp_reqid, buffer(10,2))
			-- reqid tree
			reqid_subtree:add(tlp_f.tlp_busnum, buffer(10,2), buffer(10,2):bitfield(0, 8))
			reqid_subtree:add(tlp_f.tlp_devnum, buffer(10,2), buffer(10,2):bitfield(8, 4))
			reqid_subtree:add(tlp_f.tlp_funcnum, buffer(10,2), buffer(10,2):bitfield(12, 4))
		tlp_subtree:add(tlp_f.mr_tag,         buffer(12,1))
		tlp_subtree:add(tlp_f.mr_lastbe,      buffer(13,1))
		tlp_subtree:add(tlp_f.mr_firstbe,     buffer(13,1))
		tlp_subtree:add(tlp_f.mr_addr64,      buffer(14,8))
		tlp_subtree:add(tlp_f.mr_addr64_rsvd, buffer(14,8))
		tlp_subtree:add(tlp_f.tlp_payload,    buffer(22))
	-- TLP completion packet
	elseif fmttype == 0x0a then  -- Cpl
		local cplid_subtree = tlp_subtree:add(tlp_f.tlp_cplid, buffer(10,2))
			-- cplid tree
			cplid_subtree:add(tlp_f.tlp_busnum, buffer(10,2), buffer(10,2):bitfield(0, 8))
			cplid_subtree:add(tlp_f.tlp_devnum, buffer(10,2), buffer(10,2):bitfield(8, 4))
			cplid_subtree:add(tlp_f.tlp_funcnum, buffer(10,2), buffer(10,2):bitfield(12, 4))
		tlp_subtree:add(tlp_f.cpl_cplstat, buffer(12,2))
		tlp_subtree:add(tlp_f.cpl_bcm,     buffer(12,2))
		tlp_subtree:add(tlp_f.cpl_bytecnt, buffer(12,2))
		local reqid_subtree = tlp_subtree:add(tlp_f.tlp_reqid, buffer(14,2))
			reqid_subtree:add(tlp_f.tlp_busnum, buffer(10,2), buffer(10,2):bitfield(0, 8))
			reqid_subtree:add(tlp_f.tlp_devnum, buffer(10,2), buffer(10,2):bitfield(8, 4))
			reqid_subtree:add(tlp_f.tlp_funcnum, buffer(10,2), buffer(10,2):bitfield(12, 4))
		tlp_subtree:add(tlp_f.cpl_tag,     buffer(16,1))
		tlp_subtree:add(tlp_f.cpl_rsvd0,   buffer(17,1))
		tlp_subtree:add(tlp_f.cpl_lowaddr, buffer(17,1))
	elseif fmttype == 0x4a then  -- CplD
		local cplid_subtree = tlp_subtree:add(tlp_f.tlp_cplid, buffer(10,2))
			-- cplid tree
			cplid_subtree:add(tlp_f.tlp_busnum, buffer(10,2), buffer(10,2):bitfield(0, 8))
			cplid_subtree:add(tlp_f.tlp_devnum, buffer(10,2), buffer(10,2):bitfield(8, 4))
			cplid_subtree:add(tlp_f.tlp_funcnum, buffer(10,2), buffer(10,2):bitfield(12, 4))
		tlp_subtree:add(tlp_f.cpl_cplstat, buffer(12,2))
		tlp_subtree:add(tlp_f.cpl_bcm,     buffer(12,2))
		tlp_subtree:add(tlp_f.cpl_bytecnt, buffer(12,2))
		local reqid_subtree = tlp_subtree:add(tlp_f.tlp_reqid, buffer(14,2))
			-- reqid tree
			reqid_subtree:add(tlp_f.tlp_busnum, buffer(10,2), buffer(10,2):bitfield(0, 8))
			reqid_subtree:add(tlp_f.tlp_devnum, buffer(10,2), buffer(10,2):bitfield(8, 4))
			reqid_subtree:add(tlp_f.tlp_funcnum, buffer(10,2), buffer(10,2):bitfield(12, 4))
		tlp_subtree:add(tlp_f.cpl_tag,     buffer(16,1))
		tlp_subtree:add(tlp_f.cpl_rsvd0,   buffer(17,1))
		tlp_subtree:add(tlp_f.cpl_lowaddr, buffer(17,1))
		tlp_subtree:add(tlp_f.tlp_payload, buffer(18))
	end
	-- End: TLP memory request packet

	-- pinfo
	pinfo.cols.protocol = "PCIe TLP"
end

DissectorTable.get("udp.port"):add("12288-12544", nettlp_proto)

