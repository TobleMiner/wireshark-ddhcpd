----------------------------------------
-- script-name: ddhcp_dissector.lua
--
-- author: Tobias Schramm <t.schramm(at)t-sys.eu>
-- Copyright (c) 2021, Tobias Schramm
-- Copyright (c) 2014, Hadriel Kaplan
--
-- This dissector is based on the great Wireshark lua dissector example by Hadriel Kaplan.
-- This code is licensed under the BSD (3 clause) license.
--
----------------------------------------
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    port_mcast   = 1234,
    port_ucast   = 1235,
}

-- for testing purposes, we want to be able to pass in changes to the defaults
-- from the command line; because you can't set lua preferences from the command
-- line using the '-o' switch (the preferences don't exist until this script is
-- loaded, so the command line thinks they're invalid preferences being set)
-- so we pass them in as command arguments instead, and handle it here:
local args={...} -- get passed-in args
if args and #args > 0 then
    for _, arg in ipairs(args) do
        local name, value = arg:match("(.+)=(.+)")
        if name and value then
            if tonumber(value) then
                value = tonumber(value)
            elseif value == "true" or value == "TRUE" then
                value = true
            elseif value == "false" or value == "FALSE" then
                value = false
            elseif value == "DISABLED" then
                value = debug_level.DISABLED
            elseif value == "LEVEL_1" then
                value = debug_level.LEVEL_1
            elseif value == "LEVEL_2" then
                value = debug_level.LEVEL_2
            else
                error("invalid commandline argument value")
            end
        else
            error("invalid commandline argument syntax")
        end

        default_settings[name] = value
    end
end

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

----------------------------------------


----------------------------------------
-- creates a Proto object, but doesn't register it yet
local ddhcp = Proto("ddhcp","DDHCP protocol")

local COMMAND_UPDATECLAIM = 1
local COMMAND_INQUIRE     = 2
local COMMAND_RENEWLEASE  = 16
local COMMAND_LEASE_ACK   = 17
local COMMAND_LEASE_NAK   = 18
local COMMAND_RELEASE     = 19

local command_names = {
	[COMMAND_UPDATECLAIM] = "Update claim",
	[COMMAND_INQUIRE] = "Inquire",
	[COMMAND_RENEWLEASE] = "Renew lease",
	[COMMAND_LEASE_ACK] = "Lease ACK",
	[COMMAND_LEASE_NAK] = "Lease NAK",
	[COMMAND_RELEASE] = "Release"
}


----------------------------------------
-- Portocol fields
----------------------------------------
-- Header fields
local pf_node_id            = ProtoField.new("Node ID", "ddhcp.node_id", ftypes.UINT64, nil, base.HEX)
local pf_prefix             = ProtoField.new("Prefix", "ddhcp.prefix", ftypes.IPv4)
local pf_prefix_len         = ProtoField.new("Prefix length", "ddhcp.prefix_len", ftypes.UINT8)
local pf_block_size         = ProtoField.new("Block size", "ddhcp.block_size", ftypes.UINT8)
local pf_command            = ProtoField.new("Command", "ddhcp.command", ftypes.UINT8, command_names)
local pf_count              = ProtoField.new("Number of payloads", "ddhcp.count", ftypes.UINT8)
-- Payload fields
local pf_block_idx          = ProtoField.new("Block index", "ddhcp.block_idx", ftypes.UINT32)
local pf_block_timeout      = ProtoField.new("Block timeout", "ddhcp.block_timeout", ftypes.UINT16)
local pf_block_reserved     = ProtoField.new("Block reserved", "ddhcp.block_reserved", ftypes.UINT8)
local pf_lease              = ProtoField.new("DHCP lease", "ddhcp.lease", ftypes.IPv4)
local pf_xid                = ProtoField.new("DHCP transaction id", "ddhcp.xid", ftypes.UINT32)
local pf_lease_time         = ProtoField.new("DHCP lease time", "ddhcp.lease_time", ftypes.UINT32)
local pf_chaddr             = ProtoField.new("DHCP chaddr", "ddhcp.chaddr", ftypes.NONE)
----------------------------------------
ddhcp.fields = { pf_node_id, pf_prefix, pf_prefix_len, pf_block_size, pf_command, pf_count,
                 pf_block_idx, pf_block_timeout, pf_block_reserved, pf_lease, pf_xid,
                 pf_lease_time, pf_chaddr }

----------------------------------------
-- some error expert info's
local ef_too_short   = ProtoExpert.new("ddhcp.too_short.expert", "DDHCP message too short",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local ef_bad_command = ProtoExpert.new("ddhcp.command.invalid.expert", "Unknown command",
                                     expert.group.MALFORMED, expert.severity.WARN)
-- register them
ddhcp.experts = { ef_too_short, ef_bad_command  }

----------------------------------------
local field_node_id    = Field.new("ddhcp.node_id")
local field_command    = Field.new("ddhcp.command")
local field_count      = Field.new("ddhcp.count")
local field_block_size = Field.new("ddhcp.block_size")

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------
local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

ddhcp.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                            "The debug printing level", debug_pref_enum)

ddhcp.prefs.port_mcast  = Pref.uint("Port number", default_settings.port_mcast,
                            "The multicast UDP port number for DDHCP")

ddhcp.prefs.port_ucast  = Pref.uint("Port number", default_settings.port_ucast,
                            "The unicast UDP port number for DDHCP")

----------------------------------------
-- a function for handling prefs being changed
function ddhcp.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level  = ddhcp.prefs.debug
    reset_debug_level()

    if default_settings.port_mcast ~= ddhcp.prefs.port_mcast then
        -- remove old one, if not 0
        if default_settings.port_mcast ~= 0 then
            dprint2("removing DDHCP from port",default_settings.port_mcast)
            DissectorTable.get("udp.port"):remove(default_settings.port_mcast, dns)
        end
        -- set our new default
        default_settings.port_mcast = ddhcp.prefs.port_mcast
        -- add new one, if not 0
        if default_settings.port_mcast ~= 0 then
            dprint2("adding DDHCP to port",default_settings.port_mcast)
            DissectorTable.get("udp.port"):add(default_settings.port_mcast, dns)
        end
    end

    if default_settings.port_ucast ~= ddhcp.prefs.port_ucast then
        -- remove old one, if not 0
        if default_settings.port_ucast ~= 0 then
            dprint2("removing DDHCP from port",default_settings.port_ucast)
            DissectorTable.get("udp.port"):remove(default_settings.port_ucast, dns)
        end
        -- set our new default
        default_settings.port_ucast = ddhcp.prefs.port_ucast
        -- add new one, if not 0
        if default_settings.port_ucast ~= 0 then
            dprint2("adding DDHCP to port",default_settings.port_ucast)
            DissectorTable.get("udp.port"):add(default_settings.port_ucast, dns)
        end
    end

end

dprint2("DDHCP prefs registered")

local DDHCP_HDR_LEN = 16

local payload_lengths = {
	[COMMAND_UPDATECLAIM] = 7,
	[COMMAND_INQUIRE] = 4,
	[COMMAND_RENEWLEASE] = 28,
	[COMMAND_LEASE_ACK] = 28,
	[COMMAND_LEASE_NAK] = 28,
	[COMMAND_RELEASE] = 28
}

local function get_payload_len(command_id)
    if payload_lengths[command_id] ~= nil then
        return payload_lengths[command_id]
    else
        return -1
    end
end

local function calc_block_cidr(block_idx, prefix_int)
        local ip_int = prefix_int + block_idx * field_block_size().value
        local cidr_str = ""
        for i=3,0,-1 do
            local octet = bit32.band(bit32.rshift(ip_int, i * 8), 0xff)
            cidr_str = cidr_str .. tostring(octet)
            if i > 0 then
                cidr_str = cidr_str .. "."
            end
        end
        local prefix_len = 32 - math.floor(math.log(field_block_size().value) / math.log(2) + .5)
        cidr_str = cidr_str .. "/" .. tostring(prefix_len)
        return cidr_str
end

local function parse_payload(command, tree, tvbuf, prefix_int)
    if command == COMMAND_UPDATECLAIM then
        local payload_tree = tree:add(calc_block_cidr(tvbuf:range(0, 4):uint(), prefix_int))
        payload_tree:add(pf_block_idx, tvbuf:range(0, 4))
        payload_tree:add(pf_block_timeout, tvbuf:range(4, 2))
        payload_tree:add(pf_block_reserved, tvbuf:range(6, 1))
    elseif command == COMMAND_INQUIRE then
        local payload_tree = tree:add(calc_block_cidr(tvbuf:range(0, 4):uint(), prefix_int))
        payload_tree:add(pf_block_idx, tvbuf:range(0, 4))
    else
        local payload_tree = tree:add(tostring(tvbuf:range(0, 4):ipv4()))
        payload_tree:add(pf_lease, tvbuf:range(0, 4))
        payload_tree:add(pf_xid, tvbuf:range(4, 4))
        payload_tree:add(pf_lease_time, tvbuf:range(8, 4))
        payload_tree:add(pf_chaddr, tvbuf:range(12, 16))
    end
end

local function command_has_variable_payload_count(cmd)
    return cmd == COMMAND_UPDATECLAIM or cmd == COMMAND_INQUIRE
end

----------------------------------------
-- The following creates the callback function for the dissector.
function ddhcp.dissector(tvbuf,pktinfo,root)
    dprint2("ddhcp.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("DDHCP")

    -- We want to check that the packet size is rational during dissection, so let's get the length of the
    -- packet buffer (Tvb).
    local pktlen = tvbuf:reported_length_remaining()

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(ddhcp, tvbuf:range(0, pktlen))

    -- now let's check it's not too short
    if pktlen < DDHCP_HDR_LEN then
        -- since we're going to add this protocol to a specific UDP port, we're going to
        -- assume packets in this port are our protocol, so the packet being too short is an error
        tree:add_proto_expert_info(ef_too_short)
        dprint("packet length", pktlen, "too short")
        return
    end

    -- add header fields
    tree:add(pf_node_id, tvbuf:range(0, 8))
    local prefix_int = tvbuf:range(8, 4):uint()
    tree:add(pf_prefix, tvbuf:range(8, 4))
    tree:add(pf_prefix_len, tvbuf:range(12, 1))
    tree:add(pf_block_size, tvbuf:range(13, 1))
    tree:add(pf_command, tvbuf:range(14, 1))
    tree:add(pf_count, tvbuf:range(15, 1))

    -- show node id and command in info column
    local node_id = field_node_id()
    local command = field_command()
    pktinfo.cols.info:set(node_id.display .. ": " .. command.display)

    local num_payloads = field_count().value
    local pos = DDHCP_HDR_LEN

    local payload_len = get_payload_len(command.value)

    if payload_len < 0 then
        -- trouble! We don't understand this command
        tree:add_proto_expert_info(ef_bad_command)
        return pos
    end

    if not command_has_variable_payload_count(command.value) then
        -- The DDHCP is a little quirky.
        -- Packets with a fixed number of payloads advertise a payload count of 0
        num_payloads = 1
    end

    -- Ensure all advertised payloads are present
    if pktlen < pos + num_payloads * payload_len then
        tree:add_proto_expert_info(ef_too_short)
        return pos
    end

    -- Add a new subtree for the payloads
    local payloads_tree = tree:add("Payloads")

    for i=1,num_payloads,1 do
        parse_payload(command.value, payloads_tree, tvbuf:range(pos, payload_len), prefix_int)
        pos = pos + payload_len
    end

    dprint2("ddhcp.dissector returning",pos)

    return pos
end

----------------------------------------
-- we want to have our protocol dissection invoked for a specific UDP port,
-- so get the udp dissector table and add our protocol to it
DissectorTable.get("udp.port"):add(default_settings.port_mcast, ddhcp)
DissectorTable.get("udp.port"):add(default_settings.port_ucast, ddhcp)
