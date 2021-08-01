if disable_lua == nil and enable_lua == nil and not _WIREBAIT_ON_ then
    local wirebait = require("wirebaitlib");
    local dissector_tester = wirebait.new({
        only_show_dissected_packets = true,
        dissector_filepath="C:/Users/LaysDragon/AppData/Roaming/Wireshark/plugins/minecraft-forge.lua"
    });
    -- dissector_tester:dissectHexData("72ABE636AFC86572") -- To dissect hex data from a string (no pcap needed) 
    dissector_tester:dissectPcap("direct.pcapng") -- To dissect packets from a pcap file
    return
end

-- print("hello world")
-- zlib = require("zlib")
-- uncompress = zlib.inflate()
-- Extend TvbRange
ETvbRange = {}
-- ETvbRange_mt = {}
function ETvbRange:__index(key)
    if ETvbRange[key] ~= nil then
        return ETvbRange[key]
    end

    if type(self.__proto__[key]) == "function" then
        return function(...)
            return self.__proto__[key](self.__proto__, table.unpack({...}, 2))
        end
    end
    return self.__proto__[key]
end

function ETvbRange:__call(...)
    return ETvbRange:new(self.__proto__(...))
end

function ETvbRange:uncompress(...) return ETvbRange:new(self.__proto__:uncompress(...)) end

function ETvbRange:new(range)
    if range == nil then
        error("nil range")
    end
    return setmetatable({
        __proto__ = range
    }, self)
end

function ETvbRange:proto()
    return self.__proto__
end

function ETvbRange:varint()
    local flagMask = 128
    local dataMask = 127
    local result = 0
    local shift = 0
    while shift < self:len() and 7 * shift <= 35 do
        local b = self(shift, 1):uint()
        result = bit.bor(bit.lshift(bit.band(b, dataMask), 7 * shift), result)
        shift = shift + 1
        if bit.band(b, flagMask) == 0 then
            return result, shift, true
        end
    end
    return 0, 0, false

end

function ETvbRange:mcstring()
    local string_len, shift = self:varint()
    return self(shift,string_len):string(ENC_UTF_8),shift + string_len
end

function ETvbRange:next_terminating_zero()
    local offset = 0
    while offset < self:len() do
        if self(offset,1):le_uint() == 0 then
            return offset
        end
        offset = offset + 1
    end
    return self:len()
end

function ETvbRange:estringz()

    -- local offset = 0
    local shift = self:next_terminating_zero()
    if shift < self:len() then
        shift = shift +1
    end
    return self(0,shift):string(ENC_UTF_8),shift
end

-- Extend Tvb

ETvb = {}
-- ETvb_mt = {}
function ETvb:__index(key)
    if ETvb[key] ~= nil then
        return ETvb[key]
    end

    if type(self.__proto__[key]) == "function" then
        return function(...)
            return self.__proto__[key](self.__proto__, ...)
        end
    end

    return self.__proto__[key]
end

function ETvb:__call(...)
    return ETvbRange:new(self.__proto__(...))
end

function ETvb:new(buffer)
    return setmetatable({
        __proto__ = buffer
    }, self)
end

function ETvb:proto()
    return self.__proto__
end

-- Utils

function copy(obj, seen)
    -- Handle non-tables and previously-seen tables.
    if type(obj) ~= 'table' then
        return obj
    end
    if seen and seen[obj] then
        return seen[obj]
    end

    -- New table; mark it as seen and copy recursively.
    local s = seen or {}
    local res = {}
    s[obj] = res
    for k, v in pairs(obj) do
        res[copy(k, s)] = copy(v, s)
    end
    return setmetatable(res, getmetatable(obj))
end

get_tcp_stream = Field.new("tcp.stream")
get_frame_number = Field.new("frame.number")

conversation = {}
conversation_mark = {}

function get_conversation()
    local stream_id = get_tcp_stream().value
    local frame_number = get_frame_number().value

    init_conversation(frame_number)

    local target_frame = 0
    -- print('---')
    for _, f_id in ipairs(conversation_mark[stream_id]) do
        -- print(f_id)
        if f_id > frame_number then
            break
        end
        target_frame = f_id
    end
    -- print('=>'..target_frame)
    -- print('---')

    return conversation[stream_id][target_frame]
end

function init_conversation(frame_number)
    local stream_id = get_tcp_stream().value
    frame_number = frame_number or get_frame_number().value

    if conversation[stream_id] == nil then
        conversation[stream_id] = {
            [frame_number] = {
                compressed = false,
                compression_threshold = 0,
                state = state_type.Handshaking,
                bound = bound_type.Server,
            }
        }
        conversation_mark[stream_id] = {frame_number}
    end

end

function mark_conversation(next_frame)
    next_frame = next_frame or false
    local stream_id = get_tcp_stream().value
    local frame_number = get_frame_number().value
    if next_frame then
        frame_number = frame_number + 1
    end
    
    -- local already_mark = false
    if conversation[stream_id][frame_number] ~= nil then
        return conversation[stream_id][frame_number]
        -- already_mark = true
    end

    local state = copy(get_conversation())

    conversation[stream_id][frame_number] = state
    table.insert(conversation_mark[stream_id], frame_number)
    -- if not already_mark then
    --     table.insert(conversation_mark[stream_id], frame_number)
    -- end
    -- table.sort(conversation_mark[stream_id])
    
    return state
end

function tprint(tbl, indent)
    if not indent then
        indent = 0
    end
    local toprint = string.rep(" ", indent) .. "{\r\n"
    indent = indent + 2
    for k, v in pairs(tbl) do
        toprint = toprint .. string.rep(" ", indent)
        if (type(k) == "number") then
            toprint = toprint .. "[" .. k .. "] = "
        elseif (type(k) == "string") then
            toprint = toprint .. k .. "= "
        end
        if (type(v) == "number") then
            toprint = toprint .. v .. ",\r\n"
        elseif (type(v) == "string") then
            toprint = toprint .. "\"" .. v .. "\",\r\n"
        elseif (type(v) == "table") then
            toprint = toprint .. tprint(v, indent + 2) .. ",\r\n"
        elseif (type(v) == "boolean") then
            toprint = toprint .. tostring(v) .. ",\r\n"
        else
            toprint = toprint .. "\"" .. tostring(v) .. "\",\r\n"
        end
    end
    toprint = toprint .. string.rep(" ", indent - 2) .. "}"
    -- return toprint
    print(toprint)
end

-- main

minecraft_forge_protocol = Proto("MCForge", "Minecraft Forge Protocol")

function minecraft_forge_protocol.init()
    conversation = {}
    conversation_mark = {}
end

-- packet_length = ProtoField.int32("mcforge.packet_length", "Length", base.DEC)
bound_type = {
    Server = "Server",
    Client = "Client",
}

state_type = {
    Handshaking = "Handshaking",
    Status  = "Status",
    Login = "Login" ,
    Play = "Play",

    [0] = "Handshaking",
    [1] = "Status",
    [2] = "Login",
    [3] = "Play",
}

packet_id_display = {
    [state_type.Handshaking]={
        [bound_type.Server]={
            [0] = "Handshaking",
        },
        [bound_type.Client]={
        }
    },
    [state_type.Status]={
        [bound_type.Server]={
        },
        [bound_type.Client]={
        }
    },
    [state_type.Login]={
        [bound_type.Server]={
            [0] = "Login Start",
            [1] = "Encryption Response",
        },
        [bound_type.Client]={
            [0] = "Disconnect",
            [1] = "Encryption Request",
            [2] = "Login Success",
            [3] = "Set Compression",
        }
    },
    [state_type.Play]={
        [bound_type.Server]={
            [9]="Plugin Message",
            [11]="Keep Alive",
            [13]="Player Position",
            [14]="Player Position And Look",
            [29]="Animation",
            [31]="Player Block Placement",
        },
        [bound_type.Client]={
            [3]="Spawn Mob",
            [11]="Block Change",
            [20]="Window Items",
            [22]="Set Slot",
            [24]="Plugin Message",
            [26]="Disconnect",
            [32]="Chunk Data",
            [35]="Join Game",
            [38]="Entity Relative Move",
            [39]="Entity Look And Relative Move",
            [50]="Destroy Entities",
            [54]="Entity Head Look",
            [60]="Entity Metadata",
            [62]="Entity Velocity",
            [63]="Entity Equipment",
            [71]="Time Update",
            [73]="Sound Effect",
            [78]="Entity Properties",
        }
    },
    
}

packet_id_display_mt = {}
function packet_id_display_mt:__index(key)
    state = get_conversation()
    if self[state.state][state.bound][key] == nil then
        return string.format("0x%02x Unknown", key)
    end
    return string.format("0x%02x %s", key,self[state.state][state.bound][key])
end
setmetatable(packet_id_display,packet_id_display_mt)


fmlhs_display = {
    [0]="ServerHello",
    [1]="ClientHello",
    [2]="ModList",
    [3]="RegistryData",
    [-1]="HandshakeAck",
    [-2]="HandshakeReset",
}
fmlhs_phase_display = {
    [bound_type.Client]={
        [2]="WAITINGCACK",
        [3]="COMPLETE",
    },
    [bound_type.Server]={
        [2]="WAITINGSERVERDATA",
        [3]="WAITINGSERVERCOMPLETE",
        [4]="PENDINGCOMPLETE",
        [5]="COMPLETE",
    },
    
}


fmlhs_type = {
    ServerHello = 0,
    ClientHello = 1,
    ModList = 2,
    RegistryData = 3,
    HandshakeAck = -1,
    HandshakeReset = -2,
}

protocol_fields = {
    packet_length = ProtoField.int32("mcforge.packet_length", "Length", base.DEC),
    packet_id = ProtoField.uint32("mcforge.packet_id", "ID", base.HEX),

    
    protocol_version = ProtoField.int32("mcforge.protocol_version", "Protocol Version", base.DEC),
    server_address = ProtoField.string("mcforge.server.address", "Server Address", base.UNICODE),
    server_port  = ProtoField.uint16("mcforge.server.port", "Server Port", base.DEC),
    handshacking_next_state = ProtoField.uint8("mcforge.handshacking_next_state", "Next State", base.DEC,{[1]="status",[2]="login"}),

    player_name = ProtoField.string("mcforge.player.name", "Player Username", base.UNICODE),

    compression_threshold = ProtoField.int32("mcforge.compression_threshold", "Compression Threshold", base.DEC),

    player_uuid = ProtoField.string("mcforge.player.uuid", "Player UUID", base.UNICODE),

    plugin_channel = ProtoField.string("mcforge.plugin_channel", "Channel", base.UNICODE),
    plugin_channel_data = ProtoField.bytes("mcforge.plugin_channel.data", "Data"),
    plugin_channel_register_channel = ProtoField.string("mcforge.plugin_channel.register.channel", "Channel", base.UNICODE),

    plugin_channel_fmlhs_discriminator = ProtoField.int8("mcforge.plugin_channel.fmlhs.discriminator", "Discriminator", base.DEC,fmlhs_display),
    
    plugin_channel_fmlhs_fml_protocol_version = ProtoField.uint8("mcforge.plugin_channel.fmlhs.protocol_version", "FML protocol Version", base.DEC),
    plugin_channel_fmlhs_override_dimension = ProtoField.int32("mcforge.plugin_channel.fmlhs.override_dimension", "Override dimension", base.DEC),

    plugin_channel_fmlhs_phase = ProtoField.int8("mcforge.plugin_channel.fmlhs.phase", "Phase", base.DEC),
    


    
}
minecraft_forge_protocol.fields = protocol_fields

function minecraft_forge_protocol.dissector(buffer, pinfo, tree)
    -- if pinfo.visited and next(conversation) ~= nil then
    --     return
    -- end
    buffer = ETvb:new(buffer)
    -- local buffer = buffer:len()
    local offset = 0
    if buffer:len() == 0 then
        return
    end
    local state = get_conversation()
    if pinfo.match_uint == pinfo.dst_port then
        state.bound = bound_type.Server
    else
        state.bound = bound_type.Client
    end
    

    -- if pinfo.conversation == nil then
    --     pinfo.conversation = 0
    -- end
    -- print(pinfo.conversation)
    -- pinfo.conversation = pinfo.conversation+1

    -- print(offset < buffer:len())
    -- print("===")
    
    while offset < buffer:len() do
        -- print("---")

        local packet_length, shift, ok = buffer(offset):varint()
        -- print('frame_id:'..tostring(get_frame_number()))
        -- print('packet_length:'..tostring(packet_length))
        -- pinfo.cols.info = 'packet_length:'..tostring(packet_length)
        -- local subtreet = tree:add(minecraft_forge_protocol, buffer(offset), "Minecraft Forge Packet Test")

        -- subtreet:add_le(protocol_fields.packet_length, buffer(offset, shift):proto(), packet_length)
        -- print(type(packet_length))
        -- print(tostring(packet_length))
        -- print("shift:"..shift)
        -- print("offset:"..offset)
        -- print("len:"..buffer:len())

        if not ok then
            pinfo.desegment_offset = offset;
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            -- print("next segment not enough")
            return buffer:len()
            -- return
        end

        if buffer:len() < packet_length then
            pinfo.desegment_offset = offset
            pinfo.desegment_len = packet_length - buffer:len();
            -- print("next segment packet_length not enough")
            return buffer:len()
            -- return
        end

        pinfo.cols.protocol = minecraft_forge_protocol.name
        local subtree = tree:add(minecraft_forge_protocol, buffer(offset), "Minecraft Forge Packet")

        subtree:add_le(protocol_fields.packet_length, buffer(offset, shift):proto(), packet_length)
        offset = offset + shift

        local dataBuffer = buffer
        local dataOffset = offset
        local compressed = false
        local data_length = packet_length

        if get_conversation().compressed then
            data_length, shift, ok = buffer(offset):varint()
            offset = offset + shift
            -- print(data_length, shift, ok)
            if data_length > 0 then
                dataBuffer = buffer(offset):uncompress("Data")
                dataOffset = 0
                compressed = true
            else
                dataOffset = offset
                data_length = packet_length + shift --TODO: fix it,i have no idea why I need to add this + shift to prevent out of range
            end
        end
        local data_description = ""
        if compressed then
            data_description = "(Compressed) ".. data_length .." bytes"
        end
        local data_tree = subtree:add("Data", buffer(offset),data_description)

        -- buffer = bufferf
        local packet_id, shift = dataBuffer(dataOffset):varint()
        data_tree:add_le(protocol_fields.packet_id, dataBuffer(dataOffset, shift):proto(), packet_id):append_text(" (" .. packet_id_display[packet_id] .. ")")
        dataOffset = dataOffset + shift

        local left_length = data_length - dataOffset
        print(buffer:len(),dataBuffer:len(),data_length,packet_length,left_length)

        
        pinfo.cols.info = "["..state.state.."]["..state.bound .. " Bound] "..packet_id_display[packet_id]

        if handlers[state.state][state.bound][packet_id] ~= nil then
            shift = handlers[state.state][state.bound][packet_id](dataBuffer(dataOffset), pinfo, data_tree,left_length)
            dataOffset = dataOffset + shift

            offset = offset + dataOffset
        else
            offset = offset + packet_length
        end
        --
        
        

        -- print(offset,buffer:len())
        tprint(get_conversation())
    end
    -- return offset
end

function packet_handshaking_server_0x00_handshaking(buffer, pinfo, tree,left_length)
    local offset = 0
    local version, shift = buffer:varint()
    tree:add_le(protocol_fields.protocol_version, buffer(offset, shift):proto(), version)
    offset = offset + shift

    
    
    local server_address , shift = buffer(offset):mcstring()
    tree:add_le(protocol_fields.server_address, buffer(offset,shift):proto(), server_address)
    offset = offset + shift


    tree:add_le(protocol_fields.server_port, buffer(offset,2):proto(), buffer(offset,2):uint())
    offset = offset + 2

    local next_state, shift = buffer(offset):varint()
    tree:add_le(protocol_fields.handshacking_next_state, buffer(offset, shift):proto(), next_state)
    offset = offset + shift

    local state = mark_conversation(true)
    if next_state == 1 then
        state.state = state_type.Status
    else  
        state.state = state_type.Login
    end

    return offset
end

function packet_login_server_0x00_login_start(buffer, pinfo, tree,left_length)
    local offset = 0

    local player_name , shift = buffer(offset):mcstring()
    tree:add_le(protocol_fields.player_name, buffer(offset,shift):proto(), player_name)
    offset = offset + shift

    return offset
end

function packet_login_client_0x02_login_success(buffer, pinfo, tree,left_length)
    local offset = 0
    

    
    -- tree:add_le(protocol_fields.player_uuid, buffer(offset,16):proto(), buffer(offset,16))
    -- offset = offset + 16

    local player_uuid , shift = buffer(offset):mcstring()
    tree:add_le(protocol_fields.player_uuid, buffer(offset,shift):proto(), player_uuid)
    offset = offset + shift

    local player_name , shift = buffer(offset):mcstring()
    tree:add_le(protocol_fields.player_name, buffer(offset,shift):proto(), player_name)
    offset = offset + shift

    local state = mark_conversation(true)
    state.state = state_type.Play

    return offset
end


function packet_login_client_0x03_set_compression(buffer, pinfo, tree,left_length)
    local offset = 0

    local threshold, shift = buffer:varint()
    tree:add_le(protocol_fields.compression_threshold, buffer(offset, shift):proto(), threshold)
    offset = offset + shift
    
    local state = mark_conversation(true)
    state.compressed = true
    state.compression_threshold = threshold

    return offset
end

function packet_play_client_server_0x18_plugin_message(buffer, pinfo, tree,left_length)
    local offset = 0

    local plugin_channel , shift = buffer(offset):mcstring()
    tree:add_le(protocol_fields.plugin_channel, buffer(offset,shift):proto(), plugin_channel)
    offset = offset + shift
    
    local left_length = left_length - shift
    local databuffer = buffer(offset,left_length)
    local subtree = tree:add_le(protocol_fields.plugin_channel_data, databuffer:proto())
    offset = offset + left_length

    local state = get_conversation()
    pinfo.cols.info = tostring(pinfo.cols.info) .." ["..plugin_channel.."]"

    if handlers.PluginChannels[plugin_channel] ~= nil and handlers.PluginChannels[plugin_channel][state.bound] ~= nil then
        handlers.PluginChannels[plugin_channel][state.bound](pinfo,subtree,databuffer)
    end
    



    return offset
end


-- handlers = {
--     [0] = packet_0x00_handshaking,
--     [3] = packet_0x03_set_compression
-- }
function channel_server_client_register(pinfo,tree,buffer)
    local offset = 0
    while offset < buffer:len() do
        local shift = buffer(offset):next_terminating_zero() 
        local channel , shift = buffer(offset):estringz()
        tree:add_le(protocol_fields.plugin_channel_register_channel, buffer(offset,shift):proto(), channel)
        offset = offset + shift

        -- break
    end
end

function channel_server_client_fmlhs(pinfo,tree,buffer)
    local offset = 0

    local state = get_conversation()

    tree:add_le(protocol_fields.plugin_channel_fmlhs_discriminator, buffer(offset,1):proto())
    local discriminator = buffer(offset,1):int()
    pinfo.cols.info = tostring(pinfo.cols.info) .." "..fmlhs_display[discriminator]..""
    offset = offset + 1
    if discriminator == fmlhs_type.ServerHello then
        local protocol_version = buffer(offset,1):int()
        tree:add_le(protocol_fields.plugin_channel_fmlhs_fml_protocol_version, buffer(offset,1):proto(),protocol_version)
        offset = offset + 1
        
        if protocol_version > 1 then
            tree:add_le(protocol_fields.plugin_channel_fmlhs_override_dimension, buffer(offset,4):proto())
            offset = offset + 4
        end

        
    elseif discriminator == fmlhs_type.ClientHello then
        local protocol_version = buffer(offset,1):int()
        tree:add_le(protocol_fields.plugin_channel_fmlhs_fml_protocol_version, buffer(offset,1):proto(),protocol_version)
        offset = offset + 1
        
    elseif discriminator == fmlhs_type.ModList then
    elseif discriminator == fmlhs_type.HandshakeAck then
        local phase = buffer(offset,1):int()
        tree:add_le(protocol_fields.plugin_channel_fmlhs_phase, buffer(offset,1):proto(),phase):append_text(" ("..fmlhs_phase_display[state.bound][phase]..")")
        offset = offset + 1
        pinfo.cols.info = tostring(pinfo.cols.info) .." = "..tostring(phase).."("..fmlhs_phase_display[state.bound][phase]..")"


    elseif discriminator == fmlhs_type.HandshakeReset then
    end
    


end


handlers = {
    [state_type.Handshaking]={
        [bound_type.Server]={
            [0] = packet_handshaking_server_0x00_handshaking,
        },
        [bound_type.Client]={
        }
    },
    [state_type.Status]={
        [bound_type.Server]={
        },
        [bound_type.Client]={
        }
    },
    [state_type.Login]={
        [bound_type.Server]={
            [0] = packet_login_server_0x00_login_start
        },
        [bound_type.Client]={
            [2]=packet_login_client_0x02_login_success,
            [3] = packet_login_client_0x03_set_compression,
        }
    },
    [state_type.Play]={
        [bound_type.Server]={
            [9] = packet_play_client_server_0x18_plugin_message,

        },
        [bound_type.Client]={
            [24] = packet_play_client_server_0x18_plugin_message,
        }
    },
    PluginChannels = {
        REGISTER = {
            [bound_type.Client]=channel_server_client_register,
            [bound_type.Server]=channel_server_client_register,
        },
        ["FML|HS"] = {
            [bound_type.Client]=channel_server_client_fmlhs,
            [bound_type.Server]=channel_server_client_fmlhs,
        }
    }
}


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(25565, minecraft_forge_protocol)

