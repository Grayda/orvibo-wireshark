gcrypt = require "luagcrypt"
json = require "json"
config = require "config"

local cipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_ECB)
cipher:setkey(key)

orvibo_proto = Proto("orvibo","Orvibo Protocol")
function orvibo_proto.dissector(buffer,pinfo,tree)
      pinfo.cols.protocol = "UDP"
      if buffer(0,2):string() == "hd" and buffer(4,2):string() == "pk" then
        local subtree = tree:add(orvibo_proto,buffer(),"Orvibo PK packet")
        local payload = buffer(10, buffer:len() - 10):string()
        subtree:add(buffer(4, 2), "Packet Type: " .. buffer(4, 2):string())
        subtree:add(buffer(6, 4), "CRC Checksum: " .. buffer(6,4))
        -- Trim the payload
        payload = cipher:decrypt(payload:gsub("^%s+", ""):gsub("%s+$", ""))
        res = json.decode(payload:gsub("^%s+", ""):gsub("%s+$", ""))
        subtree = subtree:add("Payload Contents:")
        for key, value in pairs(res) do
          subtree:add(key .. ": " .. value)
        end

      end
end

-- load the udp.port table, and tcp.port table
udp_table = DissectorTable.get("udp.port")
tcp_table = DissectorTable.get("tcp.port")

for key, value in pairs(ports) do
  udp_table:add(value, orvibo_proto)
  tcp_table:add(value ,orvibo_proto)
end
