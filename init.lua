gcrypt = require "luagcrypt"
json = require "json"
config = require "config"

-- AES128, ECB
local pkCipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_ECB)
local dkCipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_ECB)

-- Set the keys from our config.lua file
pkCipher:setkey(pkKey)
dkCipher:setkey(dkKey)

orvibo_proto = Proto("orvibo","Orvibo Protocol")
function orvibo_proto.dissector(buffer,pinfo,tree)
      -- This dissector applies to both UDP and TCP packets
      pinfo.cols.protocol = "UDP" and "TCP"
      -- If the packet contains "hd" (which is Orvibo's magic word) AND is a "pk" type Packet
      if buffer(0,2):string() == "hd" and buffer(4,2):string() == "pk" then
        -- Add a top-level item to our packet description pane
        local subtree = tree:add(orvibo_proto,buffer(),"Orvibo PK packet")
        -- Get the payload we're going to decrypt
        local payload = buffer(10, buffer:len() - 10):string()
        -- Trim spaces from the payload
        payload = payload:gsub("^%s+", ""):gsub("%s+$", "")
        -- Actually decrypt the payload
        decrypted = pkCipher:decrypt(payload)

        subtree1 = subtree:add("Data:")
        subtree1:add(buffer(), "Raw Packet: " .. buffer())
        subtree1:add(buffer(10, buffer:len() - 10), "Encrypted Payload: " .. buffer(10, buffer:len() - 10))
        subtree1:add(buffer(10, buffer:len() - 10), "Decrypted Payload: " .. decrypted)

        subtree:add(buffer(4, 2), "Packet Type: " .. buffer(4, 2):string())
        subtree:add(buffer(6, 4), "CRC Checksum: " .. buffer(6,4))
        subtree:add("Trimmed Payload Length: " .. payload:len())

        res = json.decode(decrypted:gsub("^%s+%x06+", ""):gsub("%s+%x06+$", ""))
        subtree2 = subtree:add("Payload Contents:")
        for key, value in pairs(res) do
          subtree2:add(key .. ": " .. value)
        end
      elseif buffer(0,2):string() == "hd" and buffer(4,2):string() == "dk" then
        -- Add a top-level item to our packet description pane
        local subtree = tree:add(orvibo_proto,buffer(),"Orvibo DK packet")
        -- Get the payload we're going to decrypt
        local payload = buffer(10, buffer:len() - 10):string()
        -- Trim spaces from the payload
        payload = payload:gsub("^%s+", ""):gsub("%s+$", "")
        -- Actually decrypt the payload
        decrypted = dkCipher:decrypt(payload)

        subtree1 = subtree:add("Data:")
        subtree1:add(buffer(), "Raw Packet: " .. buffer())
        subtree1:add(buffer(10, buffer:len() - 10), "Encrypted Payload: " .. buffer(10, buffer:len() - 10))
        subtree1:add(buffer(10, buffer:len() - 10), "Decrypted Payload: " .. decrypted)

        subtree:add(buffer(4, 2), "Packet Type: " .. buffer(4, 2):string())
        subtree:add(buffer(6, 4), "CRC Checksum: " .. buffer(6,4))
        subtree:add("Trimmed Payload Length: " .. payload:len())

        res = json.decode(decrypted:gsub("^%s+%x06+", ""):gsub("%s+%x06+$", ""))
        subtree2 = subtree:add("Payload Contents:")
        for key, value in pairs(res) do
          subtree2:add(key .. ": " .. value)
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
