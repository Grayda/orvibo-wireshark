-- Include luagcrypt for decrypting AES
gcrypt = require "luagcrypt"

-- Include json for parsing JSON to table
json = require "json"

-- Include our config, where decryption keys are stored
config = require "config"

-- Register our proto object
orvibo_proto = Proto("orvibo","Orvibo Protocol")

-- These fields allow filtering
fields = orvibo_proto.fields
fields.data = ProtoField.string("orvibo.data", "Data") -- The whole untouched packet
fields.payload = ProtoField.string("orvibo.payload", "Decrypted Payload") -- The decrypted payload
fields.pk = ProtoField.bool("orvibo.pk", "PK Packet") -- If this is a PK packet
fields.dk = ProtoField.bool("orvibo.dk", "DK Packet") -- If this is a DK packet
fields.cmd = ProtoField.string("orvibo.cmd", "Command") -- The command we've extracted from our packet or JSON
fields.uid = ProtoField.string("orvibo.uid", "Unique ID") -- The command we've extracted from our packet or JSON

function orvibo_proto.dissector(buffer,pinfo,tree)
    -- This dissector will apply to both UDP and TCP packets
    pinfo.cols.protocol = "UDP" and "TCP"

    -- We're only concerned with packets that start with "hd", which is our Orvibo packet
    if buffer(0,2):string() == "hd" then
      -- Add an item to the packet information window
      local subtree = tree:add(orvibo_proto, buffer(),"Orvibo Packet")

      -- If this is a v2 packet, which is evident by the 4th byte being either "pk" or "dk""
      if buffer(4,2):string() == "pk" or buffer(4,2):string() == "dk" then

        -- Set up our ciphers
        local pkCipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_ECB)
        local dkCipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_ECB)

        -- Set the keys from our config.lua file
        pkCipher:setkey(pkKey)
        dkCipher:setkey(dkKey)

        -- Get the unencrypted payload, which starts from the 10th byte (I think)
        local payload = buffer(10, buffer:len() - 10):string()
        -- If the packet is PK
        if buffer(4,2):string() == "pk" then
          -- Decrypt using the PK key, which was extracted from the Kepler APK
          -- We want everything from the first { to the last }
          decrypted = string.match(pkCipher:decrypt(payload), "{.*}")
          isPK = true
        -- If the packet is DK
        elseif buffer(4,2):string() == "dk" then
          -- Use the DK key. I believe this is generated server-side
          decrypted = string.match(dkCipher:decrypt(payload), "{.*}")
          isPK = false
        end

        -- Parse the decrypted packet as JSON
        jsonObj = json.decode(string.match(decrypted, "{.*}"))

        -- A new section in the packet information window
        subtree1 = subtree:add("Packet Information")
        -- Set orvibo.data to the whole buffer
        subtree1:add(fields.data, buffer())
        -- Display our encrypted payload as hex
        subtree1:add(buffer(10, buffer:len() - 10), "Encrypted Payload " .. buffer(10, buffer:len() - 10))
        -- Set orvibo.payload to our decrypted payload. Doing this also adds it to the tree
        subtree1:add(fields.payload, decrypted)
        -- If we've got a PK packet
        if isPK == true then
          -- Same as above. Set orvibo.pk to true (needs to be an int, not a boolean for some reason)
          subtree1:add(fields.pk, 1)
        elseif isPK == false then
          -- Same as above, but for DK
          subtree1:add(fields.dk, 1)
        end

        -- Display the packet checksum
        subtree1:add(buffer(6, 4), "Checksum " .. buffer(6,4))
        if jsonObj.cmd ~= nil then
          -- Grab the cmd from our JSON and set it to orvibo.cmd
          subtree1:add(fields.cmd, jsonObj.cmd)
        end

        if jsonObj.uid ~= nil then
          -- Grab the uid from our JSON and set it to orvibo.uid
          subtree1:add(fields.uid, jsonObj.uid)
        end

        -- Add a new section to the tree
        subtree2 = subtree:add("Payload Contents:")
        -- Loop through all the items in the JSON table
        for key, value in pairs(jsonObj) do
          -- Same as above
          subtree2:add(key .. ": " .. value)
        end
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
