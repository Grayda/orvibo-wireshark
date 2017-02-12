gcrypt = require "luagcrypt"
json = require "json"
config = require "config"

local cipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_ECB)
cipher:setkey(key)



-- trivial protocol example
-- declare our protocol
orvibo_proto = Proto("orvibo","Orvibo Protocol")
-- create a function to dissect it
function orvibo_proto.dissector(buffer,pinfo,tree)
      pinfo.cols.protocol = "UDP"
      if buffer(0,2):string() == "hd" and buffer(4,2):string() == "pk" then
        local subtree = tree:add(orvibo_proto,buffer(),"Orvibo PK packet")
        local payload = buffer(10, buffer:len() - 10):string()
        subtree:add(buffer(4, 2), "Packet Type: " .. buffer(4, 2):string())
        subtree:add(buffer(6, 4), "CRC Checksum: " .. buffer(6,4))
        -- Trim the payload
        payload = trim(payload:gsub("^%s+", ""):gsub("%s+$", ""))
        res = json.decode(cipher:decrypt(payload))

        subtree:add("Decrypted payload: " .. res)

      end
end

function Strip_Control_and_Extended_Codes( str )
    local s = ""
    for i = 1, str:len() do
	if str:byte(i) >= 32 and str:byte(i) <= 126 then
  	    s = s .. str:sub(i,i)
	end
    end
    return s
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 10000
udp_table:add(10000,orvibo_proto)
