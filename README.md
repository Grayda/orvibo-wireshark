# orvibo-wireshark
orvibo-wireshark is a Wireshark Dissector designed to display Orvibo packets as they come in. Right now it only supports v2 (newer) Orvibo packets, but may eventually be expanded to include legacy packets.

## Building and installing
This dissector relies on luagcrypt, which in turn relies on libgcrypt. See https://github.com/Lekensteyn/luagcrypt/ for more information, but building steps would go like this:

- Clone the `luagcrypt` repo somewhere
- Install libgcrypt and the Lua dev libraries using apt:
  - `sudo apt-get install libgcrypt20 libgcrypt20-dev liblua5.2-0 liblua5.2-0-dev`
- On Ubuntu 14.04 I needed to copy `/usr/include/lua5.2` to `/usr/local/include`
- Run `make` from the `luagcrypt` directory
- Copy `luagcrypt.so` out of the directory and into this directory
- Copy this whole folder (`luagcrypt.so` and `init.lua` to) `~/.wireshark/plugins` (make the `plugins` folder if necessary)
- Rename `config.sample.lua` to `config.lua`. Change the key to the key you've obtained from the Kepler APK
- Launch Wireshark. If you get a "module not found" error, run Wireshark from the plugin directory.

You can use LuaRocks to build this on Windows, but this hasn't been tested

## Using This Dissector
When an Orvibo packet is found, it'll appear in the Packet Detail window, under "Orvibo PK Packet". Right now it shows packet type, CRC checksum and the decrypted payload

## Acknowledgement
This code uses [json.lua](https://github.com/rxi/json.lua) and is licensed under an MIT license
