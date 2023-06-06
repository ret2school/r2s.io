+++
title = "[UTCTF 2020 - RE] Crack the heart"
tags = ["ctf", "ret2school", "UTCTF", "reverse engineering", "RE", "supersnail", "aaSSfxxx", "2020"]
date = "2020-11-25"
+++

[Author: supersnail](http://aassfxxx.infos.st/)

For this challenge, I first noticed (like in every other writeups) a big structure of offsets, that pointed to "funclets" followed by jump with rcx-relative offsets.

![Offset table](http://aassfxxx.infos.st/media/crack-the-heart/offsettbl.png)

The relative jump function:

![Next offset](http://aassfxxx.infos.st/media/crack-the-heart/nextoffset.png)

The first funclet just checks for the process being debugged, the "load_r9" funclet that jumps to the next funclet after skipping "n" bytes of garbage. Then the crackme calls a funclet "write_message" with the parameters (offset to "Why should I go out with you?" message and its size) stored after the function offset.

Then we can see funclets that xor registers, move data from offsets, and seem to perform some sort of "key scheduling", which made me to think about that good old RC4 encryption scheme.
Studying the crackme confirmed my doubts, we have an obfuscated "keyState", which is basically a table of pointers containing the actual table:

![Key state](http://aassfxxx.infos.st/media/crack-the-heart/keystate.png)

The key is also obfuscated inside garbage bytes, and each key byte is referenced by the second "set_rsi_param" call for each key-scheduling block for each key character. To  confuse the reverser, the key is also 255 bytes long, and contain non-printable characters.

Now, since we located the key and the algorithm used, we need to locate where the encrypted data (probably the flag) is located. After a little debugging with radare2 (and a a breakpoint on the "write_message" function), I finally located it in the offset table

![Key state](http://aassfxxx.infos.st/media/crack-the-heart/keyloc.png).

Given this, I wrote a script relying a lot on r2pipe to crack the crackme and get the flag:
```python

#!/usr/bin/python
import r2pipe
import struct
from Crypto.Cipher import ARC4

rop_buf = 0x4045A6

r9_caution = 0x4021FD
rsi_param = 0x402102
and_param = 0x402065

r2 = r2pipe.open("./crackme")

is_key_loading = True
count = 0
key = b""

while count < 256:
    buf = bytes(r2.cmdj("pxj 8 @0x%x" % rop_buf))
    addr = struct.unpack("<Q", buf)[0]
    if addr == rsi_param:
        if is_key_loading:
            buf = bytes(r2.cmdj("pxj 8 @0x%x" % (rop_buf + 8)))
            addr = struct.unpack("<Q", buf)
            key += bytes(r2.cmdj("pxj 1 @0x%x" % addr))
            count += 1
            is_key_loading = False
        else:
            is_key_loading = True
        rop_buf += 8
    elif addr == and_param:
        rop_buf += 8
    elif addr == r9_caution:
        rop_buf += 8 + r2.cmdj("pxj 1 @0x%x" % (rop_buf + 8))[0]
    rop_buf += 8
print(key)

data = 0x4022D5
buf = bytes(r2.cmdj("pxj 256 @0x%x" % data))
cipher = ARC4.new(key)
print(cipher.encrypt(buf))

```
