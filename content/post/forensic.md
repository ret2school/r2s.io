+++
title = "[Hitcon CTF 2020 - forensic] AC1750"
tags = ["ctf", "HitconCTF", "forensics", "supersnail", "Zeynn", "aaSSfxxx", "2020"]
date = "2020-12-01"
+++

Hello world,

The write up is about the [AC1750](https://www.mediafire.com/file/cs2xsbc7vzrimfm/ac1750-452ca8a9038502712d30c628d3444e5a22894611f1286b7a818203bdf838b434.tar.gz/file) challenge in HITCON ctf. It's a forensic challenge, where we need to analyze packets captured by Wireshark to find out what an attacker is doing on the network.

First, we need to analyze intercepted traffic with wireshark. We see a lot of HTTP packets, and some contain "Archer" references. We can see weird UDP packets with port 20002.

After some google-fu on port 20002, we come accross [this](https://www.speedguide.net/port.php?port=20002), and we can see there is a CVE targeting T-Link Archer devices. Since we noticed "archer" reference, this could be a solution...

One of the reference is an exploit [script](https://packetstormsecurity.com/files/157255/TP-Link-Archer-A7-C7-Unauthenticated-LAN-Remote-Code-Execution.html),  we need to analyze.

The CVE tells us that the packets are encrypted with a default key and IV, and use AES-128. So to verify this, let's try to decrypt an UDP payload with those parameters:

```python

>>> bob = bytes([ ... UDP packet contents ...])
>>> iv = b"1234567890abcdef"
>>> key = b"TPONEMESH_Kf!xn?"
>>> aes = AES.new(key, AES.MODE_CBC, iv)
>>> aes.decrypt(bob)
b'\xd5\xee\x8fC\xb0\xc9\xd7\x06O"@\xd7I\xe0(tK\xe0^V@NY\\\t>\x178GZ\xb6de_key_offer", "data": {"group_id": "1234", "ip": "1.3.3.7", "slave_mac": "\';echo>f;\'", "slave_private_account": "aaaaa", "slave_private_password": "aaaaa", "want_to_join": false, "model": "owned", "product_type": "archer", "operation_mode": "aaaaa"}}      '

```
Bingo, we get some readable json ! Now we need to automate this, to decrypt packets sent to port 20002. Using dpkt, we can quickly get this script:

```python

from Crypto.Cipher import AES
import dpkt
from json import loads

pcap = dpkt.pcapng.Reader(open("ac1750.pcapng", "rb"))
pcap.setfilter("udp.dport == 20002")
for ts, pkt in pcap:
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    frm = ip.data
    if isinstance(frm, dpkt.udp.UDP):
        if frm.dport == 20002:
            aes = AES.new(b"TPONEMESH_Kf!xn?", AES.MODE_CBC, b"0123456789abcdef")
            data = frm.data
            data_len = (len(data) // 16) * 16
            try:
                json_inc = aes.decrypt(frm.data).rstrip()
                offset = json_inc.find(b"\"data\": ")
                json = json_inc[offset+8:-1]
                obj = loads(json)
                print(obj["slave_mac"][2:-1])
            except ValueError:
                pass

```
Which returns some interesting commands:
```								
'h'>>f;
'i'>>f;
't'>>f;
'c'>>f;
'o'>>f;
'n'>>f;
'{'>>f;
'W'>>f;
'h'>>f;
'y'>>f;
'_'>>f;
'c'>>f;
'a'>>f;
'n'>>f;
'_'>>f;
'o'>>f;
'n'>>f;
'e'>>f;
'_'>>f;
'p'>>f;
'l'>>f;
'a'>>f;
'c'>>f;
'e'>>f;
'_'>>f;
'b'>>f;
'e'>>f;
'_'>>f;
'i'>>f;
'n'>>f;
'j'>>f;
'e'>>f;
'c'>>f;
't'>>f;
'e'>>f;
'd'>>f;
'_'>>f;
't'>>f;
'w'>>f;
'i'>>f;
'c'>>f;
'e'>>f;
'}'>>f;
```

This lead us to the flag: hitcon{Why_can_one_place_be_injected_twice}.

;)

