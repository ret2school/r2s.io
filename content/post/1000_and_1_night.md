+++
title = "[AeroCTF 2020 - RE] 1000 and 1 night"
tags = ["ctf", "ret2school", "Aero CTF 2020", "reverse engineering", "RE", "supersnail", "aaSSfxxx", "2020"]
date = "2020-11-25"
+++

[Author: supersnail](http://aassfxxx.infos.st/)

Files can be found [here](https://rakovskij-stanislav.github.io/ctf_writeups/aeroctf_2020/tasks/files.zip)

For this challenge, we get an archive with a lot of files, the name of which seems to be a hash. Each file is an ELF x86_64 program file. In addition, a server listens, and requests:

```plain
Enter valid token to binary with name <8c235f89a8143a28a1d6067e959dd858>
Token:
```
at connection. We therefore understand quickly enough that we will have to automate the reversing of all these ELFs to send the correct token back to the server, and thus have the flag, the server requesting a series of tokens before spitting the flag.

Fortunately for us, these ELFs have a very similar structure, and automation should not be too difficult (especially since the binaries are not stripped). The interesting part is therefore in the "sym.check" function under radare2: 
```
            ; CALL XREF from main @ 0x1219
┌ 171: sym.check (void *arg1);
│           ; var void *s1 @ rbp-0x38
│           ; var void *s2 @ rbp-0x30
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var signed int64_t var_4h @ rbp-0x4
│           ; arg void *arg1 @ rdi
│           0x000012a4      55             push rbp
│           0x000012a5      4889e5         mov rbp, rsp
│           0x000012a8      4883ec40       sub rsp, 0x40
│           0x000012ac      48897dc8       mov qword [s1], rdi         ; arg1
│           0x000012b0      48b8110e5655.  movabs rax, 0xe57581255560e11
│           0x000012ba      48ba0e585544.  movabs rdx, 0x114758114455580e
│           0x000012c4      488945d0       mov qword [s2], rax
│           0x000012c8      488955d8       mov qword [var_28h], rdx
│           0x000012cc      48b80d131244.  movabs rax, 0x5614410e4412130d
│           0x000012d6      48ba470d5755.  movabs rdx, 0x430d424155570d47
│           0x000012e0      488945e0       mov qword [var_20h], rax
│           0x000012e4      488955e8       mov qword [var_18h], rdx
│           0x000012e8      c745fc000000.  mov dword [var_4h], 0
│       ┌─< 0x000012ef      eb2e           jmp 0x131f
│       │   ; CODE XREF from sym.check @ 0x1323
│      ┌──> 0x000012f1      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x000012f4      4863d0         movsxd rdx, eax
│      ╎│   0x000012f7      488b45c8       mov rax, qword [s1]
│      ╎│   0x000012fb      4801d0         add rax, rdx
│      ╎│   0x000012fe      0fb600         movzx eax, byte [rax]
│      ╎│   0x00001301      83c00a         add eax, 0xa
│      ╎│   0x00001304      83f022         xor eax, 0x22
│      ╎│   0x00001307      8d48f5         lea ecx, [rax - 0xb]
│      ╎│   0x0000130a      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x0000130d      4863d0         movsxd rdx, eax
│      ╎│   0x00001310      488b45c8       mov rax, qword [s1]
│      ╎│   0x00001314      4801d0         add rax, rdx
│      ╎│   0x00001317      89ca           mov edx, ecx
│      ╎│   0x00001319      8810           mov byte [rax], dl
│      ╎│   0x0000131b      8345fc01       add dword [var_4h], 1
│      ╎│   ; CODE XREF from sym.check @ 0x12ef
│      ╎└─> 0x0000131f      837dfc1f       cmp dword [var_4h], 0x1f
│      └──< 0x00001323      7ecc           jle 0x12f1
│           0x00001325      488d4dd0       lea rcx, [s2]
│           0x00001329      488b45c8       mov rax, qword [s1]
│           0x0000132d      ba20000000     mov edx, 0x20               ; "@" ; size_t n
│           0x00001332      4889ce         mov rsi, rcx                ; const void *s2
│           0x00001335      4889c7         mov rdi, rax                ; const void *s1
│           0x00001338      e833fdffff     call sym.imp.memcmp         ; int memcmp(const void *s1, const void *s2, size_t n)
│           0x0000133d      85c0           test eax, eax
│       ┌─< 0x0000133f      7407           je 0x1348
│       │   0x00001341      b800000000     mov eax, 0
│      ┌──< 0x00001346      eb05           jmp 0x134d
│      ││   ; CODE XREF from sym.check @ 0x133f
│      │└─> 0x00001348      b801000000     mov eax, 1
│      │    ; CODE XREF from sym.check @ 0x1346
│      └──> 0x0000134d      c9             leave
└           0x0000134e      c3             ret
```
We can see that crackme fills a buffer with 4 qwords (the encrypted "token"), before retrieving the serial entered by the user, and performing calculations on it before comparing it with the first buffer.

The input encryption algorithm is therefore for each byte:
```
out[i] = ((serial[i] + 0xa) ^ 0x22) - 0xb
```
All executables have the same algorithm, only the parameters, i.e. the buffer, and the constants 0xa, 0x22 and 0xb change for each binary. So we just have to exit python and r2pipe to extract these values and communicate with the server, which gives the python below (the binaries are placed in a "files" sub-folder):

```python
#!/usr/bin/python

import r2pipe
import sys
import struct
import pexpect
import socket

buf = b""

def get_tok(file):
    r2 = r2pipe.open("files/" + file)
    # Extraction du buffer
    buf = struct.pack("<Q", r2.cmdj("pdj 1 @0x000012b0")[0]["val"])
    buf += struct.pack("<Q", r2.cmdj("pdj 1 @0x000012ba")[0]["val"])
    buf += struct.pack("<Q", r2.cmdj("pdj 1 @0x000012cc")[0]["val"])
    buf += struct.pack("<Q", r2.cmdj("pdj 1 @0x000012d6")[0]["val"])

    # Extraction des params de chiffrement
    add_operand = r2.cmdj("pdj 1 @0x00001301")[0]["val"]
    xor_operand = r2.cmdj("pdj 1 @0x00001304")[0]["val"]
    final_sub = r2.cmdj("pdj 1 @0x00001307")[0]["esil"].split(",")[0]
    final_sub = int(final_sub[2:], 16)

    out = []
    for i in buf:
        out.append(((final_sub + i) ^ xor_operand) - add_operand)

    return "".join([chr(x) for x in out])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("tasks.aeroctf.com", 44324))
toto = sock.makefile()
while True:
    line = toto.readline()
    print(line)
    if line.find("Enter valid token") > -1:
        name = line[line.find("<")+1:-2]
        token = get_tok(name)
        sock.send(bytes(token + "\n", "ascii"))
```

The only "complicated" part here is to extract the good value from the "lea ecx, [rax - 0xb]", where I based myself on the ESIL evaluation made by radare2 to recover the good value. Finally, last subtlety, the server returns an ANSI terminal reset sequence after sending the flag, so we had to redirect the output to a file, to get the flag.

That's all folks ! :þ
