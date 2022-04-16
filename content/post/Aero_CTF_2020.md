+++
title = "[AeroCTF 2020 - RE] go away"
tags = ["ctf", "ret2school", "AeroCTF", "Aero CTF 2020", "reverse engineering", "RE", "supersnail", "aaSSfxxx", "2020"]
date = "2020-11-26"
+++

Hello world,

This writeup concerns the most difficult challenge I did on the CTF (having occupied myself a few hours to break it). At first glance, we have an "obfuscated" binary, which makes system calls to mmap and mprotect: we immediately think of a packer, and we will therefore have to unpack it. 

## Unpacking crackme
Unpacking is not a problem on Linux when you are used to malware packers on Windows, thanks to radare2 and its visual mode.

The crack entrypoint therefore looks like this: 
```
            ;-- entry0:
            ;-- rip:
            0x0046cbe8      50             push rax
            0x0046cbe9      52             push rdx
            0x0046cbea      e8c8020000     call 0x46ceb7
            0x0046cbef      55             push rbp
            0x0046cbf0      53             push rbx
            0x0046cbf1      51             push rcx
            0x0046cbf2      52             push rdx
            0x0046cbf3      4801fe         add rsi, rdi
            0x0046cbf6      56             push rsi
            0x0046cbf7      4889fe         mov rsi, rdi
            0x0046cbfa      4889d7         mov rdi, rdx
            0x0046cbfd      31db           xor ebx, ebx
            0x0046cbff      31c9           xor ecx, ecx
            0x0046cc01      4883cdff       or rbp, 0xffffffffffffffff
```
 We have a call to a function 0x46ceb7, followed by what looks like a decompression function, especially aplib or one of its variants. So we have: 
```
┌ 6: fcn.0046ceb7 ();
│           0x0046ceb7      5d             pop rbp
└           0x0046ceb8      e840ffffff     call fcn.0046cdfd
```
followed by
```
           ; CALL XREF from fcn.0046ceb7 @ 0x46ceb8
┌ 186: fcn.0046cdfd (int64_t arg_0h);
│           ; var int64_t var_bh @ rbp-0xb
│           ; var int64_t var_10h @ rsp+0x30
│           ; var int64_t var_8h @ rsp+0x38
│           ; arg int64_t arg_0h @ rsp+0x40
│           0x0046cdfd      5f             pop rdi                     ; /proc/self/exe
│           0x0046cdfe      29f6           sub esi, esi
│           0x0046ce00      6a02           push 2                      ; SYS_open
│           0x0046ce02      58             pop rax
│           0x0046ce03      0f05           syscall
│           0x0046ce05      50             push rax
│           0x0046ce06      488db70f0000.  lea rsi, [rdi + 0xf]
│           0x0046ce0d      ad             lodsd eax, dword [rsi]
│           0x0046ce0e      83e0fe         and eax, 0xfffffffe         ; 4294967294
│           0x0046ce11      4189c6         mov r14d, eax
│           0x0046ce14      56             push rsi
│           0x0046ce15      5b             pop rbx
│           0x0046ce16      ad             lodsd eax, dword [rsi]
│           0x0046ce17      92             xchg eax, edx
│           0x0046ce18      4801da         add rdx, rbx
│           0x0046ce1b      ad             lodsd eax, dword [rsi]
│           0x0046ce1c      4195           xchg eax, r13d
│           0x0046ce1e      ad             lodsd eax, dword [rsi]
│           0x0046ce1f      4901f5         add r13, rsi
│           0x0046ce22      488d8df5ffff.  lea rcx, [var_bh]
│           0x0046ce29      448b39         mov r15d, dword [rcx]
│           0x0046ce2c      4c29f9         sub rcx, r15
│           0x0046ce2f      4529f7         sub r15d, r14d
│           0x0046ce32      5f             pop rdi
│           0x0046ce33      4829ca         sub rdx, rcx
│           0x0046ce36      52             push rdx
│           0x0046ce37      50             push rax
│           0x0046ce38      4929cd         sub r13, rcx
│           0x0046ce3b      57             push rdi
│           0x0046ce3c      51             push rcx
│           0x0046ce3d      4d29c9         sub r9, r9
│           0x0046ce40      4183c8ff       or r8d, 0xffffffff          ; -1
│           0x0046ce44      6a22           push 0x22                   ; '"' ; 34
│           0x0046ce46      415a           pop r10
│           0x0046ce48      52             push rdx
│           0x0046ce49      5e             pop rsi
│           0x0046ce4a      6a03           push 3                      ; 3
│           0x0046ce4c      5a             pop rdx
│           0x0046ce4d      29ff           sub edi, edi
│           0x0046ce4f      6a09           push 9                      ; SYS_mmap
│           0x0046ce51      58             pop rax
│           0x0046ce52      0f05           syscall
│           0x0046ce54      4901c6         add r14, rax
│           0x0046ce57      4889442410     mov qword [var_8h], rax
│           0x0046ce5c      4897           xchg rax, rdi
│           0x0046ce5e      448b442408     mov r8d, dword [var_10h]
│           0x0046ce63      6a12           push 0x12                   ; 18
│           0x0046ce65      415a           pop r10
│           0x0046ce67      4c89ee         mov rsi, r13
│           0x0046ce6a      6a09           push 9                      ; SYS_mmap
│           0x0046ce6c      58             pop rax
│           0x0046ce6d      0f05           syscall
│           0x0046ce6f      488b542418     mov rdx, qword [arg_0h]
│           0x0046ce74      59             pop rcx
│           0x0046ce75      51             push rcx
│           0x0046ce76      4801c2         add rdx, rax
│           0x0046ce79      4829c8         sub rax, rcx
│           0x0046ce7c      4989c4         mov r12, rax
│           0x0046ce7f      4801e8         add rax, rbp
│           0x0046ce82      50             push rax
│           0x0046ce83      482500f0ffff   and rax, 0xfffffffffffff000
│           0x0046ce89      50             push rax
│           0x0046ce8a      4829c2         sub rdx, rax
│           0x0046ce8d      52             push rdx
│           0x0046ce8e      4889de         mov rsi, rbx
│           0x0046ce91      ad             lodsd eax, dword [rsi]
│           0x0046ce92      50             push rax
│           0x0046ce93      4889e1         mov rcx, rsp
│           0x0046ce96      4a8d1423       lea rdx, [rbx + r12]
│           0x0046ce9a      4989d5         mov r13, rdx
│           0x0046ce9d      ad             lodsd eax, dword [rsi]
│           0x0046ce9e      50             push rax
│           0x0046ce9f      ad             lodsd eax, dword [rsi]
│           0x0046cea0      4190           xchg eax, r8d
│           0x0046cea2      4889f7         mov rdi, rsi
│           0x0046cea5      5e             pop rsi
│           0x0046cea6      ffd5           call rbp
│           0x0046cea8      59             pop rcx
│           0x0046cea9      5e             pop rsi
│           0x0046ceaa      5f             pop rdi
│           0x0046ceab      5d             pop rbp
│           0x0046ceac      6a05           push 5                      ; 5
│           0x0046ceae      5a             pop rdx
│           0x0046ceaf      6a0a           push 0xa                    ; 10
│           0x0046ceb1      58             pop rax
│           0x0046ceb2      0f05           syscall
└           0x0046ceb4      41ffe5         jmp r13
```
When debugging the calls in visual mode (F7), we can see alignment calculations to recover the size of the binary to be mapped and of the "anonymous" area to be created. Then, we see two mmap syscalls. The first is used to make an "anonymous" mapping which will contain the decompression and mapping code, then another one to load the binary. We then have a "call rbp" (which calls the decompression function located at 0x0046cbef, before doing an mprotect on the allocated page and jumping on it.

Once the jump is made, we land here: 
```
            0x7fb3749e3ed0      e84a000000     call 0x7fb3749e3f1f
            0x7fb3749e3ed5      83f949         cmp ecx, 0x49           ; 73
        ┌─< 0x7fb3749e3ed8      7544           jne 0x7fb3749e3f1e
        │   0x7fb3749e3eda      53             push rbx
        │   0x7fb3749e3edb      57             push rdi
```
 Same stuff as earlier, we enter the call (F7 in visual mode), and we fall back on another function which performs other operations, followed by
```
            0x7fb3749e401e      41ff66f8       jmp qword [r14 - 8]
```
 
We can reasonably think that we are approaching our OEP, so we position a breakpoint (F2) and continue the execution (F9) before returning to single-step mode.

Then, we get this
```
            ;-- rip:
            0x0048c48e      0f05           syscall
            0x0048c490      5a             pop rdx
            0x0048c491      c3             ret
```

and once we reach `ret`, we finally get the OEP of the unpacked binary! We just have to dump the program, first by listing the sections with "dm": 

```
[0x0044fd80]> dm
0x0000000000400000 - 0x000000000048d000 * usr   564K s r-x unk0 unk0 ; map.home_supersnail_Documents_hack_lab_AeroCTF_goaway.r_x
0x000000000048d000 - 0x0000000000525000 - usr   608K s r-- unk1 unk1
0x0000000000525000 - 0x000000000055a000 - usr   212K s rw- unk2 unk2
```

We can therefore dump the unpacked binary with the `wtf goaway.unpack 0x15a000 @0x400000` command, the size of the binary being 0x55a000-0x400000.

Doing `strings` on the unpacked crackme, we can see that it was written in ... the Go language, the beginning of the nightmare. 
## Reversing Go for fun and chocapicz
Unfortunately for me, the crackme was written in Go: indeed, a fairly substantial runtime is found to be embedded in Go programs, making it difficult to identify the "useful" functions and the Go runtime ones. However, Go's RTTI mechanism still allows us to get out of it, since the name of the functions (and maybe the types of variables / arguments) is still preserved, which greatly facilitates our task.

My first attempt was to use r2-gohelper , however the script only renamed a few functions, making it completely useless. In addition, radare2 is still too limited for static analysis, so I took out my good old IDA Free to analyze the "main.main" function (one of the few functions identified by r2-gohelper).

After a failed attempt to understand all the code of the runtime, I ended up having the good idea to make a "string search" in IDA, which found a lot of function names. Not having IDAPython (because Free edition, thank you Ilfak \o/), I started doing manual resolution of RTTIs for each function called: 
![rtti.png](http://real-asm.infos.st/assets/uploads/files/1583067885984-rtti.png) 

 I finally got something like this after a while renaming everything: 

![idadmp1.png](http://real-asm.infos.st//assets/uploads/files/1583067680265-idadmp1.png) 

Another difficult point was to understand the calling convention used by Go.
Actually, unlike C where a single parameter is returned, Go can return several return values, which are copied onto the stack frame of the calling function. So the stack looks something like this:
```
+-------------------+
|    ebp backup     |
+-------------------+
|  return address    |
+-------------------+
|    argument 1     |
|        ...        |
|    argument n     |
|     retour 1      |
|        ...        |
|     retour n      |
+-------------------+
|    local vars     |
+-------------------+
```
Also comes the "slice" mechanism much used by Go, which is actually a structure that could be defined like this (in 64 bits): 
```C

struct slice {
   void *pointer;
   uint64_t size;
   uint64_t allocated_size;
}

```
 Once this is understood, we can finally study the operation of the program in good conditions. 

## Crackme algorithm
The crackme starts by displaying the welcome message, then reading and storing user input (with bufio.Reader.ReadString).The crackme then removes the character "\n", before creating a HashMap.

This HashMap contains a permutation table, which will be useful later. Then, the crackme creates an array of slices which point to 16-byte "strings", which curiously look like a hash. Then, after checking the size of the flag (which must also be 16 bytes), we land to a first loop on the characters of the flag. For each character, we compute the MD5 hash of the character. 

![hashmd5.png](http://aassfxxx.infos.st/media/goaway/1583067885984-rtti.png) 

Then we recover the permutation value corresponding to the index of the character of the string in the hashmap, and compare the hash md5 to the slice whose index is the permutation:

![cmphash.png](http://aassfxxx.infos.st/media/goaway/1583067680265-idadmp1.png)

In "pythonized" pseudocode, we would get something like this: 
```py

slice = <md5 hashes array>
permutations = [0, 1, 2, 3, 1, 4, 5, 1, 6, 5, 1, 5, 7, 8, 7, 9]
for i in range(len(serial)):
   if md5(serial[i]) != slice[permutations[i]]:
     print "Bad boy"
     exit(1)

print "Good boy"

```
To recover the key, in theory, we just need to calculate the md5 for each character in the ASCII table, and compare its hash with the one found in the program. But like any theoretical solution, it does not work in practice for obscure reasons ...

## Key recovery and crackme pwning
Not understanding what is happening, I ended up opting for a more radical solution: I executed the MD5 implementation of the binary directly, controlling the radare2's debugger via r2pipe from my python script. After a few tries, I managed to make the following script:
```py

#!/usr/bin/python
import r2pipe
import hashlib
import binascii
import os

flag_md5_offsets = [0xb, 0x06, 0x0a, 0x0c, 0x7, 0x5, 0x9, 0x22, 0x8, 0x2]
hashes = []
alphabet_dict = {}

r2 = r2pipe.open("goaway.unpack")
r2.cmd("ood")
r2.cmd("db 0x48c10f")
r2.cmd("db 0x48b812")
r2.cmd("db 0x48c21e")
r2.cmd("db 0x48c223")
for i in range(0, 0x7f):
    r2.cmd("dc")
    r2.cmd("dr edx=%d" % i)
    r2.cmd("dr rip=0x%x" % 0x48c1ff)
    r2.cmd("dc")
    r2.cmd("s rsp+0x4f; wx 0x%x" % (i << 16 | 0x10))
    print(r2.cmd("dc"))
    md5 = binascii.hexlify(bytes(r2.cmdj("pxj 16 @rsp+0x18")))
    alphabet_dict[md5] = chr(i)
    r2.cmd("ood")

chars = []
for offset in flag_md5_offsets:
    addr = 0x4bf20c + (offset * 16)
    #print(hex(addr))
    nochr = binascii.hexlify(bytes(r2.cmdj("pxj 16 @0x%x" % addr)))
    hashes.append(nochr)
    chars.append(alphabet_dict[nochr])

subst = [0, 1, 2, 3, 1, 4, 5, 1, 6, 5, 1, 5, 7, 8, 7, 9]
toto = ""
for i in subst:
    toto += chars[i]

print(toto)

```
The script directly gives us the right flag, "secretkeykeklol1". However, the program is picky, and when you give it the right flag, you get 
```
hmmmm...... key is correct! But I changed my mind about printing you a flag
.....
Instead, I will display you a flag for the key 'testtesttesttest'
flag: <non-printable chars>
```

The validation flag is therefore encrypted, and according to our renaming work, is encrypted in AES. The key "testtesttesttest", encoded in hexadecimal form, is passed to the `main.ExampleNewCBCDecrypter` function (which does AES CBC as its name suggests, thank you Captain Obvious). As we are in a CTF, we will replace the barely decoded key with our flag, then continue the execution via:

```
$ r2 -d ./goaway.unpack
 -- Everybody hates warnings. Mr. Pancake, tear down this -Wall
[0x0044fd80]> db 0x48b642
[0x0044fd80]> dc
Go away I will not give you a flag!
But if you guess the key I'll print you a flag....
guess: secretkeykeklol1
hmmmm...... key is correct! But I changed my mind about printing you a flag
.....
Instead, I will display you a flag for the key 'testtesttesttest'
flag: hit breakpoint at: 48b642
[0x0048b642]> w secretkeykeklol1 @rax
[0x0048b642]> dc
Aero{3475964bdbfe31fbb40d812fa2f88114765baf72fd7ef0a912c746312bbdc07b}
[0x0044fd9b]> 
```
 We recovered our validation flag (and I was the one to first blood this challenge, w00t !)
 
 aaSSfxxx
