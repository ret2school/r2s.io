+++
title: "[JustCTF - Crypto] Vaulted"
tags = ["ctf", "ret2school", "JustCTF", "2023", "alol", "crypto", "ecc"]
date = "2023-06-02"
+++

# Vaulted

> This secure multisignature application will keep our flag safe. Mind holding on to one of the backup keys?
>
> `nc vaulted.nc.jctf.pro 1337`
>
> Author: Tjaden Hess from Trail of Bits

Vaulted was an easy crypto challenge from JustCTF 2023. To be fair it wasn't really a crypto challenge, you'd instantly know how to solve the challenge if you had a bit of crypto knowledge (especially on elliptic curves and how points can be represented) but if you didn't a bit of source code reading would make the solution obvious.

## TL;DR

- Generate a pub/priv key pair
- Enrol your public key
- Get the flag by sending your pubkey in three different formats (compressed, uncompressed and hybrid) along with three identical signatures of `b'get_flag'`

## Source code analysis

We're given the following source code and a `tar` archive containing the necessary files to run a local instance of the challenge.

```py
from coincurve import PublicKey
import json

FLAG = 'justWTF{th15M1ghtB34(0Rr3CtFl4G!Right????!?!?!??!!1!??1?}'
PUBKEYS = ['025056d8e3ae5269577328cb2210bdaa1cf3f076222fcf7222b5578af846685103', 
           '0266aa51a20e5619620d344f3c65b0150a66670b67c10dac5d619f7c713c13d98f', 
           '0267ccabf3ae6ce4ac1107709f3e8daffb3be71f3e34b8879f08cb63dff32c4fdc']


class FlagVault:
    def __init__(self, flag):
        self.flag = flag
        self.pubkeys = []

    def get_keys(self, _data):
        return str([pk.format().hex() for pk in self.pubkeys])

    def enroll(self, data):
        if len(self.pubkeys) > 3:
            raise Exception("Vault public keys are full")

        pk = PublicKey(bytes.fromhex(data['pubkey']))
        self.pubkeys.append(pk)
        return f"Success. There are {len(self.pubkeys)} enrolled"

    def get_flag(self, data):
        # Deduplicate pubkeys
        auths = {bytes.fromhex(pk): bytes.fromhex(s) for (pk, s) in zip(data['pubkeys'], data['signatures'])}

        if len(auths) < 3:
            raise Exception("Too few signatures")

        if not all(PublicKey(pk) in self.pubkeys for pk in auths):
            raise Exception("Public key is not authorized")

        if not all(PublicKey(pk).verify(s, b'get_flag') for pk, s in auths.items()):
            raise Exception("Signature is invalid")

        return self.flag


def write(data):
    print(json.dumps(data))


def read():
    try:
        return json.loads(input())
    except EOFError:
        exit(0)


WELCOME = """
Welcome to the vault! Thank you for agreeing to hold on to one of our backup keys.

The vault requires 3 of 4 keys to open. Please enroll your public key.
"""

if __name__ == "__main__":
    vault = FlagVault(FLAG)
    for pubkey in PUBKEYS:
        vault.enroll({'pubkey': pubkey})

    write({'message': WELCOME})
    while True:
        try:
            data = read()
            if data['method'] == 'get_keys': 
                write({'message': vault.get_keys(data)})
            elif data['method'] == 'enroll':
                write({'message': vault.enroll(data)})
            elif data['method'] == "get_flag":
                write({'message': vault.get_flag(data)})
            else:
                write({'error': 'invalid method'})
        except Exception as e:
            write({'error': repr(e)})
```

We can either get the vault keys, enrol a new key (the check on the number of keys is done *before* enrolling a new key so the vault can contain 4 keys) or get the flag.

Let's look closer at the `get_flag` function. 

```py
def get_flag(self, data):
    # The pubkeys are supplied by the user, even though they are defined in the program, how strange ...
    auths = {bytes.fromhex(pk): bytes.fromhex(s) for (pk, s) in zip(data['pubkeys'], data['signatures'])}

    # That's what the welcome message meant by "requires 3 of 4 keys to open",
    # we need to send at least 3 signatures (from, supposedly, 3 different pubkeys,
    # one of which can be ours)
    if len(auths) < 3:
        raise Exception("Too few signatures")

    # Create a PublicKey object for each user-supplied public key and checks if
    # it's in the vault. This inclusion check should fail as the new keys are
    # objects and have different memory addresses than the existing keys.
    # However, this isn't the case as the `__eq__` method has been overwritten
    # in the PublicKey class' definition. 

    # ```py
    #  def __eq__(self, other) -> bool:
	#      return self.format(compressed=False) == other.format(compressed=False)
	# ```
    if not all(PublicKey(pk) in self.pubkeys for pk in auths):
        raise Exception("Public key is not authorized")

    # Finally, verify all the signatures 
    if not all(PublicKey(pk).verify(s, b'get_flag') for pk, s in auths.items()):
        raise Exception("Signature is invalid")

    return self.flag
```

Even though the function blindly trusts the user-supplied public keys, it wouldn't be vulnerable if these public keys were all unique (ie. if one public key couldn't have multiple different representations). Thankfully, that's not the case.

## Representations of points on an elliptic curve

The `coincurve` library used in this challenge provides Python bindings around `libsecp256k1` (the library used by Bitcoin Core). Thus, the public (and private) keys used in the script are points on an elliptic curve. Points on an elliptic curve can be represented in two different forms: an uncompressed form and a compressed form. The uncompressed form is simply `(x, y)` (the coordinates of the point) whilst the compressed form is `(x, lsb)` (the `x` coordinate and the least significant bit of the `y` coordinate, ie. if `y` is even or odd). Prof. Buchana has a clear explanation of why:

> "As we can easily determine the y axis-value if we know the x-axis value, there is no need to store the y-axis value. But in this elliptic curve, there are two points which are always possible for every x coordinate value, so all we need to do, is to point to the correct one. For this one of these points is an even value and the other has an odd value."
>
> [ASecuritySite - 02, 03 or 04? So What Are Compressed and Uncompressed Public Keys?](https://scribe.rip/asecuritysite-when-bob-met-alice/02-03-or-04-so-what-are-compressed-and-uncompressed-public-keys-6abcb57efeb6)

`coincurve` uses the DER encoding for the representation of the keys, so the uncompressed format is `0x04 || x || y` whilst the compressed format is `(0x02|0x03) || x` (`0x02` if `y` is even, `0x03` if it's odd).

We now know that we can supply the same public key twice (formatted differently), that's 2/3 public keys taken care of but what about the last one?

From looking at the `PublicKey` class' definition in the [source code](https://github.com/ofek/coincurve/blob/master/coincurve/keys.py#L298), we find another supported format.

```
:param data: The formatted public key. This class supports parsing
             compressed   (33 bytes, header byte `0x02` or `0x03`),
             uncompressed (65 bytes, header byte `0x04`), or
             hybrid       (65 bytes, header byte `0x06` or `0x07`) format public keys.
```

The "`hybrid`" format seems to be a mix between the compressed/uncompressed formats: `(0x06|0x07) || x || y` (`0x06` if `y` is even, `0x07` if it's odd).

We can now supply three differently formatted public keys along with three times the same signature to the `get_flag` function.

# Conclusion

The script below implements this, all that's left now is to send its output to the challenge server to get the flag.
```py
from coincurve import PrivateKey
import json

sk = PrivateKey()
pk = priv.public_key

signatures = [sk.sign(b'get_flag').hex()] * 3
pubkeys = [
         pk.format(compressed=True).hex(),     # compressed
         pk.format(compressed=False).hex(),    # uncompressed
  '07' + pk.format(compressed=False).hex()[2:] # hybrid
]

print(json.dumps({
	"method": "enroll",
	"pubkey": pubkeys[0]
}))

print(json.dumps({
	"method": "get_flag",
	"pubkeys": pubkeys,
	"signatures": signatures
}))

# {"message": "justCTF{n0nc4n0n1c4l_72037872768289199286663281818929329}"}
```