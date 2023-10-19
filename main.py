from feistel import Feistel

"""
The signature of the function used to derive the key must be
(bytes, int) -> list[bytes], the size of the key must be
half the block size, and the length of the resulting array 
of round keys must be the same as the number of rounds.
"""
def make_key_derivation_function(randbytes : bytes) -> list[bytes]:
    assert rounds > 0
    assert key and len(key) > 0 and len(key) % 2 == 0
    def f(key : bytes, rounds : int):
        result = []
        for r in range(rounds):
            b = []
            for i in range(len(key)):
                b += ([((key[i] + randbytes[i] + r) % 256)])
            result.append(bytes(b))
        return result
    return f

"""
The cipher round function, here is a very simple one where we
just permute the bytes, but we can make it as complicated as needed. 
The signature of the round function should be (bytes) -> bytes, 
and we make it using currying as done below.
"""
def make_round_function(pbox):
    return (lambda inp: bytes([inp[i] for i in pbox]))

def decode(cipher, encoded):
    result = []
    for block in encoded: result += cipher.decode_block(block)
    return result

from random import randint

if __name__ == '__main__':
    msg = bytes("Hello, World!", "ascii")
    key = bytes([0x99, 0x98, 0x97, 0x96])
    rounds = 16
    randints = [randint(0, 255) for _ in range(len(key))]
    blocksize = 8
    pbox      = [blocksize // 2 - i for i in range(1, blocksize // 2 + 1)]

    cipher = Feistel(
        roundf = make_round_function(pbox), 
        rounds = rounds, 
        bsize  = blocksize, 
        key    = key, 
        derivf = make_key_derivation_function(bytes(randints))
    )

    padded     = cipher.pad(msg)
    blocks     = cipher.splitmsg(padded)
    encoded    = [cipher.encode_block(block) for block in blocks]
    decoded    = decode(cipher, encoded)
    depadded   = cipher.remove_padding(decoded)
    decodedmsg = bytes(depadded)

    print(f"Original msg: {msg}")
    print(f"Master key  : {key}")
    print(f"Integers used to derive the master key: {randints}")
    print(f"Derived Round keys  : {make_key_derivation_function(randints)(key, rounds)[:3]}, ...")
    print(f"Padded msg  : {padded}")
    print(f"Splitted msg: {blocks}")
    print(f"Encoded msg : {encoded}")
    print(f"Decoded msg : {decoded}")
    print(f"De-padded   : {depadded}")
    print(f"Decoded msg : {str(decodedmsg, 'ascii')}")