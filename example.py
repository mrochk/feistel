from feistel import Feistel

if __name__ == '__main__':

    def make_key_derivation_func(random_bytes : bytes) -> list[bytes]:
        def func(key : bytes, rounds : int):
            keys = []
            for round_ in range(rounds):
                l = []
                for i in range(len(key)):
                    l += [((key[i] + random_bytes[i] + round_) % 256)]
                keys.append(bytes(l))
            return keys
        return func

    def make_round_function(pbox, sbox):
        def func(inp):
            split_8bits = lambda n: (n >> 4, n & int(b'00001111', base=2))
            permuted    = [inp[i] for i in pbox]
            substituted = []
            for p in permuted:
                a, b = split_8bits(p)
                substituted.append(sbox[a-1][b-1])
            return bytes(substituted)
        return func

    def decode(cipher, encoded):
        result = []
        for block in encoded: 
            result += cipher.decode_block(block)
        return result

    from random import randint 

    msg       = bytes('Hello, World!', 'ascii')
    key       = bytes([0x99, 0x98, 0x97, 0x96])
    rounds    = 16
    randints  = [randint(0, 255) for _ in range(len(key))]
    blocksize = 8

    pbox      = [blocksize // 2 - i for i in range(1, blocksize // 2 + 1)]
    sbox      = [[i for i in range(x+16, -1, -1)] for x in range(0, 58, 4)]

    cipher = Feistel(
        derivefunc = make_key_derivation_func(bytes(randints)),
        roundfunc  = make_round_function(pbox, sbox), 
        blocksize  = blocksize, 
        rounds     = rounds, 
        key        = key
    )

    padded     = cipher.pad(msg)
    blocks     = cipher.split_msg(padded)
    encoded    = [cipher.encode_block(block) for block in blocks]
    decoded    = decode(cipher, encoded)
    depadded   = cipher.remove_padding(decoded)
    decodedmsg = bytes(depadded)

    print(f'Original msg: {msg}')
    print(f'Master key  : {key}')
    print(f'Integers used to derive the master key: {randints}')
    print(f'Derived Round keys  : {make_key_derivation_func(randints)(key, rounds)[:3]}, ...')
    print(f'Padded msg  : {padded}')
    print(f'Splitted msg: {blocks}')
    print(f'Encoded msg : {encoded}')
    print(f'Decoded msg : {decoded}')
    print(f'De-padded   : {depadded}')
    print(f'Decoded msg : {str(decodedmsg, "ascii")}')