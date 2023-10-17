from feistel import Feistel

if __name__ == '__main__':
    """
    TODO: 
    - Provide example for generating the round function.  
    - Implement block cipher modes.  
    """

    """
    derivf = lambda key, rounds: [key for _ in range(rounds)]

    def decode(cipher, encoded, res=[]):
        for block in encoded: res += cipher.decode_block(block)
        return res

    blocksize = 4
    msg       = bytes("Hello, World!", "ascii")
    key       = bytes([i for i in range(blocksize//2)])

    cipher = Feistel(
        roundf = make_round_function(pbox, []), 
        rounds = 16, 
        bsize  = blocksize, 
        key    = key, 
        derivf = derivf
    )

    padded     = cipher.pad(msg)
    blocks     = cipher.splitmsg(padded)
    encoded    = [cipher.encode_block(block) for block in blocks]
    decoded    = decode(cipher, encoded)
    depadded   = cipher.remove_padding(decoded)
    decodedmsg = bytes(depadded)

    print(f"Original msg: {msg}")
    print(f"Padded      : {padded}")
    print(f"Splitted    : {blocks}")
    print(f"Encoded     : {encoded}")
    print(f"Decoded     : {decoded}")
    print(f"De-padded   : {depadded}")
    print(f"Decoded msg : {str(decodedmsg, 'utf-8')}")
    """