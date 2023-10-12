class Feistel:
    def __init__(self, roundf, rounds, bsize, key, derivf):
        assert bsize > 0
        assert bsize % 2 == 0
        assert len(key) == bsize // 2
        assert rounds > 0

        self.block_size = bsize
        self.roundfunc  = roundf
        self.derivekey  = derivf
        self.rounds     = rounds
        self.key        = key

    def pad(self, msg: bytes) -> bytes:
        """
        Pad the plaintext using the following technique: append the required 
        number of 0's to the end, and write this number in the last byte. 
        """
        from math import ceil

        blocks_to_contain_msg = ceil((len(msg)+1) / self.block_size)
        to_append = (blocks_to_contain_msg * self.block_size) - len(msg)
        last_block = bytes([to_append])

        for _ in range(to_append-1): msg += bytes([0x0])
        return msg + last_block

    def remove_padding(self, msg: bytes) -> bytes:
        """
        Remove the padding added using `pad` from the plaintext.
        """
        appended_bytes = msg[len(msg)-1]
        return msg[:len(msg) - appended_bytes]

    def splitmsg(self, msg : bytes) -> list[bytes]:
        """
        Divide the message into blocks of size `block_size`.
        """
        assert len(msg) % self.block_size == 0

        blocks, index = [], 0

        for _ in range(len(msg)):
            block = []
            for _ in range(self.block_size):
                if index >= len(msg): return blocks
                block.append(msg[index])
                index += 1
            blocks.append(block)

        return blocks

    def splitblock(self, block : bytes) -> (bytes, bytes):
        """
        Split the block in half.
        """
        assert len(block) == self.block_size

        half = self.block_size // 2
        return block[:half], block[half:] # (L, R)
    
    def XOR(self, a : bytes, b : bytes) -> bytes:
        """
        From two list of bytes A and B where |A| = |B|, 
        returns [A[i] ^ B[i] | 0 <= i < len(A)].
        """
        assert len(a) == len(b)

        return [x ^ y for (x, y) in zip(a, b)]

    def encode_block(self, block : bytes) -> bytes:
        """
        Encode a block of size `block_size` using the Feistel cipher model:
        `L_i+1 = R_i` and `R_i+1 = L_i ^ f(R_i ^ K_i)` where `L`, `R` are the 
        left and right halves of the block, `^` is the XOR operation, `f` is
        the round function and `K_i` is the corresponding round key.
        """
        assert len(block) == self.block_size

        (left, right) = self.splitblock(block)
        keys = self.derivekey(self.key, self.rounds)

        for r in range(self.rounds):
            left, prevleft, prevright = right, left, right
            right = self.XOR(prevleft, (self.roundfunc(self.XOR(prevright, keys[r]))))

        return (left + right)

    def decode_block(self, block : bytes) -> bytes:
        """
        Decode a block encoded using the `encode_block` method.
        """
        assert len(block) == self.block_size

        left, right = self.splitblock(block)
        keys = self.derivekey(self.key, self.rounds)

        for r in range(self.rounds):
            right, prevright, prevleft = left, right, left
            # L_i = R_i+1 ^ f(L_i+1 ^ K_i)
            left = self.XOR(prevright, (self.roundfunc(self.XOR(prevleft, keys[r]))))

        return (left + right)

from typing import Callable

def main():
    """
    Driver test code
    """
    def make_round_function(pbox, sbox) -> Callable[[bytes], bytes]:
        permute = lambda pbox, block: bytes([block[i] for i in pbox])

        def round_function(block : bytes) -> bytes:
            assert len(pbox) == len(block)
            permuted = permute(pbox, block)
            return permuted

        return round_function

    derivf = lambda key, rounds: [key for _ in range(rounds)]

    def decode(cipher, encoded, res=[]):
        for block in encoded: res += cipher.decode_block(block)
        return res

    msg       = bytes("Hello, World!", "ascii")
    blocksize = 8
    key       = bytes([i for i in range(blocksize//2)])

    cipher = Feistel(
        roundf = make_round_function([0, 1, 3, 2], []), 
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

if __name__ == '__main__': main()

