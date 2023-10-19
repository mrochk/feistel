from typing import Callable

class Feistel:
    def __init__(self, roundf, rounds, bsize, key, derivf):
        assert bsize     >  0
        assert bsize % 2 == 0
        assert len(key)  == bsize // 2
        assert rounds    >  0

        self.derivekey  : Callable[[bytes], list[bytes]] = derivf
        self.roundfunc  : Callable[[bytes], bytes] = roundf
        self.block_size : int = bsize
        self.rounds     : int = rounds
        self.key        : bytes = key

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

        result, index = [], 0
        for _ in range(len(msg)):
            block = []
            for _ in range(self.block_size):
                if index >= len(msg): return result
                block.append(msg[index])
                index += 1
            result.append(block)

        return result

    def splitblock(self, block : bytes) -> (bytes, bytes):
        """
        Split the block in half.
        """
        assert len(block) == self.block_size
        half = self.block_size // 2
        return block[:half], block[half:]
    
    def XOR(self, a : bytes, b : bytes) -> bytes:
        """
        From two list of bytes A and B where |A| = |B|, 
        returns [A[i] ^ B[i] | 0 <= i < len(A)].
        """
        assert len(a) == len(b)
        return [x ^ y for (x, y) in zip(a, b)]

    def encode_block(self, block : bytes) -> bytes:
        """
        Encode a block of size `block_size` the following way: `L_i+1 = R_i` 
        and `R_i+1 = L_i XOR F(R_i XOR K_i)` where `L`, `R` are the left and 
        right halves of the block, `F` is the round function and `K_i` 
        is the corresponding round key.
        """
        assert len(block) == self.block_size

        left, right = self.splitblock(block)
        keys = self.derivekey(self.key, self.rounds)

        for r in range(self.rounds):
            left, prevleft, prevright = right, left, right
            rounfdf_inp = self.XOR(prevright, keys[r])
            right = self.XOR(prevleft, (self.roundfunc(rounfdf_inp)))

        return left + right

    def decode_block(self, block : bytes) -> bytes:
        """
        Decode a block encoded using the `encode_block` method.
        """
        assert len(block) == self.block_size

        left, right = self.splitblock(block)
        keys = self.derivekey(self.key, self.rounds)

        for r in range(self.rounds):
            right, prevright, prevleft = left, right, left
            rf_input = self.XOR(prevleft, keys[len(keys)-r-1])
            left = self.XOR(prevright, self.roundfunc(rf_input))

        return left + right