from typing import Callable

class Feistel:
    def __init__(self, roundfunc, rounds, blocksize, key, derivefunc):
        """
        Instantiates a cipher that uses the Feistel structure. 

        - `roundfunc`'s signature must be `(bytes) -> bytes`,
        it is the function that takes `R_i-1 XOR keys[i]` and
        is used to create `R_i` at round `i`.

        - The chosen block size must be even.

        - The key must be of type `bytes`.

        - `derivefunc`'s signature must be `(bytes) -> bytes`,
        it is a function that creates a list of `rounds` random keys
        where `keys[i]` will be used at round `i`. The size of the keys
        must be half the block size so they can be XORed with the 
        corresponding half of the block.
        """
        assert blocksize > 0 and blocksize % 2 == 0 and rounds > 0

        self.derivefunc : Callable[[bytes], list[bytes]] = derivefunc
        self.roundfunc  : Callable[[bytes], bytes] = roundfunc
        self.block_size : int = blocksize
        self.rounds     : int = rounds
        self.key        : bytes = key

    def pad(self, msg: bytes) -> bytes:
        """
        Pad the plaintext using the following technique: append the required 
        number of 0's to the end, and write this number as the new last byte. 
        """
        from math import ceil

        blocks_to_contain_msg = ceil((len(msg) + 1) / self.block_size)
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

    def split_msg(self, msg : bytes) -> list[bytes]:
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

    def split_block(self, block : bytes) -> (bytes, bytes):
        """
        Split the block in half.
        """
        assert len(block) == self.block_size
        half = self.block_size // 2
        return block[:half], block[half:]
    
    def __xor(self, a : bytes, b : bytes) -> bytes:
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
        right halves of the block, `F` is the cipher round function and `K_i` 
        is the corresponding round key.
        """
        assert len(block) == self.block_size

        left, right = self.split_block(block)
        keys = self.derivefunc(self.key, self.rounds)

        assert len(keys[0]) == self.block_size // 2

        for r in range(self.rounds):
            left, prevleft, prevright = right, left, right
            roundfunc_input  = self.__xor(prevright, keys[r])
            roundfunc_result = self.roundfunc(roundfunc_input)
            right = self.__xor(prevleft, roundfunc_result)

        return left + right

    def decode_block(self, block : bytes) -> bytes:
        """
        Decode a block encoded using `encode_block`.
        """
        assert len(block) == self.block_size

        left, right = self.split_block(block)
        keys = self.derivefunc(self.key, self.rounds)

        assert len(keys[0]) == self.block_size // 2

        for r in range(self.rounds-1, -1, -1):
            right, prevright, prevleft = left, right, left
            roundfunc_input  = self.__xor(prevleft, keys[r])
            roundfunc_result = self.roundfunc(roundfunc_input)
            left = self.__xor(prevright, roundfunc_result)

        return left + right