class Feistel:
    def __init__(self, roundf, rounds, bsize, key, derivf):
        assert bsize    > 0
        assert len(key) == bsize // 2
        assert rounds   > 0

        self.round_func      = roundf
        self.derive_key      = derivf
        self.rounds          = rounds
        self.block_size      = bsize
        self.key             = key

    def pad_msg(self, msg: bytes) -> bytes:
        """
        Pad the plaintext using the following technique: append the required 
        number of 0's to the end, and write this number in the last byte. 
        """
        bytes_to_append = self.block_size - ((len(msg) + 1) % self.block_size)
        last_block = bytes([bytes_to_append + 1])

        for _ in range(bytes_to_append): msg += bytes([0x0])

        return msg + last_block

    def rm_padding(self, msg: bytes) -> bytes:
        """
        Remove the padding from the plaintext.
        """
        bytes_appended = msg[len(msg)-1]

        return msg[:len(msg) - bytes_appended]

    def split_msg(self, msg) -> list[bytes]:
        """
        Divide the message into blocks of size block_size.
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

    def split_block(self, block : bytes) -> (bytes, bytes):
        """
        Split the block in half.
        """
        assert len(block) == self.block_size

        half = self.block_size // 2
        return block[:half], block[half:] # (L, R)
    
    def XOR(self, bytesA, bytesB):
        """
        From two list of bytes A and B where |A| = |B|, 
        returns [A[i] ^ B[i] | 0 <= i < len(A)].
        """
        assert len(bytesA) == len(bytesB)

        return [a ^ b for (a, b) in zip(bytesA, bytesB)]

    def encode_block(self, block : bytes) -> bytes:
        """
        Encode a block.
        """
        assert len(block) == self.block_size

        left, right = self.split_block(block)
        keys = self.derive_key(self.key, self.rounds)

        for r in range(self.rounds):
            # L_i+1 = R_i
            left, prevleft, prevright = right, left, right
            # R_i+1 = L_i ^ f(R_i ^ K_i)
            right = self.XOR(prevleft, (self.round_func(self.XOR(prevright, keys[r]))))

        return left + right

    def decode_block(self, block : bytes) -> bytes:
        """
        Decode a block.
        """
        assert len(block) == self.block_size

        left, right = self.split_block(block)
        keys = self.derive_key(self.key, self.rounds)

        for r in range(self.rounds):
            # R_i = L_i+1
            right, prevright, prevleft = left, right, left
            # L_i = R_i+1 ^ f(L_i+1 ^ K_i)
            left = self.XOR(prevright, (self.round_func(self.XOR(prevleft, keys[r]))))

        return left + right

def main():
    def make_round_func(permbox, substbox):
        def roundf(block : bytes):
            result = [byte for byte in block]
            return bytes(result)
        return roundf

    def derivf(key, rounds):
        keys = []
        for rounds in range(rounds): keys.append(key)
        return keys

    key = []
    bsize = 4
    for i in range(bsize//2):
        key.append(i)
    key = bytes(key)

    cipher = Feistel(make_round_func([], []), rounds=16, bsize=bsize, key=key, derivf=derivf)
    msg = bytes("hey", "ascii")
    padded = cipher.pad_msg(msg)
    print(f"Padded: {padded}")
    blocks = cipher.split_msg(padded)
    print(f"Block: {blocks}")

    encoded = []
    for block in blocks:
        encoded.append(cipher.encode_block(block))
    print(f"Encoded: {encoded}")

    decoded = []
    for block in encoded:
        decoded += (cipher.decode_block(block))
    print(f"Decoded: {decoded}")

    depadded = cipher.rm_padding(decoded)
    print(f"Depadded: {depadded}")
    print(f"Og msg: {bytes(depadded)}")

if __name__ == '__main__': main()

