import sys

from feistel_cipher.utils.GenFunc import gen_func
from feistel_cipher.utils.SecretKeyGen import SecretKeyGen
from feistel_cipher.utils.TargetFunc import target_func

BLOCK_LEN = 64
BITS_IN_BYTE = 8
KEY_LEN = 64
ROUND_COUNT = 12


class FeistelCipher:
    def __init__(self, secret_key_gen, key_gen_func, target_gen_func, block_len=BLOCK_LEN, round_count=ROUND_COUNT):
        self.key = secret_key_gen()
        self.key_gen_func = key_gen_func
        self.target_gen_func = target_gen_func
        if not self.power_2_check(block_len):
            raise Exception("Block size must be a power of 2")
        self.bloc_len = block_len
        self.bytes_block_len = block_len // BITS_IN_BYTE
        if round_count < 2 or round_count > 12:
            raise Exception("Round count must be in the range from 2 to 12")
        self.round_count = round_count

    @staticmethod
    def power_2_check(n):
        return (n & (n - 1) == 0) and n != 0

    @staticmethod
    def to_binary_string(payload: str):
        byte_data = payload.encode('utf-8')
        binary_string = ''.join(format(byte, '08b') for byte in byte_data)
        return binary_string

    @staticmethod
    def from_binary_string(payload):
        payload_bytes = [int(payload[i:i + 8], 2) for i in range(0, len(payload), 8)]
        return bytes(payload_bytes).decode('utf-8')

    def split_to_blocks(self, string):
        blocks = [string[i:i + self.bytes_block_len] for i in range(0, len(string), self.bytes_block_len)]
        while len(blocks[-1]) != self.bytes_block_len:
            blocks[-1] += " "
        return blocks

    def encrypt(self, message: str, iv: int):
        blocks = self.split_to_blocks(message)
        res = []
        previous_block = self.bintostr(self.itobinex(iv))
        for block in blocks:
            block = self.xor(block, previous_block)
            left_init = block[:self.bytes_block_len // 2]
            right_init = block[self.bytes_block_len // 2:]
            for iteration in range(self.round_count):
                curr_key = self.key_gen_func(self.key, iteration)
                left = left_init
                right = right_init
                left_int = self.bintoint(self.stobin(left))
                right_int = self.bintoint(self.stobin(right))
                left_part_enc = self.target_gen_func(left_int, curr_key, self.bloc_len // 2)
                xored = left_part_enc ^ right_int
                left_init = self.bintostr(self.itobin(xored))
                right_init = left

            ciphertext_block = left_init + right_init
            res.append(ciphertext_block)
            previous_block = ciphertext_block
        return "".join(res)

    # xor two strings
    @staticmethod
    def xor(s1, s2):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

    # string to binary
    @staticmethod
    def stobin(s):
        # print(''.join('{:08b}'.format(ord(c)) for c in s))
        return ''.join('{:08b}'.format(ord(c)) for c in s)

    # binary to int
    @staticmethod
    def bintoint(s):
        return int(s, 2)

    # int to binary
    # @staticmethod
    def itobin(self, i):
        # print(bin(i))
        return bin(i)[2:].zfill(self.bloc_len // 2)

    def itobinex(self, i):
        # print(bin(i))
        return bin(i)[2:].zfill(self.bloc_len)

    # binary to string
    @staticmethod
    def bintostr(b):
        return ''.join(chr(int(b[i: i + 8], 2)) for i in range(0, len(b), 8))

    def decrypt(self, bits, iv):
        binary_blocks = self.split_to_blocks(bits)

        res = []

        previous_block = self.bintostr(self.itobinex(iv))
        for block in binary_blocks:
            right_init = block[:self.bytes_block_len // 2]
            left_init = block[self.bytes_block_len // 2:]
            for iteration in range(self.round_count-1, -1, -1):
                curr_key = self.key_gen_func(self.key, iteration)
                left = left_init
                right = right_init
                left_int = self.bintoint(self.stobin(left))
                right_int = self.bintoint(self.stobin(right))
                left_part_enc = self.target_gen_func(left_int, curr_key, self.bloc_len // 2)
                xored = left_part_enc ^ right_int
                left_init = self.bintostr(self.itobin(xored))
                right_init = left

            decrypted_block = self.xor(right_init + left_init, previous_block)
            res.append(decrypted_block)

            previous_block = block

        return "".join(res)


if __name__ == '__main__':
    key_generator = SecretKeyGen(KEY_LEN)
    fc = FeistelCipher(key_generator, gen_func, target_func)
    key_generator.reset()
    iv_key = key_generator()
    enc = fc.encrypt("hello world", iv_key)
    dec = fc.decrypt(enc, iv_key)
    print(enc)
    print(dec)
