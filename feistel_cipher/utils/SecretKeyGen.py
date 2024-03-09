import random


class SecretKeyGen:
    def __init__(self, rand_bits):
        self.sequence = None
        self.rand_bits = rand_bits

    def generate_sequence(self):
        self.sequence = random.getrandbits(self.rand_bits)

    def get_sequence(self):
        if self.sequence is None:
            self.generate_sequence()
        return self.sequence

    def reset(self):
        self.sequence = None

    def __call__(self, *args, **kwargs):
        return self.get_sequence()
