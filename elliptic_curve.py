import random
import hashlib

from utils import modinv


class EC:
    def __init__(self, p: int, a: int, b: int, n: int, h: int, base_point: tuple[int, int]):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.h = h
        self.base_point = base_point

    def point_add(self, p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
        x1,  y1 = p
        x2,  y2 = q

        if x1 == x2:
            g = ((3 * x1 ** 2 + self.a) * modinv((2 * y1), self.p))
        else:
            g = ((y2 - y1) * modinv(x2 - x1, self.p))

        x3 = (g ** 2 - x1 - x2) % self.p
        y3 = ((g * (x1 - x3)) - y1) % self.p

        return (x3, y3)

    def scalar_multiply(self, point: tuple[int, int], scalar: int):
        if scalar == 0 or scalar >= self.n:
            raise Exception("scalar bigger than the order n")

        scalar_bin = str(bin(scalar))[2:]
        q = point

        for i in range(1, len(scalar_bin)):
            q = self.point_add(q, q)
            if scalar_bin[i] == "1":
                q = self.point_add(q, point)
        return q

    def get_curve_params(curve: str):
        if curve == "secp256k1":
            return dict(
                p=2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1,
                a=0,
                b=7,
                n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
                h=1,
                base_point=(
                    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
                )
            )
        elif curve == "secp192k1":
            return dict(
                p=2**192 - 2**32 - 2**12 - 2**8 - 2**7 - 2**6 - 2**3 - 1,
                a=0,
                b=3,
                n=0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D,
                h=1,
                base_point=(
                    0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D,
                    0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D
                )
            )
        elif curve == "secp224k1":
            return dict(
                p=2**224 - 2**32 - 2**12 - 2**11 - 2**9 - 2**7 - 2**4 - 2 - 1,
                a=0,
                b=5,
                n=0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7,
                h=1,
                base_point=(
                    0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C,
                    0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5
                )
            )
        else:
            raise Exception(f"curve {curve} is not supported")


class ECDSA(EC):
    def __init__(self, curve: str):
        curve = EC.get_curve_params(curve)
        EC.__init__(self, p=curve["p"], a=curve["a"], b=curve["b"],
                    n=curve["n"], h=curve["h"], base_point=curve["base_point"])

    def create_random_keypair(self):
        private_key = random.randrange(1, self.n)
        public_key = self.scalar_multiply(self.base_point, private_key)
        return (private_key, public_key)

    def sign_message(self, signing_key: int, message_hash: bytes) -> tuple[int, int]:
        n_bit_len = str(bin(self.n))[2:].__len__()
        bit_len = message_hash.__len__()

        if bit_len > self.n:
            message_hash = message_hash[bit_len - n_bit_len:]

        z = int.from_bytes(message_hash)

        r = 0
        s = 0

        # the use of a random seed means the resulting signature is nondeterministic
        while r == 0 or s == 0:
            seed = random.randrange(1, self.n)
            p = self.scalar_multiply(self.base_point, seed)
            r = p[0] % self.n
            s = (z + r * signing_key) * modinv(seed, self.n)

        return (r, s)

    def verify_signature(self, signature: tuple[int, int], message_hash: bytes, verifying_key: int) -> bool:
        z = int.from_bytes(message_hash)
        u1 = (z * modinv(signature[1], self.n)) % self.n
        u2 = (signature[0] * modinv(signature[1], self.n)) % self.n

        p = self.point_add(self.scalar_multiply(self.base_point, u1),
                           self.scalar_multiply(verifying_key, u2))

        if signature[0] == (p[0] % self.n):
            return True
        else:
            return False


hash = hashlib.sha256(b"this is a message").digest()

ecdsa = ECDSA("secp256k1")
alice = ecdsa.create_random_keypair()

sign = ecdsa.sign_message(alice[0], hash)

print(f"Alice's signature : {sign}")
print(f"{ecdsa.verify_signature(sign, hash, alice[1])}")
