from abc import ABC, abstractmethod
from hashlib import sha256


class Hasher(ABC):
    """
    An abstract class for being generic over hash function implementations used in the merkle tree.
    """

    @abstractmethod
    def hash(self, string) -> bytes:
        pass


class Sha256(Hasher):
    def __init__(self) -> None:
        self

    def hash(self, string: bytes = b"") -> bytes:
        return sha256(string).digest()


class MerkleTree:
    """
    A merkle tree with a generic hasher.
    """

    def __init__(self, hasher: Hasher = Sha256) -> None:
        self.hasher = hasher

    def build(self, leaves: list[bytes]) -> list[bytes]:
        if len(leaves) % 2 == 1:
            raise Exception("leaves must be of even length")

        tree = [0] * len(leaves) + leaves
        for i in range(len(leaves) - 1, 0, -1):
            tree[i] = self.hasher.hash(tree[i * 2] + tree[i * 2 + 1])
        return tree


leaves = [i.to_bytes(32) for i in range(4)]
tree = MerkleTree().build(leaves)


print(hex(int.from_bytes(tree[1])))
