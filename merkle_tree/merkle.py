from abc import ABC, abstractmethod
import hashlib
import numbers


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

    def hash(self, string: bytes) -> bytes:
        return hashlib.sha256(string).digest()


"""
Compute the merkle root of a list of leaves. Returning a list of bytes representing the merkle tree.
"""


def merkle_root(leaves: list[bytes], hasher: Hasher = Sha256()) -> list[bytes]:
    if len(leaves) % 2 == 1:
        raise Exception("leaves must be of even length")

    tree = [b""] * (len(leaves) - 1) + leaves
    for i in range(len(leaves) - 1, -1, -1):
        tree[i - 1] = hasher.hash(tree[i * 2 - 1] + tree[i * 2])
    return tree


def bytesToHex(byte):
    if isinstance(byte, numbers.Number):
        return hex(byte)
    else:
        return hex(
            int.from_bytes(
                byte,
            )
        )


leaves = [i.to_bytes(32) for i in range(4)]
tree = merkle_root(leaves)

print(list(map(bytesToHex, tree)))
