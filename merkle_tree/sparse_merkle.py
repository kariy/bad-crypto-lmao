from merkle import Sha256, Hasher

type Entry = tuple[bytes, bytes]


class Node:
    def __init__(self) -> None:
        self.left = None
        self.right = None

        self.hash = None
        self.value = None

    def is_internal(self) -> bool:
        return self.left is not None or self.right is not None

    def __str__(self) -> str:
        return f"Node(key={self.value[0]}, value={self.value[1]}, hash={self.hash})"


class SparseMerkle:
    def __init__(self, hasher: Hasher = Sha256) -> None:
        self.root = None
        self.hasher = hasher

    def insert(self, entry: Entry) -> None:
        if self.root is None:
            self.root = Node()
            self.root.value = entry
            self.root.hash = self.hasher.hash(entry[0] + entry[1])
        else:
            path = self.hasher.hash(entry[0] + entry[1])
            b = path & 0x01

            parent_node = self.root
            current_node = None
            while current_node.is_internal():
                if b == 0:
                    current_node = parent_node.left
                else:
                    current_node = parent_node.right

                if current_node is None:
                    current_node = Node()
                    current_node.value = entry
                    current_node.hash = path

                    if b == 0:
                        parent_node.left = current_node
                    else:
                        parent_node.right = current_node
                    break
