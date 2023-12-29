import hashlib


class Sha1:
    '''
        implemented based on this specification https://www.rfc-editor.org/rfc/pdfrfc/rfc3174.txt.pdf
    '''

    def __init__(self) -> None:
        self.data = bytes()
        self.h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]

    def _padding(self):
        '''
            The resultant message must be a multiple of 64 bytes (512 bits).
            The last 64 bits of the last 512-bit block are reserved for the length of the original message in bits.
        '''
        zeros = b"\x00" * (63 - (len(self.data) + 8) % 64)
        msg_len = len(self.data) * 8
        return self.data + b"\x80" + zeros + msg_len.to_bytes(8, "big")

    def _circular_shift(self, n: int, b: int):
        if b < 0 or b >= 32:
            raise Exception("shift value must be >= 0 and < 32")
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def _expand_block(self, block: list):
        '''
            expand 16 words block into a 80 words block
        '''
        words = block + [0] * 64  # 80 - 16 = 64
        for t in range(16, 80):
            words[t] = self._circular_shift(
                (words[t - 3] ^ words[t - 8] ^ words[t - 14] ^ words[t - 16]), 1)
        return words

    def _split_into_blocks(self, data: bytes):
        '''
            1 block == 16 words (64 bytes)
        '''
        blocks = list()
        for i in range(0, len(data), 64):
            blocks.append([])
            for j in range(i, i + 64, 4):
                blocks[i % 63].append(int.from_bytes(data[j:j + 4]))

        return blocks

    def update(self, data: bytes):
        self.data = self.data + data

    def finalize(self):
        padded_data = self._padding()
        blocks = self._split_into_blocks(padded_data)
        for block in blocks:
            expanded_block = self._expand_block(block)
            a, b, c, d, e = self.h
            for t in range(0, 80):
                if 0 <= t < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= t < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= t < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= t < 80:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                a, b, c, d, e = (
                    self._circular_shift(a, 5) + f + e + k +
                    expanded_block[t] & 0xFFFFFFFF,
                    a,
                    self._circular_shift(b, 30),
                    c,
                    d
                )

            self.h = [
                self.h[0] + a & 0xFFFFFFFF,
                self.h[1] + b & 0xFFFFFFFF,
                self.h[2] + c & 0xFFFFFFFF,
                self.h[3] + d & 0xFFFFFFFF,
                self.h[4] + e & 0xFFFFFFFF
            ]

        return "%08x%08x%08x%08x%08x" % tuple(self.h)


message = b"CHUNG HAs first ever Special Single Killing Me is an uptempo, pop number piece and rhythmical vocal that describes a painful heartbreak. The chorus highlights CHUNG HAs vocal colors and her writing abilities and she describes the repetition of everyday life and exhaustion. Like the bright light at the end of a tunnel, CHUNG HA refocuses her message of hope in her lyrics for people."

s = Sha1()
s.update(message)
digest = s.finalize()

b = hashlib.sha1(message).hexdigest()
print(digest == b)
