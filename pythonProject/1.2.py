#SM4-GCM软件优化实现
import struct
from typing import List, Tuple


S_BOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]

def _L(b: int) -> int:
    return b ^ (b << 2 | b >> 30) ^ (b << 10 | b >> 22) ^ \
           (b << 18 | b >> 14) ^ (b << 24 | b >> 8) & 0xffffffff

T0 = [_L(S_BOX[i] << 24) & 0xffffffff for i in range(256)]
T1 = [_L(S_BOX[i] << 16) & 0xffffffff for i in range(256)]
T2 = [_L(S_BOX[i] << 8) & 0xffffffff for i in range(256)]
T3 = [_L(S_BOX[i] << 0) & 0xffffffff for i in range(256)]

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def key_expansion(key: List[int]) -> List[int]:
    K = [key[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        b = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]
        s = T0[(b >> 24) & 0xff] ^ \
            T1[(b >> 16) & 0xff] ^ \
            T2[(b >> 8) & 0xff] ^ \
            T3[b & 0xff]
        temp = K[i] ^ s
        rk.append(temp)
        K.append(temp)
    return rk

#SM4
def sm4_encrypt_block(plain: List[int], rk: List[int]) -> List[int]:
    x0, x1, x2, x3 = plain
    for i in range(0, 32, 4):
        t = T0[(x1 >> 24) & 0xff] ^ T1[(x1 >> 16) & 0xff] ^ T2[(x1 >> 8) & 0xff] ^ T3[x1 & 0xff] ^ rk[i]
        x0, x1, x2, x3 = x1 ^ t ^ x2 ^ x3 ^ rk[i], x0, x1, x2
        t = T0[(x1 >> 24) & 0xff] ^ T1[(x1 >> 16) & 0xff] ^ T2[(x1 >> 8) & 0xff] ^ T3[x1 & 0xff] ^ rk[i + 1]
        x0, x1, x2, x3 = x1 ^ t ^ x2 ^ x3 ^ rk[i + 1], x0, x1, x2
        t = T0[(x1 >> 24) & 0xff] ^ T1[(x1 >> 16) & 0xff] ^ T2[(x1 >> 8) & 0xff] ^ T3[x1 & 0xff] ^ rk[i + 2]
        x0, x1, x2, x3 = x1 ^ t ^ x2 ^ x3 ^ rk[i + 2], x0, x1, x2
        t = T0[(x1 >> 24) & 0xff] ^ T1[(x1 >> 16) & 0xff] ^ T2[(x1 >> 8) & 0xff] ^ T3[x1 & 0xff] ^ rk[i + 3]
        x0, x1, x2, x3 = x1 ^ t ^ x2 ^ x3 ^ rk[i + 3], x0, x1, x2
    return [x3, x2, x1, x0]

#GCM工具
def bytes_to_words(b: bytes) -> List[int]:
    return [int.from_bytes(b[i:i + 4], 'big') for i in range(0, len(b), 4)]

def words_to_bytes(w: List[int]) -> bytes:
    return b''.join(x.to_bytes(4, 'big') for x in w)

def _gf128_mul(X: int, Y: int) -> int:
    Z = 0
    for i in range(128):
        if (X >> (127 - i)) & 1:
            Z ^= Y
        carry = Y & 1
        Y >>= 1
        if carry:
            Y ^= 0xe1000000000000000000000000000000
    return Z

#预计算
H_TABLE = [[0] * 16 for _ in range(16)]
def _init_ghash_table(H: int):
    for i in range(16):
        v = 0
        for j in range(4):
            v ^= (H & 0xffff) << (4 * j)
            H = _gf128_mul(H, 2)
        H_TABLE[0][i] = v
    for t in range(1, 16):
        for i in range(16):
            H_TABLE[t][i] = _gf128_mul(H_TABLE[t - 1][i], 2)

def ghash(H: int, data: bytes) -> int:
    Y = 0
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i:i + 16].ljust(16, b'\x00'), 'big')
        Y ^= block
        for j in range(0, 128, 4):
            nibble = (Y >> (124 - j)) & 0xf
            Y ^= H_TABLE[j // 4][nibble] << (124 - j)
    return Y

class SM4_GCM:
    def __init__(self, key: List[int]):
        self.rk = key_expansion(key)
        H_block = sm4_encrypt_block([0, 0, 0, 0], self.rk)
        self.H = int.from_bytes(words_to_bytes(H_block), 'big')
        _init_ghash_table(self.H)

    def _gctr(self, icb: List[int], plain: bytes) -> bytes:
        out = bytearray()
        cb = icb.copy()
        for i in range(0, len(plain), 16):
            keystream = words_to_bytes(sm4_encrypt_block(cb, self.rk))
            out.extend(bytes(a ^ b for a, b in zip(plain[i:i + 16], keystream)))
            cb[3] = (cb[3] + 1) & 0xffffffff
            if cb[3] == 0:
                cb[2] = (cb[2] + 1) & 0xffffffff
        return bytes(out)

    def encrypt(self, iv: bytes, plain: bytes, aad: bytes = b'') -> Tuple[bytes, bytes]:
        if len(iv) != 12:
            raise ValueError("IV must be 96-bit")
        iv_words = bytes_to_words(iv + b'\x00\x00\x00\x01')
        cipher = self._gctr(iv_words, plain)
        #计算 tag
        len_aad = len(aad) * 8
        len_c   = len(cipher) * 8
        tag_data = aad + b'\x00' * (-len(aad) % 16) + cipher + \
                   b'\x00' * (-len(cipher) % 16) + \
                   struct.pack('>QQ', len_aad, len_c)
        tag = ghash(self.H, tag_data)
        tag_block = int.from_bytes(words_to_bytes(iv_words), 'big')
        tag_block |= 0x00000001000000000000000000000000
        tag ^= tag_block
        tag = int.to_bytes(tag, 16, 'big')
        return cipher, tag

    def decrypt(self, iv: bytes, cipher: bytes, tag: bytes, aad: bytes = b'') -> bytes:
        if len(iv) != 12:
            raise ValueError("IV must be 96-bit")
        iv_words = bytes_to_words(iv + b'\x00\x00\x00\x01')
        #验证 tag
        len_aad = len(aad) * 8
        len_c   = len(cipher) * 8
        tag_data = aad + b'\x00' * (-len(aad) % 16) + cipher + \
                   b'\x00' * (-len(cipher) % 16) + \
                   struct.pack('>QQ', len_aad, len_c)
        computed_tag = ghash(self.H, tag_data)
        tag_block = int.from_bytes(words_to_bytes(iv_words), 'big')
        tag_block |= 0x00000001000000000000000000000000
        computed_tag ^= tag_block
        if int.from_bytes(tag, 'big') != computed_tag:
            raise ValueError("Auth tag mismatch")
        plain = self._gctr(iv_words, cipher)
        return plain


if __name__ == '__main__':
    key = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210]
    iv  = b'\x00' * 12
    aad = b'authenticated-data'
    msg = b'hello sm4-gcm world'
    gcm = SM4_GCM(key)
    ct, tag = gcm.encrypt(iv, msg, aad)
    print("cipher:", ct.hex())
    print("tag   :", tag.hex())
    pt = gcm.decrypt(iv, ct, tag, aad)
    print("plain :", pt)