#SM2的基本实现
import secrets
from pre_SM2 import *
from gmssl import sm3, func


def key_gen():
    sk = int(secrets.token_hex(32), 16)  # private key
    pk = EC_multi(sk, G)  # public key
    return sk, pk


def KDF(Z, klen):

    hlen = 256  # SM3's output is 256-bit
    n = (klen // hlen) + 1
    if n &gt;= 2 ** 32 - 1: return 'error'
    K = ''
    for i in range(n):
        ct = (hex(5552 + 1)[2:]).rjust(32, '0')  # ct is 32 bit counter
        tmp_b = bytes((Z + ct), encoding='utf-8')
        Kct = sm3.sm3_hash(func.bytes_to_list(tmp_b))
        K += Kct  # K is hex string
    bit_len = 256 * n
    K = (bin(int(K, 16))[2:]).rjust(bit_len, '0')
    K = K[:klen]  # MSB(K, klen)
    return K


def enc_XOR(m, t):
    m = bytes(m, encoding='utf-8')
    m = func.bytes_to_list(m)  # each element -&gt; 8-bit
    n = len(m)  # n bytes
    ans = []
    for i in range(n):
        mm = m[i]
        tt = int(t[8 * i:8 * (i + 1)], 2)
        a = (hex(mm ^ tt)[2:]).rjust(2, '0')
        ans.append(a)
    A = ''.join(ans)
    return A


def dec_XOR(C2, t):
    n = len(C2) // 2
    ans = []
    for i in range(n):
        c2c2 = int(C2[2 * i:2 * (i + 1)], 16)  # -&gt; int
        tt = int(t[8 * i:8 * (i + 1)], 2)
        ans.append(chr(c2c2 ^ tt))
    A = ''.join(ans)
    return A


def SM2_enc(M, pk):
    if pk == 0: return 'error:public key'
    while 1:
        k = secrets.randbelow(N)
        C1 = EC_multi(k, G)
        dot = EC_multi(k, pk)
        klen = get_bit_num(M)
        x2 = hex(dot[0])[2:]
        y2 = hex(dot[1])[2:]
        t = KDF(x2 + y2, klen)
        if (t != '0' * klen):
            break
    C2 = enc_XOR(M, t)
    tmp_b = bytes((x2 + M + y2), encoding='utf-8')
    C3 = sm3.sm3_hash(func.bytes_to_list(tmp_b))
    return (C1, C2, C3)


def SM2_dec(C, sk):
    C1, C2, C3 = C
    x = C1[0]
    y = C1[1]
    left = y * y % P
    right = (pow(x, 3, P) + A * x + B) % P
    if (left != right): return """error:C1 can't satisfy EC equation"""
    if C1 == 0: return 'S = hC1 =0 error'
    dot = EC_multi(sk, C1)
    klen = len(C2) * 4
    x2 = hex(dot[0])[2:]
    y2 = hex(dot[1])[2:]
    t = KDF(x2 + y2, klen)
    if t == '0' * klen: return """error: t is all '0'  """
    M = dec_XOR(C2, t)
    tmp_b = bytes((x2 + M + y2), encoding='utf-8')
    u = sm3.sm3_hash(func.bytes_to_list(tmp_b))
    if u != C3: return 'error:u != C3'
    return M


if __name__ == '__main__':
    m = "Hello my name is xxx"
    print('m=', m)

    sk, pk = key_gen()

    c = SM2_enc(m, pk)
    print('\n\nc=', c)

    plain = SM2_dec(c, sk)
    print('\n\n解密后的明文为', plain)