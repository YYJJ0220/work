#SM3的基本实现
from gmssl import sm3
import hmac


def encrypt(src: str):
    return sm3_hash(src)


def sm3_hash(src: str):
    msg_list = [i for i in bytes(src.encode('utf-8'))]
    return sm3.sm3_hash(msg_list).upper()


def verify(src: str, sm3_hex_str: str):
    new_hex_str = sm3_hash(src)
    return new_hex_str == sm3_hex_str


def encrypt_with_key(src: str, key: str):

    return hmac_hash(src, key, 'SM3')


def hmac_hash(src: str, key: str, mod: str):
    return hmac.new(key.encode('utf-8'), src.encode('utf-8'), mod).hexdigest().upper()


def verify_with_key(src: str, sm3_hex_str: str, key: str):
    new_hex_str = hmac_hash(src, key, 'SM3')
    return new_hex_str == sm3_hex_str


if __name__ == "__main__":
    src = "测试字符串"
    key = "ABCDEF"

    hash_str = encrypt(src)
    flag = verify(src, hash_str)
    print(hash_str)
    print(flag)

    hash_str = encrypt_with_key(src, key)
    flag = verify_with_key(src, hash_str, key)
    print(hash_str)
    print(flag)