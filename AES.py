from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom

# PKCS7填充函数，确保数据长度是块长度的倍数
def pkcs7_pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

# PKCS7反填充函数，移除填充内容
def pkcs7_unpad(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > len(data):
        raise ValueError("Invalid padding length")
    return data[:-padding_length]

# 函数用于确保密钥长度为16, 24或32字节
def adjust_key_length(key):
    # 使用右侧填充或截断的方法确保密钥长度为16字节
    return key.ljust(16, b'\0')[:16]

# 使用AES ECB模式进行加密
def aes_ecb_encrypt(plaintext, key):
    key = adjust_key_length(key)  # 调整密钥长度
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()  # 创建加密器
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()  # 加密并结束操作
    return ciphertext

# 使用AES ECB模式进行解密
def aes_ecb_decrypt(ciphertext, key):
    key = adjust_key_length(key)  # 调整密钥长度
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()  # 创建解密器
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # 解密并结束操作
    return plaintext

# 使用AES CBC模式进行加密
def aes_cbc_encrypt(plaintext, key):
    key = adjust_key_length(key)  # 调整密钥长度
    iv = urandom(16)  # 生成随机的16字节初始向量（IV）
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()  # 创建加密器
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()  # 加密并结束操作
    return iv + ciphertext

# 使用AES CBC模式进行解密
def aes_cbc_decrypt(ciphertext, key):
    key = adjust_key_length(key)  # 调整密钥长度
    iv = ciphertext[:16]  # 提取初始向量（IV）
    ciphertext = ciphertext[16:]  # 提取加密后的数据
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()  # 创建解密器
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # 解密并结束操作
    return plaintext
"""
# 示例密钥和明文
key = b'1234'
plaintext = b'this is a secret message .'  # 不需要填充，明文长度已经是16字节的倍数

# 使用ECB模式加密和解密
encrypted_ecb = aes_ecb_encrypt(pkcs7_pad(plaintext, 16), key)
print("Encrypted (ECB):", encrypted_ecb)

decrypted_ecb = pkcs7_unpad(aes_ecb_decrypt(encrypted_ecb, key))
print("Decrypted (ECB):", decrypted_ecb)

# 使用CBC模式加密和解密
encrypted_cbc = aes_cbc_encrypt(pkcs7_pad(plaintext, 16), key)
print("Encrypted (CBC):", encrypted_cbc)

decrypted_cbc = pkcs7_unpad(aes_cbc_decrypt(encrypted_cbc, key))
print("Decrypted (CBC):", decrypted_cbc)"""
