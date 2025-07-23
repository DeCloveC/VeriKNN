import pytroy
import os
import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import SHA256
from os import urandom
import random
import hashlib
import numpy as np
tag = "secure_shared_tag"
tag_array = [ord(char) for char in tag]

class Ckks:
    def __init__(self):
        poly_modulus_degree = 4096
        coeff_modulus_bits = [30, 20, 20, 30]

        parameters = pytroy.EncryptionParameters(pytroy.SchemeType.ckks)
        parameters.set_poly_modulus_degree(poly_modulus_degree)
        parameters.set_coeff_modulus(pytroy.CoeffModulus.create(poly_modulus_degree, coeff_modulus_bits))
        self.scale = 2.0 ** 20
        self.context = pytroy.SEALContext(parameters)
        self.encoder = pytroy.CKKSEncoder(self.context)
        self.keygen = pytroy.KeyGenerator(self.context)
        self.public_key = self.keygen.create_public_key()
        self.secret_key = self.keygen.secret_key()
        self.relin_keys = self.keygen.create_relin_keys()
        self.galois_keys = self.keygen.create_galois_keys()
        self.encryptor = pytroy.Encryptor(self.context, self.public_key)

    def save_keys(self, directory="keys"):
        os.makedirs(directory, exist_ok=True)

        # 保存密钥
        with open(f"{directory}/public_key.pkl", "wb") as f:
            pickle.dump(self.public_key.save(), f)
        with open(f"{directory}/secret_key.pkl", "wb") as f:
            pickle.dump(self.secret_key.save(), f)
        with open(f"{directory}/relin_keys.pkl", "wb") as f:
            pickle.dump(self.relin_keys.save(), f)
        with open(f"{directory}/galois_keys.pkl", "wb") as f:
            pickle.dump(self.galois_keys.save(), f)
        print(f"Keys saved successfully in {directory}")
    def load_keys(self, directory="keys"):
        # 加载密钥
        public_key_path = f"{directory}/public_key.pkl"
        print(f"Loading public key from: {public_key_path}")
        with open(public_key_path, "rb") as f:
            public_key_data = pickle.load(f)
        self.public_key.load(public_key_data)

        with open(f"{directory}/secret_key.pkl", "rb") as f:
            secret_key_data = pickle.load(f)
        self.secret_key.load(secret_key_data)

        with open(f"{directory}/relin_keys.pkl", "rb") as f:
            relin_keys_data = pickle.load(f)
        self.relin_keys.load(relin_keys_data)

        with open(f"{directory}/galois_keys.pkl", "rb") as f:
            galois_keys_data = pickle.load(f)
        self.galois_keys.load(galois_keys_data)

        # 初始化加密器和解密器
        self.encryptor = pytroy.Encryptor(self.context, self.public_key)
        self.decryptor = pytroy.Decryptor(self.context, self.secret_key)
        self.evaluator = pytroy.Evaluator(self.context)
        print(f"Keys loaded successfully from {directory}")






def generate_and_save_aes_key(file_path):
    """
    生成 AES 密钥并保存到文件。
    
    Args:
        file_path (str): 要保存密钥的文件路径。
    """
    key = get_random_bytes(16)  # 16 字节密钥（AES-128）
    with open(file_path, 'wb') as key_file:
        key_file.write(key)
    print(f"AES key saved to {file_path}")




# AES加密函数
def aes_encrypt(aes_key, data):
    """
    使用AES-GCM加密数据
    """
    if isinstance(data, dict):
        data = json.dumps(data)  # 将字典序列化为JSON字符串
    iv = urandom(12)  # 生成随机IV
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return {
        "ciphertext": ciphertext,
        "tag": encryptor.tag,
        "iv": iv,
    }


# AES解密函数
def aes_decrypt(aes_key, encrypted_data):
    """
    使用AES-GCM解密数据
    """
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(encrypted_data["iv"], encrypted_data["tag"]))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(encrypted_data["ciphertext"]) + decryptor.finalize()
    return json.loads(plaintext.decode())  # 反序列化JSON字符串为字典


# 随机数生成函数
# def generate_random_with_timestamp_and_tag(timestamp, tag, size=10):
#     """
#     根据时间戳和标签生成固定长度的随机数
#     """
#     seed = f"{timestamp}_{tag}"
#     random_values = hashlib.sha256(seed.encode()).digest()[:size]
#     return random_values.hex()


# MAC生成函数
def generate_mac_with_aes_and_hash(encrypted_message, timestamp, tag, aes_key):
    """
    生成MAC和加密的时间戳/标签
    """
    # 加密 timestamp 和 tag
    encrypted_timestamp_tag = aes_encrypt(aes_key, {"timestamp": timestamp, "tag": tag})
    
    # 生成随机数
    random_values = generate_random_with_timestamp_and_tag(timestamp, tag, size=10)
    
    # 确保消息是字符串
    if isinstance(encrypted_message, list):
        encrypted_message = ''.join(map(str, encrypted_message))
    elif not isinstance(encrypted_message, str):
        encrypted_message = str(encrypted_message)
    
    # 组合数据
    combined_data = f"{encrypted_message}_{random_values}"
    
    # 使用HMAC生成MAC
    h = hmac.HMAC(aes_key, SHA256())
    h.update(combined_data.encode())
    mac = h.finalize().hex()
    
    return mac, encrypted_timestamp_tag


def generate_random_with_timestamp_and_tag(timestamp, tag):
    """
    根据时间戳和标签生成固定长度的随机数
    """

    # 1. 拼接 timestamp 和 tag
    input_string = f"{timestamp}_{tag}"

    # 2. 对拼接字符串进行 SHA-256 哈希处理
    hash_object = hashlib.sha256(input_string.encode())
    hash_hex = hash_object.hexdigest()

    # 3. 使用哈希值作为种子初始化随机数生成器
    random.seed(int(hash_hex, 16))  # 使用哈希的十六进制值作为种子

    # 4. 生成长度为 2048 的随机数列表
    random_list = [random.randint(0, 100) for _ in range(2048)]

    return random_list



def generate_mac_with_ckks(ckks,message, timestamp, tag):
    """
    生成MAC和加密的时间戳/标签
    """
    random_values = generate_random_with_timestamp_and_tag(timestamp, tag)
    tag_array.append(timestamp)

    list_new=ckks.encoder.encode(tag_array, ckks.scale) #编码加密
    enc_tag_time = ckks.encryptor.encrypt(list_new)
    if isinstance(message, pytroy.Ciphertext) :
        # print('send_1')
        # 生成随机数
        plain_data_x1 = ckks.encoder.encode(random_values, ckks.scale)  # 编码加密
        plain_data_x1 = ckks.encryptor.encrypt(plain_data_x1)
        
        # 使用密文执行加法
        enc_add_mac = ckks.evaluator.add(message, plain_data_x1)
        
        return enc_add_mac, enc_tag_time
    elif isinstance(message, list) and isinstance(message[0], pytroy.Ciphertext):
        # print('send_2')
        plain_data_x1 = ckks.encoder.encode(random_values, ckks.scale)  #
        plain_data_x1 = ckks.encryptor.encrypt(plain_data_x1) 
        result = message[0]
        for enc_msg in message[1:]:
            result = ckks.evaluator.add(result, enc_msg)  # 累加到 result

        enc_add_mac = ckks.evaluator.add(result, plain_data_x1)
        return enc_add_mac, enc_tag_time

    else:
        # print("send_plain")
        if isinstance(message,int):
            # length=0
            random_values = random_values[0]
            mac_values = message + random_values
            message=[message]
            mac_values=[mac_values]
        else:
            length = len(message)
            random_values = random_values[:length]
            mac_values = message + random_values
        plain_data_x1 = ckks.encoder.encode(mac_values, ckks.scale)
        enc_data_mac = ckks.encryptor.encrypt(plain_data_x1)
        
        # 对 message 进行编码加密
        plain_data_x1 = ckks.encoder.encode(message, ckks.scale)
        enc_data_message = ckks.encryptor.encrypt(plain_data_x1)
        print('send ok')
        return enc_data_message, enc_data_mac, enc_tag_time


        
def verify_mac_with_ckks(ckks, message,  mac, enc_tag_time, tag):
    """
    验证 MAC 和加密的时间戳/标签
    """
    # 1. 解密加密的时间戳和标签
    decrypted_tag_time = ckks.decryptor.decrypt(enc_tag_time)  # 解密加密的时间戳和标签
    tag_time_list = ckks.encoder.decode(decrypted_tag_time).real

    # 2. 提取解密出的时间戳和标签
    decrypted_tag = tag_time_list[:len(tag_array)]  # 标签
    decrypted_timestamp = tag_time_list[-1]       # 时间戳


    
    # print(tag_array,'\n',decrypted_tag)
    # 确保解密后的时间戳和标签与输入一致
    # print(tag_array,decrypted_tag)
    if not np.all(np.isclose(tag_array, decrypted_tag, atol=1)):  # 允许误差在 1 以内
        return False, "tag mismatch", None


    # 3. 生成随机数，确保长度匹配
    random_values = generate_random_with_timestamp_and_tag(decrypted_timestamp, tag)

    if isinstance(message, pytroy.Ciphertext) :
        # print('send_1')
        # 对密文进行验证
        # 解密密文并验证
        decrypted_message = ckks.decryptor.decrypt(message)
        decoded_message = ckks.encoder.decode(decrypted_message).real

        # 使用解密的消息与随机数值计算 MAC
        mac_computed = decoded_message + random_values

        decrypted_mac = ckks.decryptor.decrypt(mac)
        decoded_mac = ckks.encoder.decode(decrypted_mac).real

        
        
        # 比较计算的 MAC 和解密的密文
        if not np.all(np.isclose(mac_computed, decoded_mac)):
        # if mac_computed == decoded_mac:
            return True, "MAC verification succeeded",decoded_message
        else:
            return False, "MAC verification failed",None
    
    elif isinstance(message, list) and isinstance(message[0], pytroy.Ciphertext):
        # print('send_2')
        # 如果 message 是密文列表，逐一对密文进行加法累加
        result = []
        # 假设 message 是一个包含多个解密后的列表
        for enc_msg in message:
            decrypted_message = ckks.decryptor.decrypt(enc_msg)  # 解密
            decrypted_message = ckks.encoder.decode(decrypted_message).real  # 解码
            
            result.append(decrypted_message)  # 将解密结果存储到 result 中

        # 现在对 result 中的每列求和
        # 假设每个解密的消息是列表且长度一致，可以使用 zip 对每列进行求和
        summed_result = [sum(x) for x in zip(*result)]

        mac_cal = [x + y for x, y in zip(summed_result, random_values)]

        # 解密并进行对比
        decrypted_mac = ckks.decryptor.decrypt(mac)
        decoded_mac = ckks.encoder.decode(decrypted_mac).real

        if not np.all(np.isclose(mac_cal, decoded_mac)):
            return True, "MAC verification succeeded",result
        else:
            return False, "MAC verification failed",None

    # else:
    #     # 处理 message 是明文的情况

       

    #     # 对 message 进行加密
    #     decrypted_message = ckks.decryptor.decrypt(message)
    #     decoded_message = ckks.encoder.decode(decrypted_message)

    #     decoded_message=decoded_message[:length]+random_values[:length]
    #     # 解密并对比
    #     decrypted_mac = ckks.decryptor.decrypt(mac)
    #     decoded_mac = ckks.encoder.decode(decrypted_mac)

    #     # 验证 mac 是否与加密数据一致
    #     if decoded_mac == decoded_message:
    #         return True, "MAC verification succeeded",decoded_message
    #     else:
    #         return False, "MAC verification failed",None







def generate_random_list_with_seed(timestamp, tag, size=2048):
    """
    根据时间戳和标签作为种子生成固定长度的随机数列表
    """
    # 将时间戳和标签组合成种子字符串
    seed = f"{timestamp}_{tag}"
    
    # 使用种子初始化随机数生成器
    random.seed(seed)
    
    # 生成随机数列表
    random_list = [random.random() for _ in range(size)]
    
    return random_list



# MAC验证函数
def verify_mac_with_aes_and_hash(aes_key, encrypted_message, mac_received, encrypted_timestamp_tag):
    """
    验证MAC和加密的时间戳/标签
    """
    try:
        # 解密 timestamp 和 tag
        decrypted_data = aes_decrypt(aes_key, encrypted_timestamp_tag)
        timestamp = decrypted_data.get("timestamp")
        tag = decrypted_data.get("tag")
        
        if timestamp is None or tag is None:
            raise ValueError("Decrypted data does not contain valid timestamp or tag.")
        
        # 生成随机数
        random_values = generate_random_with_timestamp_and_tag(timestamp, tag, size=10)
        
        # 确保消息为字符串形式
        if isinstance(encrypted_message, list):
            encrypted_message = ''.join(map(str, encrypted_message))
        elif not isinstance(encrypted_message, str):
            encrypted_message = str(encrypted_message)
        
        # 组合数据
        combined_data = f"{encrypted_message}_{random_values}"
        
        # 使用HMAC验证
        h = hmac.HMAC(aes_key, SHA256())
        h.update(combined_data.encode())
        mac_calculated = h.finalize().hex()
        
        # 比较接收到的MAC与计算的MAC
        if mac_received == mac_calculated:
            return True, "MAC verification succeeded"
        else:
            return False, "MAC verification failed"
    
    except Exception as e:
        return False, f"Failed to verify MAC: {str(e)}"

if __name__ == "__main__":
    pytroy.initialize_kernel()
    ckks = Ckks()
    ckks.save_keys()




