from Client.setup import Ckks
from Server.server_1 import process_encryption
import pytroy
import random
import numpy as np
import pickle
import time
import os
import gc
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# class Ckks:
#     def __init__(self):
#         poly_modulus_degree = 8192
#         coeff_modulus_bits = [45, 40, 40, 45]

#         parameters = pytroy.EncryptionParameters(pytroy.SchemeType.ckks)
#         parameters.set_poly_modulus_degree(poly_modulus_degree)
#         parameters.set_coeff_modulus(pytroy.CoeffModulus.create(poly_modulus_degree, coeff_modulus_bits))
#         self.scale = 2.0 ** 40
#         self.context = pytroy.SEALContext(parameters)
#         self.encoder = pytroy.CKKSEncoder(self.context)
#         self.public_key = pytroy.PublicKey()
#         self.secret_key = pytroy.SecretKey()
#         self.galois_keys = pytroy.GaloisKeys()
#         self.relin_keys = pytroy.RelinKeys()
#         self.encryptor = None
#         self.decryptor = None

    # def load_keys(self, directory="keys"):
    #     # 加载密钥
    #     public_key_path = f"{directory}/public_key.pkl"
    #     print(f"Loading public key from: {public_key_path}")
    #     with open(public_key_path, "rb") as f:
    #         public_key_data = pickle.load(f)
    #     self.public_key.load(public_key_data)

    #     with open(f"{directory}/secret_key.pkl", "rb") as f:
    #         secret_key_data = pickle.load(f)
    #     self.secret_key.load(secret_key_data)

    #     with open(f"{directory}/relin_keys.pkl", "rb") as f:
    #         relin_keys_data = pickle.load(f)
    #     self.relin_keys.load(relin_keys_data)

    #     with open(f"{directory}/galois_keys.pkl", "rb") as f:
    #         galois_keys_data = pickle.load(f)
    #     self.galois_keys.load(galois_keys_data)

    #     # 初始化加密器和解密器
    #     self.encryptor = pytroy.Encryptor(self.context, self.public_key)
    #     self.decryptor = pytroy.Decryptor(self.context, self.secret_key)
    #     self.evaluator = pytroy.Evaluator(self.context)
    #     print(f"Keys loaded successfully from {directory}")
        




def load_mappings_from_file_grid(filename):
    """从文件加载映射并恢复加密对象"""
    with open(filename, 'rb') as f:
        mappings = pickle.load(f)

    # 恢复 Ciphertext 对象
    for split_id, split_info in mappings.items():
        enc_data_first = pytroy.Ciphertext()
        enc_data_first.load(split_info["Grid_Box List"])  # 恢复加密数据
        
        # 将解密后的数据替换
        split_info["Grid_Box List"] = enc_data_first

    return mappings



def load_mappings_from_file_grid_box_mapping(filename):
    """从文件加载映射并恢复加密对象"""
    with open(filename, 'rb') as f:
        mappings = pickle.load(f)

    # 恢复 Ciphertext 对象
    for cell_id, grid_box in mappings.items():
        encrypted_grid_box = pytroy.Ciphertext()
        encrypted_grid_box.load(grid_box)  # 恢复加密数据
        
        # 将解密后的数据替换
        mappings[cell_id] = encrypted_grid_box

    return mappings



def load_mappings_from_file(filename):
    """
    从指定文件读取映射数据并恢复加密对象。
    
    Args:
        filename (str): 文件名，包含已保存的数据。
        ckks: 用于恢复加密数据的 CKKS 加密对象实例。
    
    Returns:
        dict: 读取并恢复后的映射数据。
    """
    with open(filename, 'rb') as pickle_file:
        loaded_mappings = pickle.load(pickle_file)
    
    # 恢复加密数据
    for row_id, mapping in loaded_mappings.items():
        enc_data_first=pytroy.Ciphertext()
        enc_data_first.load(mapping["First Coordinates List"])

        enc_data_second=pytroy.Ciphertext()
        enc_data_second.load(mapping["Second Coordinates List"])

        # 更新恢复的数据
        mapping["First Coordinates List"] = enc_data_first
        mapping["Second Coordinates List"] = enc_data_second
    
    print(f"Data has been loaded from {filename}.")
    return loaded_mappings

def load_and_decode_coordinates(file_path):
    """
    从文件加载加密数据并解密解码得到坐标。

    参数:
    - file_path: 存储加密坐标字典的文件路径
    - ckks: Ckks 实例，用于解密和解码

    返回:
    - 解密解码后的坐标字典
    """
    # 从文件加载加密数据
    with open(file_path, 'rb') as file:
        loaded_vr_id_to_coordinates = pickle.load(file)

    # 解密并解码坐标
    vr_id_to_coordinates_decoded = {}

    for vr_id, enc_data in loaded_vr_id_to_coordinates.items():
        # 创建一个新的 Ciphertext 对象并加载加密数据
        enc_obj = pytroy.Ciphertext()
        enc_obj.load(enc_data)

        # # 解密
        # decrypted_data = ckks.decryptor.decrypt(enc_obj)

        # # 解码
        # decoded_coordinates = ckks.encoder.decode(decrypted_data)

        # 将解码后的坐标存入字典
        vr_id_to_coordinates_decoded[vr_id] = enc_obj

    return vr_id_to_coordinates_decoded




def decrypt_coordinate( encrypted_entry, aes_key):
    """
    解密指定 VR_ID 对应的密文数据。
    
    Args:
        vr_id_to_coordinates (dict): 存储加密数据的字典。
        vr_id (str): 要解密的 VR_ID。
        aes_key (bytes): AES 解密密钥。
    
    Returns:
        list: 解密后的坐标数据（浮点数列表）。
    """
    # 获取密文数据

    
    encrypted_data = base64.b64decode(encrypted_entry["encrypted_data"])
    iv = base64.b64decode(encrypted_entry["iv"])

    # 初始化 AES 解密器
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # 解密并解码数据
    decrypted_bytes = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    coordinates = list(map(float, decrypted_bytes.decode('utf-8').split(',')))

    return coordinates

def load_aes_key(file_path):
    """
    从文件加载 AES 密钥。
    
    Args:
        file_path (str): 密钥文件路径。
    
    Returns:
        bytes: 加载的 AES 密钥。
    """
    with open(file_path, 'rb') as key_file:
        key = key_file.read()
    print(f"AES key loaded from {file_path}")
    return key
print(111)
# raise ValueError
pytroy.initialize_kernel()
ckks=Ckks()
ckks.load_keys()
aes_key = load_aes_key("Data/AES_key.bin")







# x,y=random.randint(0,1),random.randint(0,1)
x,y=0.55, 0.55
x = round(x, 2)
y = round(y, 2)
point_array = np.array([-x,-y]*1024)

point_data = ckks.encoder.encode(point_array, ckks.scale) #编码加密
enc_point = ckks.encryptor.encrypt(point_data)

point_array_x = np.array([-x]*2048)
point_array_y = np.array([-y]*2048)
k=10

point_data_x = ckks.encoder.encode(point_array_x, ckks.scale) #编码加密
enc_point_x = ckks.encryptor.encrypt(point_data_x)


point_data_y = ckks.encoder.encode(point_array_y, ckks.scale) #编码加密
enc_point_y = ckks.encryptor.encrypt(point_data_y)

# 提前加载所有需要的数据
current_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(current_dir, "Data")

# 预加载数据
# cell_id_grid_box_mapping=load_mappings_from_file_grid_box_mapping(os.path.join(data_dir, 'cell_id_grid_box_mapping.pkl'))
splits_dict = load_mappings_from_file_grid(os.path.join(data_dir, 'test_splits_dict.pkl'))
grid_mappings = load_mappings_from_file(os.path.join(data_dir, 'grid_mappings.pkl'))
if k<=5:
    independent_mappings = load_mappings_from_file(os.path.join(data_dir, 'independent_mappings.pkl'))
elif k>5:
    independent_mappings = load_mappings_from_file(os.path.join(data_dir, 'all_mappings.pkl'))
elif k>20:
    independent_mappings = load_mappings_from_file(os.path.join(data_dir, 'final_mappings.pkl'))
file_path='Data/vr_id_to_coordinates_AES.pkl'
with open(file_path, "rb") as file:
        vr_id_to_coordinates_decoded = pickle.load(file)
# vr_id_to_coordinates_decoded = load_and_decode_coordinates(os.path.join(data_dir, 'vr_id_to_coordinates.pkl'))



# process_encryption(ckks,enc_point,enc_x,enc_y,k=1):
start_time = time.time()
plain_gird=process_encryption(ckks,enc_point,enc_point_x,enc_point_y,k,splits_dict=splits_dict,
                                grid_mappings=grid_mappings,
                                real_mappings=independent_mappings,
                                vr_id_to_coordinates_decoded=vr_id_to_coordinates_decoded)

# print("plain_gird",plain_gird)
result=[]
if k==1:
    decoded_coordinates=decrypt_coordinate(plain_gird,aes_key)
    # decrypted_data = ckks.decryptor.decrypt(plain_gird)
    # decoded_coordinates = ckks.encoder.decode(decrypted_data)[0:2].real
    print(decoded_coordinates)
else:
    for i in  plain_gird:
        decoded_coordinates=decrypt_coordinate(i,aes_key)     
        result.append(decoded_coordinates)
    print(result)
end_time = time.time()
execution_time = end_time - start_time
print(f"运行时间: {execution_time:.6f} 秒")