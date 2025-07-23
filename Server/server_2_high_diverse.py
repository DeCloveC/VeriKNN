import numpy as np
import random
import heapq
from itertools import chain
from Client.setup import aes_encrypt,aes_decrypt,generate_mac_with_aes_and_hash,verify_mac_with_aes_and_hash,generate_mac_with_ckks,verify_mac_with_ckks
import re

import hashlib
import sys
import time
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random
import base64
tag = "secure_shared_tag"
# tag2='plain_shared_tag'
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

aes_key = load_aes_key("Data/AES_key.bin")
def generate_random(tag, timestamp, length=1):
    """
    根据标签和时间戳生成随机数序列
    """
    seed = hashlib.sha256(f"{tag}{timestamp}".encode()).hexdigest()
    random.seed(seed)
    return [random.randint(1, 10) for _ in range(length)]

def verify_mac(ckks, encrypted_message, mac1_received,  tag, timestamp):
    """
    验证基于CKKS密文的MAC码
    """
    r = generate_random(tag, timestamp, length=2048)
    # print(r)
    r=ckks.encoder.encode(r, ckks.scale)
    r = ckks.encryptor.encrypt(r)
    if isinstance(encrypted_message, list):
        encrypted_message=encrypted_message[0]
    ckks.evaluator.mod_switch_to_inplace(r, encrypted_message.parms_id()) 
    # 密文乘以明文
    mac1 = ckks.evaluator.add(encrypted_message, r)

    # 重新缩放
    ckks.evaluator.rescale_to_next_inplace(mac1)
    # mac2_calculated = pow(encrypted_message, r, modulus)


    plain_mul_d = ckks.decryptor.decrypt(mac1)

    # 解码
    mul_d1 = ckks.encoder.decode(plain_mul_d).real



    plain_mul_d = ckks.decryptor.decrypt(mac1_received)

    # 解码
    mul_d2 = ckks.encoder.decode(plain_mul_d).real

    # 验证MAC1和MAC2
    if mul_d1.all() == mul_d2.all() :
        return True, "MAC verification succeeded"
    else:
        return False, "MAC verification failed"


def generate_random_with_timestamp_and_tag(timestamp, tag, size=1):
    """
    根据时间戳和 tag 生成随机数。
    :param timestamp: 时间戳 (int)
    :param tag: 唯一标识 (str)
    :param size: 随机数的个数 (int)
    :return: 随机数列表
    """
    # 使用时间戳和 tag 生成种子
    seed = int(hashlib.sha256(f"{timestamp}_{tag}".encode()).hexdigest(), 16) % (2**32)
    random.seed(seed)
    return [random.random() for _ in range(size)]


def extract_numbers_from_data(data):
    """
    从输入数据中提取数字。
    :param data: 标量、字符串、列表或 numpy 数组
    :return: 提取的数字 (numpy 数组)
    """
    if np.isscalar(data):
        if isinstance(data, (int, float)):
            return np.array([float(data)])
        elif isinstance(data, str):
            # 提取字符串中的所有数字
            numbers = re.findall(r"[-+]?\d*\.\d+|\d+", data)
            if not numbers:
                raise ValueError(f"No numeric values found in data: {data}")
            return np.array([float(num) for num in numbers])
    elif isinstance(data, (list, np.ndarray)):
        extracted = []
        for item in data:
            if isinstance(item, (int, float)):
                extracted.append(float(item))
            elif isinstance(item, str):
                # 提取字符串中的所有数字
                numbers = re.findall(r"[-+]?\d*\.\d+|\d+", item)
                extracted.extend([float(num) for num in numbers])
        if not extracted:
            raise ValueError(f"No numeric values found in data: {data}")
        return np.array(extracted)
    else:
        raise TypeError(f"Unsupported data type: {type(data)}")

def generate_mac_plain(data, timestamp, tag):
    """
    根据数据、时间戳和 tag 生成 MAC。
    :param data: 输入数据 (标量、列表或 numpy 数组)
    :param timestamp: 时间戳 (int)
    :param tag: 唯一标识 (str)
    :return: 生成的 MAC
    """
    # 提取数字
    numeric_data = extract_numbers_from_data(data)
    
    # 生成与数据大小一致的随机数
    random_values = generate_random_with_timestamp_and_tag(timestamp, tag, size=numeric_data.size)
    
    # 转换为 numpy 数组
    random_values = np.array(random_values).reshape(numeric_data.shape)
    
    # 计算 MAC：数据与随机数逐元素相乘
    mac = numeric_data * random_values
    return mac



def calcute_grid(ckks,encrpted_gird,length,mac1,encrypted_timestamp_tag,num_to_change = 2):
    result, message,mul_d = verify_mac_with_ckks(
    ckks,
    encrpted_gird,
    mac1,
    encrypted_timestamp_tag,
    tag
    )
    # result=True
    # result, message = verify_mac(
    # ckks,
    # encrpted_gird,
    # mac1,
    # tag,
    # timestamp
    # )
    # raise ValueError
    if result:
        # plain_mul_d = ckks.decryptor.decrypt(encrpted_gird) #解码解密查看结果
        
        # mul_d = ckks.encoder.decode(plain_mul_d)[0:length].real
        # print("mul_d",mul_d)
        # print("mul_d",mul_d)
        mul_d=mul_d[:length]
        temp = [0] *(length//64)
        for i in range(len(mul_d) // 4):  # 每4个元素为一组
            index = i * 4  # 当前分组的起始下标
            if (mul_d[index] < 0 and mul_d[index + 1] < 0 and
                mul_d[index + 2] > 0 and mul_d[index + 3] > 0):  # 分别对应当前组的4个下标
                temp[i] = 1  # 对应分组满足条件，设置 temp 中的值
        # print("temp",temp)
        temp=np.array(temp).reshape(-1, 1).flatten().tolist()
        zero_indices = [i for i, value in enumerate(temp) if value == 0]
        # print(zero_indices)
        if(len(zero_indices))==length//4:
            # print('none')
            return [],None,None
        else:
            indices_to_change = random.sample(zero_indices, num_to_change)
            for idx in indices_to_change:
                temp[idx] = 1
            timestamp = int(time.time())
            # print('111',type(temp))
            message,generated_mac, encrypted_timestamp_tag=generate_mac_with_ckks(ckks,temp,timestamp,tag)

            # mac_plain1 = generate_mac_plain(temp, timestamp1, tag2)

            return message,generated_mac,encrypted_timestamp_tag
        
    else:
        print('there11')
        print(message)
        sys.exit("Program terminated due to invalid MAC verification.")  # 终止程序并打印信息


def calcute_grid_ou(ckks, encrpted_ou_first, VR_id_list,mac2,encrypted_timestamp_tag):

    result, message,decrypted_ou_first = verify_mac_with_ckks(
    ckks,
    encrpted_ou_first,
    mac2,
    encrypted_timestamp_tag,
    tag
    )
    """
    计算加密数据的欧氏距离，并返回 VR_id_list 中与最小距离对应的 VR_ID。
    """
    if result:
        min_value = float('inf')  # 初始化为正无穷
        min_indices = (-1, -1)  # 初始化最小值的二维索引 (行, 列)
        length = len(VR_id_list[0])  # 假设每行长度相同
        # print("decrypted_ou_first",decrypted_ou_first)
        # print(type(decrypted_ou_first))
        # 遍历加密数据，找到最小值及对应索引
        for row_index, encrypted_ou in enumerate(decrypted_ou_first):
            # 解密
            # plain_mul_d = ckks.decryptor.decrypt(encrypted_ou)
            # print(type(encrypted_ou))
            # 解码并取实数部分
            mul_d = encrypted_ou[:length]
            # print("mul_d:", mul_d)

            # 确保 mul_d 是一维数组
            if isinstance(mul_d, np.ndarray):  # 如果是 NumPy 数组
                flattened_mul_d = mul_d.tolist()  # 转换为 Python 列表
                mul_d = encrypted_ou[:length]
            elif isinstance(mul_d, (list, tuple)):  # 如果是列表或元组
                flattened_mul_d = mul_d
            else:
                raise ValueError(f"Unexpected mul_d type: {type(mul_d)}")
            flattened_mul = flattened_mul_d[::64]
            # 找到当前加密数据的最小值及其下标
            local_min_value = min(flattened_mul)
            local_min_index = flattened_mul.index(local_min_value)

            # 如果当前最小值小于已记录的最小值，则更新
            if local_min_value < min_value:
                min_value = local_min_value
                min_indices = (row_index, local_min_index)

        # 使用最小索引返回对应的 VR_ID
        min_vr_id = VR_id_list[min_indices[0]][min_indices[1]] if min_indices != (-1, -1) else None
        # print("VR_id_list:", VR_id_list)
        # print("min_vr_id:", min_vr_id)
        timestamp = int(time.time())
        # generated_mac, encrypted_timestamp_tag=generate_mac_with_aes_and_hash(min_vr_id,timestamp,tag,aes_key)
        # raise ValueError

        # min_vr_id = "V17918"
        numeric_value = int(min_vr_id[1:])  # 去掉第一个字符 'V'，然后转换为整数
        # print(numeric_value)  # 输出：17918

        min_vr_id,generated_mac, encrypted_timestamp_tag=generate_mac_with_ckks(ckks,numeric_value,timestamp,tag)

        # mac_plain2 = generate_mac_plain(min_vr_id, timestamp1, tag2)
        return min_vr_id,generated_mac,encrypted_timestamp_tag
    else:
        print('there12')
        print(message)
        sys.exit("Program terminated due to invalid MAC verification.")  # 终止程序并打印信息

    
def calcute_grid_ou_final(ckks, encrpted_ou_second, length, k, VR_id_list,mac3,timestamp):

    result, message,plain_mul_d = verify_mac_with_ckks(
    ckks,
    encrpted_ou_second,
    mac3,
    timestamp,
    tag
    )
    if result:
        """
        计算加密数据的 top-k 最小值的 VR_ID 坐标。

        参数：
        - ckks: CKKS 实例，用于解密和解码操作。
        - encrpted_ou_second: 加密的欧氏距离列表。
        - length: 数据长度。
        - k: 返回的 top-k 个元素。
        - VR_id_list: 与数据对应的 VR_ID 列表。

        返回：
        - top_k_vr_ids: top-k 最小值对应的 VR_ID。
        """
        # # 解密
        # plain_mul_d = ckks.decryptor.decrypt(encrpted_ou_second)

        # 解码
        mul_d = plain_mul_d[0:length]

        # 获取 top-k 最小值及其下标
        top_k_indices = heapq.nsmallest(k, enumerate(mul_d), key=lambda x: x[1])
        # print("top_k_indices",top_k_indices)
        # 提取 VR_ID 列表中的对应项
        top_k_vr_ids = [VR_id_list[index] for index, _ in top_k_indices]
        # print(top_k_vr_ids)
        # raise ValueError
        timestamp = int(time.time()) 
        top_k_numbers = [int(v[1:]) for v in top_k_vr_ids]
        # generated_mac, encrypted_timestamp_tag=generate_mac_with_aes_and_hash(top_k_vr_ids,timestamp,tag,aes_key)
        top_k_vr_ids,generated_mac, encrypted_timestamp_tag=generate_mac_with_ckks(ckks,top_k_numbers,timestamp,tag)

        # mac_plain3 = generate_mac_plain(top_k_vr_ids, timestamp1, tag2)
        return top_k_vr_ids,generated_mac,encrypted_timestamp_tag
    else:
        print(message)
        sys.exit("Program terminated due to invalid MAC verification.")  # 终止程序并打印信息