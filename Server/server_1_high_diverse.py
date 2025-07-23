import random
from Server.server_2_high_diverse import calcute_grid,calcute_grid_ou_final,calcute_grid_ou
from Client.setup import generate_mac_with_ckks,verify_mac_with_ckks
import re
import pytroy
import time
from itertools import chain
import numpy as np
import hashlib
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random
import base64
# tag2='plain_shared_tag'
tag = "secure_shared_tag"


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





def process_neighbors_and_compute(ckks, min_index, mappings, enc_x, enc_y, plain_data_r, enc_point, k):
    """
    根据最小索引获取邻居信息，并处理加密的网格数据，进行计算。
    参数:
    - ckks: CKKS 加密环境
    - min_index: 最小值索引
    - mappings: 对应的映射（如 independent_mappings, all_mappings, final_mappings）
    - enc_x, enc_y: 加密的 X 和 Y 坐标
    - plain_data_r: 明文数据，用于与密文相乘
    - enc_point: 加密点（用于参数转换）
    - k: k 值，用于判断不同的处理逻辑
    """
    # 获取最小索引对应的邻居
    # print("min_index",min_index)
    neighbors = mappings.get(min_index, None)
    # print("neighbors",neighbors)
    # raise ValueError
    if neighbors:
        # 获取邻居列表的长度
        need_length = len(neighbors['VR_IDs List'])

        # 获取加密的网格数据
        encrpt_gird_vr = neighbors['Coordinates List']

        # 进行加密计算：mod_switch、加法、平方、乘法等
        ckks.evaluator.mod_switch_to_inplace(encrpt_gird_vr, enc_point.parms_id())
        
        # 密文相加
        enc_add = ckks.evaluator.add(encrpt_gird_vr, enc_point)
        enc_add = ckks.evaluator.square(enc_add)
        for c in range(6):
            temp_rot = ckks.evaluator.rotate_vector(enc_add, t,  ckks.galois_keys)  # 不消耗层数
            enc_add = ckks.evaluator.add(temp_rot, enc_add)                   # 不消耗层数
            t *= 2



        enc_add_final = ckks.evaluator.multiply_plain(enc_add, plain_data_r)

        # 重新缩放
        ckks.evaluator.rescale_to_next_inplace(enc_add_final)


        timestamp = int(time.time())
        # generated_mac, encrypted_timestamp_tag=generate_mac_with_aes_and_hash(enc_add_final,timestamp,tag,aes_key)
        generated_mac, encrypted_timestamp_tag=generate_mac_with_ckks(ckks,enc_add_final,timestamp,tag)
        # mac3 = generate_mac(ckks, enc_add_final, tag, timestamp)
        # 最终的计算函数

        enc_data_size = sys.getsizeof(enc_add_final)  # 获取对象的大小，单位为字节
                # 将字节转换为 KB
        enc_data_size_kb = enc_data_size / 1024

        print(f"3密文的大小为: {enc_data_size_kb:.2f} KB")
        topk,mac_plain3,timestamp1=calcute_grid_ou_final(ckks, enc_add_final, need_length, k,neighbors['VR_IDs List'],generated_mac,encrypted_timestamp_tag)
        # result,message=verify_mac_with_aes_and_hash(aes_key,topk,mac_plain3,timestamp1)
        result,message,topk=verify_mac_with_ckks(ckks,topk,mac_plain3,timestamp1,tag)
        topk=topk[:k]
        # result,message=verify_mac_plain(topk,mac_plain3,timestamp1,tag2)
        topk=['V'+str(round(i)) for i in topk]
        # print('there1')
        if not result:
            print(message)
            sys.exit("Program terminated due to invalid MAC verification.")  # 终止程序并打印信息
            
        return topk
    else:
        print(f"No neighbors found for min_index {min_index}.")
        return None
def get_coordinates_for_multiple_indexes(vr_id_to_coordinates_decoded, min_indexes):
    """
    获取多个索引对应的坐标
    参数:
    - vr_id_to_coordinates_decoded: 存储 VR_ID 和对应坐标的字典
    - min_indexes: 可能是一个索引列表
    返回:
    - 返回一个坐标列表，若某个索引没有找到坐标，则返回 None
    """
    # print(min_indexes)
    coordinates_list = []

    for min_index in min_indexes:
        coordinates = vr_id_to_coordinates_decoded.get(min_index, None)
        coordinates_list.append(coordinates)

    return coordinates_list


def generate_random(tag, timestamp, length=1):
    """
    根据标签和时间戳生成随机数序列
    """
    seed = hashlib.sha256(f"{tag}{timestamp}".encode()).hexdigest()
    random.seed(seed)
    return [random.randint(1, 10) for _ in range(length)]


def generate_mac(ckks, encrypted_message, tag, timestamp):
    """
    生成基于CKKS密文的MAC码
    """
    # 生成随机数
    r = generate_random(tag, timestamp, length=2048)
    # print(r)
    r=ckks.encoder.encode(r, ckks.scale)
    r = ckks.encryptor.encrypt(r)
    if isinstance(encrypted_message, list):
        encrypted_message=encrypted_message[0]

    ckks.evaluator.mod_switch_to_inplace(r, encrypted_message.parms_id()) 
    # 密文乘以明文
    enc_add_total = ckks.evaluator.add(encrypted_message, r)

    # 重新缩放
    ckks.evaluator.rescale_to_next_inplace(enc_add_total)
    # 模运算参数

    # 生成MAC1：线性组合
    mac1 = enc_add_total

    # 生成MAC2：指数运算
    # mac2 = pow(encrypted_message, r, modulus)

    return mac1

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


def generate_mac_plain(data, timestamp, tag):
    """
    根据数据、时间戳和 tag 生成 MAC。
    :param data: 输入数据 (标量、列表或 numpy 数组)
    :param timestamp: 时间戳 (int)
    :param tag: 唯一标识 (str)
    :return: 生成的 MAC
    """
    # 如果 data 是标量，转为 numpy 数组
    if np.isscalar(data):
        data = np.array([data])
    elif not isinstance(data, np.ndarray):
        data = np.array(data)
    
    # 生成与数据大小一致的随机数
    random_values = generate_random_with_timestamp_and_tag(timestamp, tag, size=data.size)
    
    # 转换为 numpy 数组
    random_values = np.array(random_values).reshape(data.shape)
    
    # 计算 MAC：数据与随机数逐元素相乘
    mac = data * random_values
    return mac

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

def verify_mac_plain(data, mac, timestamp, tag):
    """
    验证 MAC 的有效性。
    :param data: 原始数据 (标量、字符串、列表或 numpy 数组)
    :param mac: 提供的 MAC (标量或 numpy 数组)
    :param timestamp: 时间戳 (int)
    :param tag: 唯一标识 (str)
    :return: (验证结果, 错误消息)
    """
    # 提取数字
    try:
        numeric_data = extract_numbers_from_data(data)
    except ValueError as e:
        return False, f"Data extraction failed: {e}"
    
    # 如果 mac 是标量，转为 numpy 数组
    if np.isscalar(mac):
        mac = np.array([mac])
    elif not isinstance(mac, np.ndarray):
        mac = np.array(mac)

    # 重新生成 MAC
    expected_mac = generate_mac_plain(numeric_data, timestamp, tag)

    # 验证 MAC 是否一致
    if np.allclose(expected_mac, mac):
        return True, "MAC verification successful."
    else:
        return False, "MAC verification failed."





def process_encryption(ckks, enc_point, enc_x, enc_y, k=1,
                       splits_dict=None, grid_mappings=None,
                       real_mappings=None,  vr_id_to_coordinates_decoded=None):
    """
    对 cell_voronoi_mapping 数据进行加密、旋转处理并计算网格。

    Args:
        cell_voronoi_mapping (list or dict): 输入的 cell_voronoi_mapping 数据。
        ckks (object): CKKS 对象，用于加密和计算。

    Returns:
        list: 解密后的网格数据 plain_grid。
    """
    # 随机生成 r_number 并初始化 r 列表
    r_number = random.randint(1, 10)
    # r_number=1
    r = np.array([r_number]*2048)
    # print("r",r)
    # 编码 r 数据
    plain_data_r = ckks.encoder.encode(r, ckks.scale)
    # current_dir = os.path.dirname(os.path.abspath(__file__))
    # data_dir = os.path.join(current_dir, "../Data")


    available_keys = list(splits_dict.keys())  # 可用键列表
    # print("available_keys",available_keys)
    selected_keys = []
    # print(splits_dict)
    # print("available_keys",available_keys)
    while available_keys:
        start_time = time.time()
        key = random.choice(available_keys)  # 随机选择一个键
        selected_keys.append(key)  # 记录选择的键
        available_keys.remove(key)  # 移除已选择的键
        if key not in splits_dict:
            raise ValueError(f"Key {key} not found in splits_dict.")
        # total_grid_boxes_list = []
        # 遍历选定部分的所有 items
        item = splits_dict[key]
        # print(item)
        grid_box = item["Grid_Box List"]
        # print(grid_box)

        ###ID的长度
        length=len(item["Cell_IDs"])
        # print("length",length)


    # 初始化 plain_grid
        plain_grid = []
        Ou_grid=[]
        enc_data_total=grid_box
            # 将加密数据转换到目标参数 ID
        # print("Scale of enc_data_total: ", enc_point.scale())  # 获取 scale
        # print("Parms_id of enc_data_total: ", enc_point.parms_id())  # 获取 parms_id
        # plain_mul_d = ckks.decryptor.decrypt(enc_data_total) #解码解密查看结果
        
        # mul_d = ckks.encoder.decode(plain_mul_d)[0:length].real
        # # print("mul_d",mul_d)
        # ckks.evaluator.mod_switch_to_inplace(plain_data_r, enc_data_total.parms_id())

        # plain_data_r.scale(enc_data_total.scale())

        # c3=ckks.evaluator.add_plain(enc_data_total, plain_data_r)
        # print(111)
        ckks.evaluator.mod_switch_to_inplace(enc_data_total, enc_point.parms_id())

        # 密文相加
        enc_add_total = ckks.evaluator.add(enc_data_total, enc_point)

        # 密文乘以明文
        enc_add_total = ckks.evaluator.multiply_plain(enc_add_total, plain_data_r)
        # 对于加密后的密文 enc_data_total 和 plain_data_r


        # 重新缩放
        # ckks.evaluator.rescale_to_next_inplace(enc_add_total)

        # plain_mul_d = ckks.decryptor.decrypt(enc_add_total) #解码解密查看结果
        
        # mul_d = ckks.encoder.decode(plain_mul_d)[0:length].real
        # print("mul_d",mul_d)

        # 生成 -64 的倍数作为旋转步数
        min_value = -300
        max_value = -1
        possible_values = [x for x in range(min_value, max_value + 1) if x % -128 == 0]
        t = random.choice(possible_values)

        # 向右旋转密文向量
        temp_rot = ckks.evaluator.rotate_vector(enc_add_total, t, ckks.galois_keys)
        ckks.evaluator.rescale_to_next_inplace(temp_rot)
        # print("t",t)
        # 解密并计算网格
        # print(length*4 - t)
        
        timestamp = int(time.time())
        #单密文
        # random_list = [random.randint(0, 100) for _ in range(2048)]
        # plain_data_x1 = ckks.encoder.encode(random_list, ckks.scale)  # 编码加密
        # enc_point = ckks.encryptor.encrypt(plain_data_x1)

        # print("Scale of enc_data_total: ", temp_rot.scale())  # 获取 scale
        # print("Parms_id of enc_data_total: ", temp_rot.parms_id())  # 获取 parms_id



        # print("Scale of plain_data_r: ", plain_data_r.scale())  # 获取 scale
        # print("Parms_id of plain_data_r: ", plain_data_r.parms_id())  # 获取 parms_id
        # temp_rot.scale(plain_data_x1.scale)
        # ckks.evaluator.mod_switch_to_inplace(plain_data_r, temp_rot.parms_id())
        # c3=ckks.evaluator.add(temp_rot, enc_point)
        # raise ValueError
        # generated_mac, encrypted_timestamp_tag=generate_mac_with_aes_and_hash(temp_rot,timestamp,tag,aes_key)
        generated_mac, encrypted_timestamp_tag=generate_mac_with_ckks(ckks,temp_rot,timestamp,tag)
        # print("成功")
        # raise ValueError

        enc_data_size = sys.getsizeof(temp_rot)  # 获取对象的大小，单位为字节
        # 将字节转换为 KB
        enc_data_size_kb = enc_data_size / 1024

        print(f"1密文的大小为: {enc_data_size_kb:.2f} KB")

        plain_grid,mac,encrypted_timestamp_tag = calcute_grid(ckks, temp_rot, length * 128 - t, generated_mac,encrypted_timestamp_tag,num_to_change=2 )
        # plain_grid,mac_plain1,timestamp1 = calcute_grid(ckks, temp_rot, length * 4 - t, mac1,timestamp,num_to_change=2 )
        end = time.time()

        print(f'decode Time taken: {end-start_time:.6f} seconds')
        # 如果解密后的网格有值，进行左旋操作
        # print(plain_grid,mac,encrypted_timestamp_tag)
        if mac:
            start_time = time.time()
            result, message,plain_grid = verify_mac_with_ckks(ckks,plain_grid, mac, encrypted_timestamp_tag,tag)
            # result, message = verify_mac_with_aes_and_hash(aes_key,plain_grid, mac, encrypted_timestamp_tag)
            # print(length,-t//4,(length * 4 - t)//4)
            plain_grid=plain_grid[-t//128:(length * 128 - t)//128]
            # raise ValueError
            # print('there2')
            if not result:
                print(message)
                sys.exit("Program terminated due to invalid MAC verification.")  # 终止程序并打印信息
            
            # plain_grid=plain_grid[-t//4:]
            # plain_grid = rotate_left(plain_grid, -t)
            # 按行打印
            # for row in plain_grid:
            #     print(row)
            epsilon = 1e-3  # 你可以根据实际情况调整这个值

            # 查找接近1的元素的索引
            indices = [i for i, value in enumerate(plain_grid) if abs(value - 1) < epsilon][0:length]
            # indices = [i for i, value in enumerate(plain_grid) if value == 1][0:length]
            # 获取 vrs_list 中对应下标的值
            # print(indices)
            #############!!!!!!!!!!!!splits_dict不需要VRs
            corresponding_vrs = [item["Cell_IDs"][i] for i in indices][0:length]
            grid_encode=[grid_mappings[i]  for i in corresponding_vrs]
            VR_id_list=[]
            random_indices = list(range(len(grid_encode)))
            
            random.shuffle(random_indices)
            # for _ in range(len(grid_encode)):
            #     VR_id_list.append(grid_encode[_]['VR_IDs List'])
            ###最小的欧氏距离
            for idx in random_indices:
                # 处理 VR_IDs List
                VR_id_list.append(grid_encode[idx]['VR_IDs List'])
                
                # 处理加密的网格数据（encrpt_gird_vr_x_point 和 encrpt_gird_vr_y_point）
                encrpt_gird_vr_point = grid_encode[idx]['Coordinates List']  # 这里假设 'Grid_X' 是对应的数据
                # encrpt_gird_vr_y_point = grid_encode[idx]['Second Coordinates List']  # 假设 'Grid_Y' 是对应的数据
                
                # 加密计算过程
                ckks.evaluator.mod_switch_to_inplace(encrpt_gird_vr_point, enc_point.parms_id())
                
                
                # enc_add_x = ckks.evaluator.add(encrpt_gird_vr_x_point, enc_x)

                enc_add = ckks.evaluator.add(encrpt_gird_vr_point, enc_point)
                enc_add = ckks.evaluator.square(enc_add)
                for c in range(6):
                    temp_rot = ckks.evaluator.rotate_vector(enc_add, t,  ckks.galois_keys)  # 不消耗层数
                    enc_add = ckks.evaluator.add(temp_rot, enc_add)                   # 不消耗层数
                    t *= 2


                enc_add_final = ckks.evaluator.multiply_plain(enc_add, plain_data_r)

                # 重新缩放
                ckks.evaluator.rescale_to_next_inplace(enc_add_final)

                # 将加密结果添加到 Ou_grid
                Ou_grid.append(enc_add_final)
            end = time.time()

            print(f'test_time: {end-start_time:.6f} seconds')
            timestamp = int(time.time())
            # mac2 = generate_mac(ckks, Ou_grid, tag, timestamp)
            # generated_mac, encrypted_timestamp_tag=generate_mac_with_aes_and_hash(Ou_grid,timestamp,tag,aes_key)
            # print(type(Ou_grid))
            # print(len(Ou_grid))
            generated_mac, encrypted_timestamp_tag=generate_mac_with_ckks(ckks,Ou_grid,timestamp,tag)
            enc_data_size = sys.getsizeof(Ou_grid)  # 获取对象的大小，单位为字节
            # 将字节转换为 KB
            enc_data_size_kb = enc_data_size / 1024

            print(f"2密文的大小为: {enc_data_size_kb:.2f} KB")
            min_index,mac_plain2,timestamp1=calcute_grid_ou(ckks,Ou_grid,VR_id_list,generated_mac,encrypted_timestamp_tag)
            # result, message = verify_mac_with_aes_and_hash(aes_key,plain_grid, mac, encrypted_timestamp_tag)

            # result,message=verify_mac_with_aes_and_hash(aes_key,min_index,mac_plain2,timestamp1)
            result,message,decoded_min_index=verify_mac_with_ckks(ckks,min_index,mac_plain2,timestamp1,tag)
            print('there3')
            if not result:
                print(message)
                sys.exit("Program terminated due to invalid MAC verification.")  # 终止程序并打印信息
            decoded_min_index=round(decoded_min_index[0])
            # print("min_index",decoded_min_index)
            decoded_min_index='V'+str(decoded_min_index)
            # raise ValueError
            if k ==1:
                coordinates = vr_id_to_coordinates_decoded.get(decoded_min_index, None)
                return coordinates
            elif k <=5:
                print("进入这里")
                
                topk=process_neighbors_and_compute(ckks, decoded_min_index, real_mappings, enc_x, enc_y, plain_data_r, enc_point, k)
            ###如果不ok的话,再将最下标对应的所有加密的邻居发给S2解密
            # elif k<=10:
            #     topk=process_neighbors_and_compute(ckks, decoded_min_index, real_mappings, enc_x, enc_y, plain_data_r, enc_point, k)
            # else:
            #     topk=process_neighbors_and_compute(ckks, decoded_min_index, real_mappings, enc_x, enc_y, plain_data_r, enc_point, k)
            
            if topk:
                coordinates_list = get_coordinates_for_multiple_indexes(vr_id_to_coordinates_decoded, topk)
                # print("coordinates_list",coordinates_list)
                return coordinates_list




            


            

