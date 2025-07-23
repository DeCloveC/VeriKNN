import numpy as np
import matplotlib.pyplot as plt
from matplotlib.collections import PolyCollection
from matplotlib.patches import Rectangle
from scipy.spatial import Voronoi
from shapely.geometry import Polygon, box
print(111)
from setup import Ckks
import pandas as pd
from scipy.spatial.distance import euclidean
import pickle
# from setup import Ckks
import random
import pytroy
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

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

# 示例：生成密钥并保存到 key.bin
####ID:::Coordinates
N=10
def save_mappings_to_file(grid_mappings, filename):
    """
    将 grid_mappings 保存到指定文件。
    
    Args:
        grid_mappings (dict): 需要保存的字典数据。
        filename (str): 文件名，保存数据的路径。
    """
    with open(filename, 'wb') as pickle_file:
        pickle.dump(grid_mappings, pickle_file)
    print(f"Data has been saved to {filename}.")

###映射表
# def encrypt_and_save_cell_id_grid_box_mapping(cell_id_grid_box_mapping, ckks, file_path):
#     """
#     将 cell_id_grid_box_mapping 的 Grid_Box 加密并保存到文件。

#     参数：
#         cell_id_grid_box_mapping (dict): 包含 Cell_ID 和对应 Grid_Box 的字典。
#         ckks (object): CKKS 加密对象，包含编码器和加密器。
#         file_path (str): 保存加密数据的文件路径。

#     返回：
#         None
#     """
#     for cell_id, grid_box in cell_id_grid_box_mapping.items():
#         # 编码并加密 Grid_Box
#         plain_data = ckks.encoder.encode(grid_box, ckks.scale)
#         encrypted_grid_box = ckks.encryptor.encrypt(plain_data)

#         # 保存加密后的数据到字典
#         cell_id_grid_box_mapping[cell_id] = encrypted_grid_box.save()

#     # 保存加密后的字典到文件
#     with open(file_path, 'wb') as file:
#         pickle.dump(cell_id_grid_box_mapping, file)


###分割表
def split_and_encrypt_voronoi_data(cell_voronoi_mapping, num_splits=5,randomness_factor=0.1):
    """
    将 cell_voronoi_mapping 划分为指定数量的份，并对每个分割的 Grid_Box List 进行加密。
    
    参数：
    cell_voronoi_mapping (list): 包含 'Cell_ID', 'Grid_Box', 'VRs' 信息的列表
    num_splits (int): 分割的数量，默认为 5
    
    返回：
    dict: 每个分割的数据，包括 'Cell_IDs', 'VRs', 'Grid_Box List'（加密后的 Grid_Box List）
    """
    total_length = len(cell_voronoi_mapping)

    base_size = total_length // num_splits
    remaining = total_length % num_splits  # 剩余的长度

    # 初始化分割列表
    split_sizes = [base_size] * num_splits

    # 分配剩余的长度到随机的部分
    for i in range(remaining):
        split_sizes[i] += 1

    # 引入随机扰动，同时动态调整其他分组大小
    for i in range(num_splits):
        max_adjustment = int(base_size * randomness_factor)
        adjustment = random.randint(-max_adjustment, max_adjustment)

        # 确保调整后的值不会小于1，并且总和保持一致
        if split_sizes[i] + adjustment > 0:
            split_sizes[i] += adjustment
            # 调整其余部分以平衡总和
            surplus = sum(split_sizes) - total_length
            if surplus > 0:  # 超过总长时减少后续的值
                for j in range(num_splits):
                    if split_sizes[j] > 1:
                        reduction = min(surplus, split_sizes[j] - 1)
                        split_sizes[j] -= reduction
                        surplus -= reduction
                        if surplus == 0:
                            break
            elif surplus < 0:  # 不足总长时增加后续的值
                for j in range(num_splits):
                    addition = min(-surplus, total_length - sum(split_sizes))
                    split_sizes[j] += addition
                    surplus += addition
                    if surplus == 0:
                        break

    splits = []
    start = 0
    for size in split_sizes:
        splits.append(cell_voronoi_mapping[start:start + size])
        start += size

    # 转换为新列表形式并保持每个 'VRs', 'Grid_Box', 'Cell_ID' 的对应关系
    splits_dict = {}
    for i, split in enumerate(splits):
        split_info = {
            'Cell_IDs': [],
            # 'VRs': [],
            'Grid_Box List': []
        }
        for item in split:
            # 添加 Cell_ID
            split_info['Cell_IDs'].append(item['Cell_ID'])
            
            # 添加 VRs（将每个 VR 添加到一个子列表中，按照 Cell_ID 分组）
            # vr_list = item['VRs'].split(',')
            # split_info['VRs'].append(vr_list)  # 将对应的 VRs 添加为子列表
            
            # 展开 Grid_Box List
            split_info['Grid_Box List'].extend(item['Grid_Box'])  # 扁平化处理 Grid_Box 元组
        # print("split_info",split_info)
        # 编码并加密 Grid_Box List
        plain_data_total = ckks.encoder.encode(split_info['Grid_Box List'], ckks.scale)  # 编码加密
        enc_data_total = ckks.encryptor.encrypt(plain_data_total)


        # print("mul_d",mul_d)
        split_info['Grid_Box List'] = enc_data_total.save()  # 保存加密数据

        # 将每个分割的所有格子相关信息存储到 splits_dict
        splits_dict[i+1] = split_info

    return splits_dict

def process_and_encrypt_coordinates_aes(vr_neighbors, aes_key):
    """
    将 VR 坐标处理并使用 AES 加密，存储为字典。
    
    Args:
        vr_neighbors (list): 原始的 VR 数据列表，每个元素包含 'VR_ID' 和 'Coordinates'。
        aes_key (bytes): AES 加密密钥，应为 16、24 或 32 字节长度。
    
    Returns:
        dict: 一个字典，键是 VR_ID，值是 AES 加密的坐标数据。
    """
    simplified_vr_neighbors = [
        {'VR_ID': vr['VR_ID'], 'Coordinates': vr['Coordinates']}
        for vr in vr_neighbors
    ]

    # 初始化字典存储加密数据
    vr_id_to_coordinates = {}

    for vr in simplified_vr_neighbors:
        vr_id = vr['VR_ID']
        coordinates = vr['Coordinates']
        
        # 对坐标进行处理（此处为直接使用原始坐标）
        processed_coordinates = [coordinates[0], coordinates[1]]
        # print(processed_coordinates)

        # 将坐标转换为字符串进行加密
        coordinates_str = ",".join(map(str, processed_coordinates))
        coordinates_bytes = coordinates_str.encode('utf-8')

        # 初始化 AES 加密器
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv  # 生成随机 IV

        # 加密数据
        encrypted_data = cipher.encrypt(pad(coordinates_bytes, AES.block_size))

        # 存储加密数据和 IV
        vr_id_to_coordinates[vr_id] = {
            "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
        }

    return vr_id_to_coordinates



def process_and_encrypt_coordinates(vr_neighbors, ckks):
    """
    将 VR 坐标处理并加密，存储为字典。
    
    Args:
        vr_neighbors (list): 原始的 VR 数据列表，每个元素包含 'VR_ID' 和 'Coordinates'。
        ckks (object): CKKS 加密对象，包含加密所需的编码器和加密器。
    
    Returns:
        dict: 一个字典，键是 VR_ID，值是加密的坐标数据。
    """
    simplified_vr_neighbors = [
        {'VR_ID': vr['VR_ID'], 'Coordinates': vr['Coordinates']}
        for vr in vr_neighbors
    ]

    # 初始化字典存储加密数据
    vr_id_to_coordinates = {}

    for vr in simplified_vr_neighbors:
        vr_id = vr['VR_ID']
        coordinates = vr['Coordinates']
        
        # 对坐标进行处理（此处为直接使用原始坐标）
        processed_coordinates = [coordinates[0], coordinates[1]]
        print(processed_coordinates)

        # 编码加密
        plain_data = ckks.encoder.encode(processed_coordinates, ckks.scale)
        enc_data = ckks.encryptor.encrypt(plain_data).save()
        enc_data_second=pytroy.Ciphertext()
        enc_data_second.load(enc_data)
        # 存储处理后的加密坐标
        vr_id_to_coordinates[vr_id] = enc_data

    return vr_id_to_coordinates


###方格到实际VRs的表

def generate_grid_mappings(cell_voronoi_mapping, vr_coordinates_mapping, ckks):
    """
    提取 cell_voronoi_mapping 中的 VRs 和对应的 Coordinates，并生成加密的 grid_mappings。

    Args:
        cell_voronoi_mapping (list): 包含 Cell_ID 和 VRs 的列表。
        vr_coordinates_mapping (list): 提供包含 VR_ID 和 Coordinates 的映射列表。
        ckks (object): CKKS 加密对象，包含加密所需的编码器和加密器。

    Returns:
        dict: 包含加密坐标和映射信息的 grid_mappings。
    """
    # 将 vr_coordinates_mapping 转换为字典形式，方便查找
    vr_coordinates_dict = {entry["VR_ID"]: entry["Coordinates"] for entry in vr_coordinates_mapping}

    grid_mappings = {}
    # print(len(cell_voronoi_mapping))
    # count=0
    # 遍历 cell_voronoi_mapping 并处理
    for cell in cell_voronoi_mapping:
        cell_id = cell.get("Cell_ID")
        vr_list = cell.get("VRs", "").split(",") if cell.get("VRs") != "None" else []

        # 提取 VRs 和对应的 Coordinates
        vr_coords_mapping = {vr: vr_coordinates_dict.get(vr, "None") for vr in vr_list}

        #### 初始化当前行的存储
        first_coordinates_list = []  # 存储每个坐标的第一个值
        second_coordinates_list = []  # 存储每个坐标的第二个值
        vr_ids_list = []       # VR_ID 列表
        coordinate_to_vr_id = {}  # 坐标到 VR_ID 的映射

        # 遍历当前行的键值对
        for vr_id, coord in vr_coords_mapping.items():
            if coord == "None":
                continue
            # 扁平化添加坐标
            first_coordinates_list.append(coord[0])
            second_coordinates_list.append(coord[1])
            # 添加 VR_ID
            vr_ids_list.append(vr_id)
            # 建立坐标到 VR_ID 的映射
            # print(f"Type of coord: {type(coord)}, Value: {coord}")

            coordinate_to_vr_id[tuple(coord)] = vr_id
        # count+=len(first_coordinates_list)
        if len(first_coordinates_list) > 2048:
            first_coordinates_list = first_coordinates_list[:2048]
            second_coordinates_list = second_coordinates_list[:2048]
        plain_data_first = ckks.encoder.encode(first_coordinates_list, ckks.scale)
        enc_data_first = ckks.encryptor.encrypt(plain_data_first).save()



        plain_data_second = ckks.encoder.encode(second_coordinates_list, ckks.scale)
        enc_data_second = ckks.encryptor.encrypt(plain_data_second).save()

        # 存储当前行的独立映射
        grid_mappings[cell_id] = {
            "First Coordinates List": enc_data_first,
            "Second Coordinates List": enc_data_second,
            "VR_IDs List": vr_ids_list
            # "Coordinate to VR_ID Mapping": coordinate_to_vr_id
        }
    # print("all",count)
    # raise ValueError
    return grid_mappings





############# 起始表
def generate_independent_mappings(point_and_neighbors_coords_dict, ckks):
    """
    根据点和邻居的坐标字典生成独立的加密映射。

    Args:
        point_and_neighbors_coords_dict (dict): 包含点及其邻居坐标的字典。
        ckks (object): CKKS 加密对象，包含加密所需的编码器和加密器。

    Returns:
        dict: 独立映射，包含加密的坐标、VR_ID 列表和映射关系。
    """
    independent_mappings = {}

    # 遍历每一行的数据
    for vr_id, data in point_and_neighbors_coords_dict.items():
        # 初始化当前行的存储
        first_coordinates_list = []  # 存储第一个坐标值 (x)
        second_coordinates_list = []  # 存储第二个坐标值 (y)
        vr_ids_list = []       # 存储 VR_ID
        coordinate_to_vr_id = {}  # 坐标到 VR_ID 的映射

        # 当前点的坐标
        coord = data['Coordinates']  # 直接使用元组 (x, y)
        first_coordinates_list.append(coord[0])  # 添加第一个坐标值 (x)
        second_coordinates_list.append(coord[1])  # 添加第二个坐标值 (y)
        vr_ids_list.append(vr_id)
        coordinate_to_vr_id[tuple(coord)] = vr_id  # 添加到映射
        # 遍历邻居
        for neighbor_vr_id, neighbor_coord in data['Neighbors'].items():
            if tuple(neighbor_coord) not in coordinate_to_vr_id:  # 确保不重复添加
                first_coordinates_list.append(neighbor_coord[0])  # 添加邻居的第一个坐标值 (x)
                second_coordinates_list.append(neighbor_coord[1])  # 添加邻居的第二个坐标值 (y)
                vr_ids_list.append(neighbor_vr_id)
                coordinate_to_vr_id[tuple(neighbor_coord)] = neighbor_vr_id  # 转换为 tuple


        # 加密第一个和第二个坐标列表
        plain_data_first = ckks.encoder.encode(first_coordinates_list, ckks.scale)  # 编码加密
        enc_data_first = ckks.encryptor.encrypt(plain_data_first).save()

        plain_data_second = ckks.encoder.encode(second_coordinates_list, ckks.scale)  # 编码加密
        enc_data_second = ckks.encryptor.encrypt(plain_data_second).save()

        # 存储当前行的独立映射
        independent_mappings[vr_id] = {
            "First Coordinates List": enc_data_first,
            "Second Coordinates List": enc_data_second,
            "VR_IDs List": vr_ids_list
            # "Coordinate to VR_ID Mapping": coordinate_to_vr_id
        }

    return independent_mappings

# 使用示例
# independent_mappings = generate_independent_mappings(point_and_neighbors_coords_dict, ckks)
# print(independent_mappings)



############# 后面两个表
# Initialize mappings
def generate_all_mappings(all_related_coords_dict, ckks):
    """
    根据 all_related_coords_dict 和 CKKS 对象生成加密的全局映射。

    Args:
        all_related_coords_dict (dict): 包含每个点及其所有关联坐标的字典。
        ckks (object): CKKS 加密对象，包含加密所需的编码器和加密器。

    Returns:
        dict: 全局映射，包含加密的坐标、VR_ID 列表和映射关系。
    """
    all_mappings = {}

    # 遍历每一行的数据
    for vr_id, coord_data in all_related_coords_dict.items():
        # 提取坐标和 VR_IDs
        unique_coordinates = list(coord_data.values())
        unique_vr_ids = list(coord_data.keys())

        # 初始化存储
        first_coordinates_list = []  # 存储第一个坐标值 (x)
        second_coordinates_list = []  # 存储第二个坐标值 (y)
        flattened_vr_ids = []  # 存储 VR_IDs
        coordinate_to_vr_id = {}  # 坐标到 VR_ID 的映射
        seen_coords = set()

        # 去重并构建映射
        for i, coord in enumerate(unique_coordinates):
            if tuple(coord) not in seen_coords:
                first_coordinates_list.append(coord[0])  # 添加第一个坐标值 (x)
                second_coordinates_list.append(coord[1])  # 添加第二个坐标值 (y)
                flattened_vr_ids.append(unique_vr_ids[i])
                coordinate_to_vr_id[tuple(coord)] = unique_vr_ids[i]  # 添加到映射
                seen_coords.add(tuple(coord))

        # 加密第一个和第二个坐标列表
        plain_data_first = ckks.encoder.encode(first_coordinates_list, ckks.scale)  # 编码加密
        enc_data_first = ckks.encryptor.encrypt(plain_data_first).save()

        plain_data_second = ckks.encoder.encode(second_coordinates_list, ckks.scale)  # 编码加密
        enc_data_second = ckks.encryptor.encrypt(plain_data_second).save()

        # 存储结果
        all_mappings[vr_id] = {
            "First Coordinates List": enc_data_first,
            "Second Coordinates List": enc_data_second,
            "VR_IDs List": flattened_vr_ids
            # "Coordinate to VR_ID Mapping": coordinate_to_vr_id
        }

    return all_mappings


# Initialize mappings
def generate_final_mappings(final_related_coords_dict, ckks):
    """
    根据 final_related_coords_dict 和 CKKS 对象生成加密的最终映射。

    Args:
        final_related_coords_dict (dict): 包含每个点及其所有关联坐标的字典。
        ckks (object): CKKS 加密对象，包含加密所需的编码器和加密器。

    Returns:
        dict: 最终映射，包含加密的坐标、VR_ID 列表和映射关系。
    """
    final_mappings = {}

    # 遍历每一行的数据
    for vr_id, coord_data in final_related_coords_dict.items():
        # 提取坐标和 VR_IDs
        unique_coordinates = list(coord_data.values())
        unique_vr_ids = list(coord_data.keys())

        # 初始化存储
        first_coordinates_list = []  # 存储第一个坐标值 (x)
        second_coordinates_list = []  # 存储第二个坐标值 (y)
        flattened_vr_ids = []  # 存储 VR_IDs
        coordinate_to_vr_id = {}  # 坐标到 VR_ID 的映射
        seen_coords = set()

        # 去重并构建映射
        for i, coord in enumerate(unique_coordinates):
            if tuple(coord) not in seen_coords:
                first_coordinates_list.append(coord[0])  # 添加第一个坐标值 (x)
                second_coordinates_list.append(coord[1])  # 添加第二个坐标值 (y)
                flattened_vr_ids.append(unique_vr_ids[i])
                coordinate_to_vr_id[tuple(coord)] = unique_vr_ids[i]  # 添加到映射
                seen_coords.add(tuple(coord))

        # 加密第一个和第二个坐标列表
        plain_data_first = ckks.encoder.encode(first_coordinates_list, ckks.scale)  # 编码加密
        enc_data_first = ckks.encryptor.encrypt(plain_data_first).save()

        plain_data_second = ckks.encoder.encode(second_coordinates_list, ckks.scale)  # 编码加密
        enc_data_second = ckks.encryptor.encrypt(plain_data_second).save()

        # 存储结果
        final_mappings[vr_id] = {
            "First Coordinates List": enc_data_first,
            "Second Coordinates List": enc_data_second,
            "VR_IDs List": flattened_vr_ids
            # "Coordinate to VR_ID Mapping": coordinate_to_vr_id
        }

    return final_mappings


def bounded_voronoi(bnd, pnts):
    """
    计算并绘制有界的 Voronoi 图的函数
    """

    # 为了使所有母点的 Voronoi 区域有限，添加 3 个虚拟母点
    gn_pnts = np.concatenate([pnts, np.array([[100, 100], [100, -100], [-100, 0]])])

    # 计算 Voronoi 图
    vor = Voronoi(gn_pnts)

    # 将划分区域转换为 Polygon 对象
    bnd_poly = Polygon(bnd)

    # 用于存储各 Voronoi 区域的列表
    vor_polys = []

    # 遍历除虚拟点外的母点
    for i in range(len(gn_pnts) - 3):

        # 不考虑闭空间的 Voronoi 区域
        vor_poly = [vor.vertices[v] for v in vor.regions[vor.point_region[i]]]
        # 计算划分区域与 Voronoi 区域的交集
        i_cell = bnd_poly.intersection(Polygon(vor_poly))

        # 存储考虑闭空间的 Voronoi 区域的顶点坐标
        if not i_cell.is_empty:
            vor_polys.append((i, i_cell))  # 存储索引和裁剪后的多边形

    return vor_polys, vor


def get_deep_neighbors_coords(vr_id, depth, vr_neighbors, visited=None):
    if visited is None:
        visited = set()
    if depth == 0 or vr_id in visited:
        return {}

    visited.add(vr_id)

    # 获取当前点的直接邻居
    current_row = next((r for r in vr_neighbors if r["VR_ID"] == vr_id), None)
    if not current_row or current_row["Neighbor_VRs"] == "None":
        return {}

    neighbors = current_row["Neighbor_VRs"].split(",")
    neighbors_coords = {
        neighbor: next((r["Coordinates"] for r in vr_neighbors if r["VR_ID"] == neighbor), None) for neighbor in neighbors
    }
    neighbors_coords = {k: v for k, v in neighbors_coords.items() if v is not None}  # 去掉 None

    # 递归获取更深层的邻居 Coordinates
    for neighbor in neighbors:
        deeper_neighbors_coords = get_deep_neighbors_coords(neighbor, depth - 1, vr_neighbors, visited)
        neighbors_coords.update(deeper_neighbors_coords)

    return neighbors_coords





# # Step 1: 设置边界和种子点
# np.random.seed(45)
# boundary = np.array([[0, 0], [1, 0], [1, 1], [0, 1]])  # 定义 1x1 的矩形边界
# file_path = "../Data/normalized_array.npy"  # 替换为您的文件路径
# loaded_data = np.load(file_path)
# # points = np.random.rand(20, 2)  # 生成 20 个随机点，范围在 [0, 1] 内

# points=loaded_data
# points = np.round(points, N)
# # Step 2: 计算有界 Voronoi 图
# vor_polys, vor = bounded_voronoi(boundary, points)
# # print("vor_polys",vor_polys)
# # Step 3: 定义网格并分割
# grid_size = 0.1  # 网格大小为 0.2x0.2
# x_min, x_max = 0, 1
# y_min, y_max = 0, 1
# x_coords = np.arange(x_min, x_max + grid_size, grid_size)
# y_coords = np.arange(y_min, y_max + grid_size, grid_size)

# cell_voronoi_mapping = []
# cell_id_grid_box_mapping = {}

# # 遍历网格单元
# for gx in range(len(x_coords) - 1):
#     for gy in range(len(y_coords) - 1):
#         # 获取网格单元的边界
#         grid_x_min, grid_x_max = x_coords[gx], x_coords[gx + 1]
#         grid_y_min, grid_y_max = y_coords[gy], y_coords[gy + 1]
#         cell_box = box(grid_x_min, grid_y_min, grid_x_max, grid_y_max)  # 构造网格单元
#         cell_id = gx * (len(y_coords) - 1) + gy + 1

#         # 找出与当前网格单元相交的 Voronoi 区域
#         vr_in_cell = [
#             f"V{i+1}" for i, poly in vor_polys if cell_box.intersects(poly)
#         ]  # 列表推导式代替循环判断

#         # 添加到 cell_voronoi_mapping
#         rounded_bounds = tuple(round(coord, 2) for coord in cell_box.bounds)
#         cell_voronoi_mapping.append({
#             "Cell_ID": cell_id,
#             "Grid_Box": rounded_bounds,
#             "VRs": ",".join(vr_in_cell) if vr_in_cell else "None"
#         })

#         # 添加到 cell_id_grid_box_mapping
#         cell_id_grid_box_mapping[cell_id] = cell_box.bounds

# # print("cell_voronoi_mapping",cell_voronoi_mapping)

# max_length = max(len(cell["VRs"].split(",")) for cell in cell_voronoi_mapping if cell["VRs"] != "None")+2

# # Step 2: 填充随机点，使每行的 VRs 达到最大长度
# new_points_data = []  # 用于存储新增点的详细信息

# for cell in cell_voronoi_mapping:
#     existing_vrs = cell["VRs"].split(",") if cell["VRs"] != "None" else []
#     current_length = len(existing_vrs)

#     # 如果当前长度小于最大长度，填充随机点
#     if current_length < max_length:
#         num_new_points = max_length - current_length
#         new_points = [f"V{np.random.randint(21, 50)}" for _ in range(num_new_points)]
#         updated_vrs = existing_vrs + new_points
#         cell["VRs"] = ",".join(updated_vrs)

#         # 为新点生成随机坐标
#         for new_vr in new_points:
#             coord = (round(np.random.uniform(1, 2), N), round(np.random.uniform(1, 2),N))
#             new_points_data.append({
#                 "VR_ID": new_vr,
#                 "Coordinates": coord,
#                 "Neighbor_VRs": "",
#             })


# # Step 4: 构建 VR 和邻居的关系表
# vr_neighbors = []
# for i, poly1 in vor_polys:
#     neighbors = []
#     for j, poly2 in vor_polys:
#         if i != j and poly1.intersects(poly2):  # 如果两个多边形相交，则是邻居
#             neighbors.append(f"V{j+1}")
#     vr_neighbors.append({
#         "VR_ID": f"V{i+1}",
#         "Coordinates": tuple(points[i]),
#         "Neighbor_VRs": ",".join(neighbors) if neighbors else "None"
#     })

# # Step 2: Adding new points to vr_neighbors
# processed_vr_ids = set(vr["VR_ID"] for vr in vr_neighbors)  # 跟踪已有的 VR_ID

# for new_point in new_points_data:
#     if new_point["VR_ID"] in processed_vr_ids:  # 检查是否已处理过
#         continue  # 如果已处理，跳过此点

#     num_neighbors = np.random.randint(1, 4)
#     existing_ids = [vr["VR_ID"] for vr in vr_neighbors]
#     neighbors = np.random.choice(existing_ids, num_neighbors, replace=False).tolist()

#     new_point["Neighbor_VRs"] = ",".join(neighbors)  # 保留原始顺序
#     processed_vr_ids.add(new_point["VR_ID"])  # 标记此点为已处理
#     vr_neighbors.append(new_point)  # 添加到 vr_neighbors

# # 初始化一个集合，跟踪处理过的 VR_ID
# processed_vr_ids = set(vr["VR_ID"] for vr in vr_neighbors)

# # 遍历现有的 vr_neighbors 并随机添加新邻居
# for vr in vr_neighbors:
#     if vr["VR_ID"] not in processed_vr_ids:  # 确保未重复处理
#         processed_vr_ids.add(vr["VR_ID"])  # 标记为已处理

#         # 50% 概率添加新邻居
#         if np.random.rand() > 0.5:
#             num_new_neighbors = np.random.randint(1, 3)  # 随机生成 1-2 个新邻居
#             new_neighbors = [f"V{np.random.randint(21, 50)}" for _ in range(num_new_neighbors)]

#             # 保证新邻居唯一性，且不重复出现在现有邻居中
#             unique_new_neighbors = [
#                 neighbor for neighbor in new_neighbors 
#                 if neighbor not in vr["Neighbor_VRs"].split(",")  # 检查是否已存在
#             ]

#             # 为每个新邻居生成随机坐标，并更新 vr_neighbors
#             for new_neighbor in unique_new_neighbors:
#                 coord = (round(np.random.uniform(1, 2),N), round(np.random.uniform(1, 2),N))
#                 vr_neighbors.append({
#                     "VR_ID": new_neighbor,
#                     "Coordinates": coord,
#                     "Neighbor_VRs": ""  # 不计算距离或排序
#                 })

#                 # 直接追加新邻居
#                 if vr["Neighbor_VRs"]:
#                     vr["Neighbor_VRs"] += f",{new_neighbor}"
#                 else:
#                     vr["Neighbor_VRs"] = new_neighbor



# # 初始化两个字典和一个新的字典
# point_and_neighbors_coords_dict = {}  # 存储当前点和邻居的 Coordinates
# all_related_coords_dict = {}  # 存储当前点、邻居和邻居的邻居的 Coordinates（去重）
# final_related_coords_dict = {}  # 存储当前点、邻居、邻居的邻居以及再往下的 Coordinates（去重）

# # Helper function: 获取指定深度的邻居的 Coordinates


# # 遍历 vr_neighbors，提取数据
# for vr in vr_neighbors:
#     current_point_id = vr["VR_ID"]  # 当前点的 VR_ID
#     current_point_coords = vr["Coordinates"]  # 当前点的 Coordinates
#     neighbors = vr["Neighbor_VRs"].split(",") if vr["Neighbor_VRs"] != "None" else []

#     # Step 1: 当前点和邻居的 Coordinates
#     neighbors_coords = {
#         neighbor: next((r["Coordinates"] for r in vr_neighbors if r["VR_ID"] == neighbor), None) for neighbor in neighbors
#     }
#     neighbors_coords = {k: v for k, v in neighbors_coords.items() if v is not None}  # 去掉 None
#     point_and_neighbors_coords_dict[current_point_id] = {
#         "Coordinates": current_point_coords,
#         "Neighbors": neighbors_coords
#     }

#     # Step 2: 当前点、邻居和邻居的邻居的 Coordinates
#     all_coords_dict = {current_point_id: current_point_coords}  # 存储当前点的 Coordinates
#     all_coords_dict.update(neighbors_coords)  # 添加邻居的 Coordinates

#     for neighbor in neighbors:
#         neighbor_row = next((r for r in vr_neighbors if r["VR_ID"] == neighbor), None)
#         if neighbor_row:
#             neighbor_neighbors = neighbor_row["Neighbor_VRs"].split(",") if neighbor_row["Neighbor_VRs"] != "None" else []
#             for nn in neighbor_neighbors:
#                 nn_coord = next((r["Coordinates"] for r in vr_neighbors if r["VR_ID"] == nn), None)
#                 if nn_coord:
#                     all_coords_dict[nn] = nn_coord

#     all_related_coords_dict[current_point_id] = all_coords_dict

#     # Step 3: 当前点及递归深度范围内的所有 Coordinates
#     depth = 3  # 递归深度
#     final_coords_dict = get_deep_neighbors_coords(current_point_id, depth, vr_neighbors)
#     final_coords_dict[current_point_id] = current_point_coords  # 添加当前点的 Coordinates
#     final_related_coords_dict[current_point_id] = final_coords_dict

# #输出结果
# print("Point and Neighbors' Coordinates (Dictionary):", point_and_neighbors_coords_dict)
# print("All Related Coordinates (Dictionary):", all_related_coords_dict)
# print("Final Related Coordinates (Dictionary):", final_related_coords_dict)

# print("cell_voronoi_mapping",cell_voronoi_mapping)
# print()
# print("vr_neighbors",vr_neighbors)




# import json
# import os

# # 设置保存目录为挂载点下的一个子目录
# save_directory = "/mnt/4b5da12c-2706-4084-b917-64a73ebd2641/my_project"

# # 确保保存目录存在，如果不存在则创建
# os.makedirs(save_directory, exist_ok=True)

# # 保存并打印路径的函数
# def save_and_print(data, filename):
#     file_path = os.path.join(save_directory, filename)
#     with open(file_path, "w") as f:
#         json.dump(data, f, indent=4)
#     print(f"Saved {filename} to {file_path}")

# # 保存 point_and_neighbors_coords_dict
# save_and_print(point_and_neighbors_coords_dict, "point_and_neighbors_coords_dict.json")

# # 保存 all_related_coords_dict
# save_and_print(all_related_coords_dict, "all_related_coords_dict.json")

# # 保存 final_related_coords_dict
# save_and_print(final_related_coords_dict, "final_related_coords_dict.json")

# # 保存 cell_voronoi_mapping
# save_and_print(cell_voronoi_mapping, "cell_voronoi_mapping.json")

# # 保存 vr_neighbors
# save_and_print(vr_neighbors, "vr_neighbors.json")





import json

save_directory = "/mnt/4b5da12c-2706-4084-b917-64a73ebd2641/my_project"

# 读取并打印 JSON 数据的函数
def load_and_print(filename):
    file_path = os.path.join(save_directory, filename)
    with open(file_path, "r") as f:
        data = json.load(f)
    print(f"Loaded {filename} from {file_path}")
    return data

# 读取 point_and_neighbors_coords_dict
point_and_neighbors_coords_dict = load_and_print("point_and_neighbors_coords_dict.json")

# 读取 all_related_coords_dict
all_related_coords_dict = load_and_print("all_related_coords_dict.json")

# 读取 final_related_coords_dict
final_related_coords_dict = load_and_print("final_related_coords_dict.json")

# 读取 cell_voronoi_mapping
cell_voronoi_mapping = load_and_print("cell_voronoi_mapping.json")

# 读取 vr_neighbors
vr_neighbors = load_and_print("vr_neighbors.json")

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
#         self.encryptor = None
#         self.decryptor = None

#     def load_keys(self, directory="keys"):
#         # 加载密钥
#         public_key_path = f"{directory}/public_key.pkl"
#         print(f"Loading public key from: {public_key_path}")
#         with open(public_key_path, "rb") as f:
#             public_key_data = pickle.load(f)
#         self.public_key.load(public_key_data)


#         with open(f"{directory}/secret_key.pkl", "rb") as f:
#             secret_key_data = pickle.load(f)
#         self.secret_key.load(secret_key_data)

#         # 初始化加密器和解密器
#         self.encryptor = pytroy.Encryptor(self.context, self.public_key)
#         self.decryptor = pytroy.Decryptor(self.context, self.secret_key)
#         self.evaluator = pytroy.Evaluator(self.context)
#         print(f"Keys loaded successfully from {directory}")


# print(2222)
pytroy.initialize_kernel()

ckks=Ckks()
ckks.load_keys()
aes_key = open("../Data/AES_key.bin", 'rb').read()
print(1111)
vr_id_to_coordinates=process_and_encrypt_coordinates_aes(vr_neighbors, aes_key)

##vr_id_to_coordinates = process_and_encrypt_coordinates(vr_neighbors, ckks)
grid_mappings = generate_grid_mappings(cell_voronoi_mapping, vr_neighbors, ckks)
independent_mappings = generate_independent_mappings(point_and_neighbors_coords_dict, ckks)
all_mappings = generate_all_mappings(all_related_coords_dict, ckks)
final_mappings = generate_final_mappings(final_related_coords_dict, ckks)
splits_dict = split_and_encrypt_voronoi_data(cell_voronoi_mapping, num_splits=10, randomness_factor=0.2)

# # 如果文件夹不存在，创建它
data_dir = os.path.expanduser("../Data")

if not os.path.exists(data_dir):
    os.makedirs(data_dir)

save_mappings_to_file(vr_id_to_coordinates, os.path.join(data_dir, 'vr_id_to_coordinates_AES.pkl'))
save_mappings_to_file(grid_mappings, os.path.join(data_dir, 'grid_mappings.pkl'))
save_mappings_to_file(independent_mappings, os.path.join(data_dir, 'independent_mappings.pkl'))
save_mappings_to_file(all_mappings, os.path.join(data_dir, 'all_mappings.pkl'))
save_mappings_to_file(final_mappings, os.path.join(data_dir, 'final_mappings.pkl'))
save_mappings_to_file(splits_dict, os.path.join(data_dir, 'test_splits_dict.pkl'))
# ##encrypt_and_save_cell_id_grid_box_mapping(cell_id_grid_box_mapping,ckks,'cell_id_grid_box_mapping.pkl')

