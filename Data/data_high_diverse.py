import numpy as np
import matplotlib.pyplot as plt
from matplotlib.collections import PolyCollection
from matplotlib.patches import Rectangle
from scipy.spatial import Voronoi
from shapely.geometry import Polygon, boxxx
import pandas as pd
from scipy.spatial.distance import euclidean
import pickle
from setup import Ckks
import random
import math
from Crypto.Cipher import AES
import base64
from Crypto.Util.Padding import pad, unpad

####ID:::Coordinates

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

###分割表
def split_and_encrypt_voronoi_data(cell_voronoi_mapping, num_splits=5):
    """
    将 cell_voronoi_mapping 划分为指定数量的份，并对每个分割的 Grid_Box List 进行加密。
    
    参数：
    cell_voronoi_mapping (list): 包含 'Cell_ID', 'Grid_Box', 'VRs' 信息的列表
    num_splits (int): 分割的数量，默认为 5
    
    返回：
    dict: 每个分割的数据，包括 'Cell_IDs', 'VRs', 'Grid_Box List'（加密后的 Grid_Box List）
    """
    total_length = len(cell_voronoi_mapping)

    # 初始化分割
    split_sizes = []
    remaining_length = total_length
    for i in range(num_splits - 1):
        max_size = remaining_length - (num_splits - len(split_sizes) - 1)
        size = random.randint(1, max_size)  # 确保每份至少有 1 个元素
        split_sizes.append(size)
        remaining_length -= size

    # 最后一份分配剩余长度
    split_sizes.append(remaining_length)
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
            current_grid_box = list(item['Grid_Box']) # 转换为列表以便修改

            current_length = len(current_grid_box)

            if current_length == 0:
                # 如果 Grid_Box 为空，可以直接extend，或者根据需求补齐到2^0=1
                # 这里选择不补，直接extend，因为2^0=1的补齐可能不符合实际用途
                pass 
            else:
                # 找到大于等于 current_length 的最小的 2 的 n 次方
                # 例如：
                # 如果 current_length = 3，log2(3) = 1.58 -> ceil(1.58) = 2 -> 2^2 = 4 (补1个0)
                # 如果 current_length = 8，log2(8) = 3.0 -> ceil(3.0) = 3 -> 2^3 = 8 (不补)
                next_power_of_2 = 2**math.ceil(math.log2(current_length))
                padding_needed = next_power_of_2 - current_length

                if padding_needed > 0:
                    # 添加所需数量的零
                    current_grid_box.extend([0] * padding_needed)

            # 现在，current_grid_box 已经补齐到 2 的 n 次方，可以安全地 extend 了
            split_info['Grid_Box List'].extend(current_grid_box)
        
        # 编码并加密 Grid_Box List
        plain_data_total = ckks.ckks_encoder.encode(split_info['Grid_Box List'], ckks.scale)  # 编码加密
        enc_data_total = ckks.encryptor.encrypt(plain_data_total)
        split_info['Grid_Box List'] = enc_data_total.save()  # 保存加密数据

        # 将每个分割的所有格子相关信息存储到 splits_dict
        splits_dict[i+1] = split_info

    return splits_dict




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
        processed_coordinates = coordinates
        
        # 编码加密
        plain_data = ckks.ckks_encoder.encode(processed_coordinates, ckks.scale)
        enc_data = ckks.encryptor.encrypt(plain_data).save()
        
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

    # 遍历 cell_voronoi_mapping 并处理
    for cell in cell_voronoi_mapping:
        cell_id = cell.get("Cell_ID")
        vr_list = cell.get("VRs", "").split(",") if cell.get("VRs") != "None" else []

        # 提取 VRs 和对应的 Coordinates
        vr_coords_mapping = {vr: vr_coordinates_dict.get(vr, "None") for vr in vr_list}

        #### 初始化当前行的存储
        coordinates_list = []  # 存储每个坐标的第一个值
        # second_coordinates_list = []  # 存储每个坐标的第二个值
        vr_ids_list = []       # VR_ID 列表
        # coordinate_to_vr_id = {}  # 坐标到 VR_ID 的映射

        # 遍历当前行的键值对
        for vr_id, coord in vr_coords_mapping.items():
            if coord == "None":
                continue
            coordinates_list.original_list.extend(coord)

            # 扁平化添加坐标
            # first_coordinates_list.append(coord[0])
            # second_coordinates_list.append(coord[1])
            # 添加 VR_ID
            vr_ids_list.append(vr_id)
            # 建立坐标到 VR_ID 的映射
            # coordinate_to_vr_id[coord] = vr_id
        vr_ids_list+=[100]*(2048-len(vr_ids_list))
        # 编码加密
        # plain_data_first = ckks.ckks_encoder.encode(first_coordinates_list, ckks.scale)
        # enc_data_first = ckks.encryptor.encrypt(plain_data_first).save()

        plain_data = ckks.ckks_encoder.encode(coordinates_list, ckks.scale)
        enc_data = ckks.encryptor.encrypt(plain_data).save()

        # 存储当前行的独立映射
        grid_mappings[cell_id] = {
            "Coordinates List": enc_data,
            # "Second Coordinates List": enc_data_second,
            "VR_IDs List": vr_ids_list
            # "Coordinate to VR_ID Mapping": coordinate_to_vr_id
        }

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
        first_coordinates = []  # 存储第一个坐标值 (x)
        vr_ids_list = []       # 存储 VR_ID
        coordinate_to_vr_id = {}  # 坐标到 VR_ID 的映射

        # 当前点的坐标
        coord = data['Coordinates']  # 直接使用元组 (x, y)
        first_coordinates.extend(coord)  # 添加第一个坐标值 (x)
        vr_ids_list.append(vr_id)
        coordinate_to_vr_id[coord] = vr_id  # 添加到映射

        # 遍历邻居
        for neighbor_vr_id, neighbor_coord in data['Neighbors'].items():
            if neighbor_coord not in coordinate_to_vr_id:  # 确保不重复添加
                first_coordinates.extend(neighbor_coord)  # 添加邻居的第一个坐标值 (x)
                vr_ids_list.append(neighbor_vr_id)
                coordinate_to_vr_id[neighbor_coord] = neighbor_vr_id

        # 加密第一个和第二个坐标列表
        plain_data_first = ckks.ckks_encoder.encode(first_coordinates, ckks.scale)  # 编码加密
        enc_data_first = ckks.encryptor.encrypt(plain_data_first).save()



        # 存储当前行的独立映射
        independent_mappings[vr_id] = {
            "Coordinates List": enc_data_first,
            "VR_IDs List": vr_ids_list
            # "Coordinate to VR_ID Mapping": coordinate_to_vr_id
        }

    return independent_mappings




import numpy as np
from collections import defaultdict
from sklearn.neighbors import NearestNeighbors
import os
import pickle # Import pickle module

# --- Helper function to save mappings (as requested by user) ---
def save_mappings_to_file(data_to_save, filename):
    """
    将字典数据保存到指定文件 (使用 pickle)。
    
    Args:
        data_to_save (dict): 需要保存的字典数据。
        filename (str): 文件名，保存数据的路径。
    """
    with open(filename, 'wb') as pickle_file:
        pickle.dump(data_to_save, pickle_file)
    print(f"数据已保存到 '{filename}'。")

# --- 设置文件路径和d值 ---
output_dir = "mnist_experiment_data" # MNIST实验数据的保存目录
d_value = 40 # MNIST实验中明确的模型向量数量 d=40
step_size = 0.1 # 每个维度切分成 10 段 (1 / 0.1 = 10)

# --- Voronoi 映射相关参数 ---
# 直接使用所有d个模型向量作为Voronoi种子点
# 第三层索引深度：只保存当前点和第一层深度的邻居
num_voronoi_neighbors_to_map = 5 # 仅考虑每个VR的1个最近邻作为其“第一层深度邻居”

print("--- 准备数据和索引构建 (MNIST数据集) ---")

# --- 加载MNIST数据集的模型向量 ---
model_vectors_filename = os.path.join(output_dir, f"X_model_d{d_value}.npy")
model_labels_filename = os.path.join(output_dir, f"y_model_d{d_value}.npy")

try:
    X_model_current = np.load(model_vectors_filename)
    y_model_current = np.load(model_labels_filename)
    print(f"\n--- 正在处理 d={d_value} 的MNIST模型向量集 ---")
    print(f"成功加载 d={d_value} 的模型向量。形状: {X_model_current.shape}")

    # --- 1. 定义网格参数 ---
    gamma = X_model_current.shape[1] # 数据维度 (MNIST是 30 维)
    min_vals = np.zeros(gamma) # 假设数据已缩放到 [0, 1]
    max_vals = np.ones(gamma) # 假设数据已缩放到 [0, 1]
    
    print(f"数据维度 (gamma): {gamma}")
    print(f"每个维度步长: {step_size}")
    print(f"每个维度切分段数: {int(1 / step_size)}")


    # --- 第一层索引构建: 网格划分与边界信息 (grid_cells_info) ---
    # 存储结构: {cell_id_tuple: {'point_indices': [idx1, idx2, ...], 'bounds': (min_corner_array, max_corner_array)}}
    grid_cells_info = {} 

    print(f"\n--- 第一层索引: 网格划分与边界信息 ---")
    for i, point in enumerate(X_model_current):
        grid_indices = []
        for d_idx in range(gamma):
            idx = int(np.floor((point[d_idx] - min_vals[d_idx]) / step_size))
            max_idx_for_dim = int(1 / step_size) - 1 
            if idx > max_idx_for_dim: 
                idx = max_idx_for_dim
            grid_indices.append(idx)
        
        cell_id = tuple(grid_indices)

        if cell_id not in grid_cells_info:
            min_corner = np.array([min_vals[d_idx] + cell_idx * step_size for d_idx, cell_idx in enumerate(cell_id)])
            max_corner = np.array([min_vals[d_idx] + (cell_idx + 1) * step_size for d_idx, cell_idx in enumerate(cell_id)])
            max_corner = np.minimum(max_corner, max_vals)

            grid_cells_info[cell_id] = {
                'point_indices': [],
                'bounds': (min_corner, max_corner)
            }
        grid_cells_info[cell_id]['point_indices'].append(i)

    print(f"发现 {len(grid_cells_info)} 个唯一的被占用的网格单元。")

    # 保存 grid_cells_info (第一层索引的物理存储)
    output_grid_info_filename = os.path.join(output_dir, f"grid_cells_info_d{d_value}.pkl") 
    save_mappings_to_file(grid_cells_info, output_grid_info_filename) 


    # --- 第一层索引: 网格单元到 Voronoi 区域的映射 (cell_voronoi_mapping) ---
    print(f"\n--- 第一层索引: 网格单元到 Voronoi 区域的映射 ---")
    
    # 4.1 选择 Voronoi 种子点: 直接使用所有d个模型向量作为种子点
    voronoi_seed_points = X_model_current
    # VR_ID 就是种子点在 voronoi_seed_points 数组中的索引 (0到d-1)
    
    print(f"  已选择 {d_value} 个Voronoi种子点 (即所有模型向量)。")

    # 4.2 构建NearestNeighbors模型来映射点到VR_ID (每个模型向量到它自己)
    nn_model_for_vr = NearestNeighbors(n_neighbors=1, algorithm='auto').fit(voronoi_seed_points)
    distances, vr_ids_for_points = nn_model_for_vr.kneighbors(X_model_current)
    point_to_vr_id_map = {i: vr_ids_for_points[i][0] for i in range(d_value)}
    print(f"  已将所有 {d_value} 个模型向量映射到最近的Voronoi种子点。")

    # 4.3 构建Voronoi区域邻居映射 (近似)
    # 找到每个种子点在其他种子点中的k个最近邻，作为其邻居VR
    # +1 是因为kneighbors会返回点本身作为第一个邻居
    nn_model_for_vr_neighbors = NearestNeighbors(n_neighbors=num_voronoi_neighbors_to_map + 1, algorithm='auto').fit(voronoi_seed_points)
    distances_neighbors, neighbor_vr_ids = nn_model_for_vr_neighbors.kneighbors(voronoi_seed_points)
    
    voronoi_neighbors_map = {}
    for vr_idx in range(d_value):
        voronoi_neighbors_map[vr_idx] = [n_id for n_id in neighbor_vr_ids[vr_idx] if n_id != vr_idx][:num_voronoi_neighbors_to_map]
    print(f"  已为每个Voronoi种子点构建近似邻居列表 (深度={num_voronoi_neighbors_to_map})。")

    # 4.4 构建 cell_voronoi_mapping 为列表格式 (用户请求的修改)
    cell_voronoi_mapping = []
    cell_counter = 0 # 用于生成从0开始的顺序Cell_ID
    
    # 遍历 grid_cells_info 来获取每个被占用网格单元的 tuple_cell_id 和其 bounds
    for tuple_cell_id, info in grid_cells_info.items():
        # 重新计算 cell_vrs_for_this_cell_id
        cell_vrs_for_this_cell_id = set()
        for p_idx in info['point_indices']:
            vr_id_of_point = point_to_vr_id_map[p_idx]
            cell_vrs_for_this_cell_id.add(int(vr_id_of_point))
            for neighbor_vr in voronoi_neighbors_map.get(vr_id_of_point, []):
                cell_vrs_for_this_cell_id.add(int(neighbor_vr))

        # 获取 Grid_Box (左下角和右上角坐标)
        grid_box_min_corner = info['bounds'][0] # numpy array
        grid_box_max_corner = info['bounds'][1] # numpy array
        
        # --- 按照用户请求的新格式构建 Grid_Box ---
        # 格式: [dim1_min, dim1_max, dim2_min, dim2_max, ..., dim_gamma_min, dim_gamma_max]
        flattened_grid_box = []
        for dim_idx in range(gamma):
            flattened_grid_box.append(grid_box_min_corner[dim_idx])
            flattened_grid_box.append(grid_box_max_corner[dim_idx])

        cell_voronoi_mapping.append({
            'Cell_ID': cell_counter, # 从0开始的顺序整数ID
            'Grid_Box': flattened_grid_box, # 使用新格式
            'VRs': [f"V{vr_id + 1}" for vr_id in sorted(list(cell_vrs_for_this_cell_id))], # 转换为 V{id+1} 格式的列表
        })
        cell_counter += 1
    
    print(f"  已将 {len(cell_voronoi_mapping)} 个被占用的网格单元映射到Voronoi区域 (列表格式)。")

    output_cell_voronoi_map_filename = os.path.join(output_dir, f"cell_voronoi_mapping_d{d_value}.pkl") 
    save_mappings_to_file(cell_voronoi_mapping, output_cell_voronoi_map_filename) 
    
    output_voronoi_seeds_filename = os.path.join(output_dir, f"voronoi_seed_points_d{d_value}.npy") 
    np.save(output_voronoi_seeds_filename, voronoi_seed_points)
    print(f"Voronoi种子点已保存到 '{output_voronoi_seeds_filename}'")


    # --- 第三层索引: 当前点和第一层深度的邻居信息 (point_to_neighbors_info) ---
    print(f"\n--- 第三层索引: 当前点和第一层深度的邻居信息 ---")
    # 将 point_to_neighbors_info 转换为列表形式 (用户请求的修改)
    vr_neighbors = []
    for i in range(d_value):
        vr_id = point_to_vr_id_map[i] # 此时 vr_id 就是 i
        neighbor_vr_ids = voronoi_neighbors_map.get(vr_id, [])
        # neighbor_points_coords = [voronoi_seed_points[n_id] for n_id in neighbor_vr_ids] # 不再直接存储，但可以根据需要重新获取
        
        vr_neighbors.append({
            'VR_ID': f"V{vr_id + 1}", # 对应示例中的 VR_ID
            'Coordinates': tuple(X_model_current[i].tolist()), # 对应示例中的 Coordinates
            'Neighbor_VRs': ",".join([f"V{n_id + 1}" for n_id in neighbor_vr_ids]) if neighbor_vr_ids else "None" # 对应示例中的 Neighbor_VRs
        })

    output_point_neighbors_filename = os.path.join(output_dir, f"point_to_neighbors_info_d{d_value}.pkl") 
    save_mappings_to_file(vr_neighbors, output_point_neighbors_filename) # Using helper function

except FileNotFoundError:
    print(f"\n错误: 无法找到 d={d_value} 的模型向量文件。请确保 '{output_dir}' 目录中存在 '{model_vectors_filename}' 和 '{model_labels_filename}'。")
    print("请先运行MNIST的明文实验代码来生成这些数据。")
except Exception as e:
    print(f"\n处理 d={d_value} 时发生错误: {e}")






max_length = max(len(cell["VRs"].split(",")) for cell in cell_voronoi_mapping if cell["VRs"] != "None")+2

# Step 2: 填充随机点，使每行的 VRs 达到最大长度
new_points_data = []  # 用于存储新增点的详细信息

for cell in cell_voronoi_mapping:
    existing_vrs = cell["VRs"].split(",") if cell["VRs"] != "None" else []
    current_length = len(existing_vrs)

    # 如果当前长度小于最大长度，填充随机点
    if current_length < max_length:
        num_new_points = max_length - current_length
        new_points = [f"V{np.random.randint(21, 50)}" for _ in range(num_new_points)]
        updated_vrs = existing_vrs + new_points
        cell["VRs"] = ",".join(updated_vrs)

        # 为新点生成随机坐标
        for new_vr in new_points:
            coord = (np.random.uniform(1, 2,size=gamma))
            new_points_data.append({
                "VR_ID": new_vr,
                "Coordinates": coord,
                "Neighbor_VRs": "",
            })



processed_vr_ids = set(vr["VR_ID"] for vr in vr_neighbors)  # 跟踪已有的 VR_ID

for new_point in new_points_data:
    if new_point["VR_ID"] in processed_vr_ids:  # 检查是否已处理过
        continue  # 如果已处理，跳过此点

    num_neighbors = np.random.randint(1, 4)
    existing_ids = [vr["VR_ID"] for vr in vr_neighbors]
    neighbors = np.random.choice(existing_ids, num_neighbors, replace=False).tolist()

    new_point["Neighbor_VRs"] = ",".join(neighbors)  # 保留原始顺序
    processed_vr_ids.add(new_point["VR_ID"])  # 标记此点为已处理
    vr_neighbors.append(new_point)  # 添加到 vr_neighbors

# 初始化一个集合，跟踪处理过的 VR_ID
processed_vr_ids = set(vr["VR_ID"] for vr in vr_neighbors)

# 遍历现有的 vr_neighbors 并随机添加新邻居
for vr in vr_neighbors:
    if vr["VR_ID"] not in processed_vr_ids:  # 确保未重复处理
        processed_vr_ids.add(vr["VR_ID"])  # 标记为已处理

        # 50% 概率添加新邻居
        if np.random.rand() > 0.5:
            num_new_neighbors = np.random.randint(1, 3)  # 随机生成 1-2 个新邻居
            new_neighbors = [f"V{np.random.randint(21, 50)}" for _ in range(num_new_neighbors)]

            # 保证新邻居唯一性，且不重复出现在现有邻居中
            unique_new_neighbors = [
                neighbor for neighbor in new_neighbors 
                if neighbor not in vr["Neighbor_VRs"].split(",")  # 检查是否已存在
            ]

            # 为每个新邻居生成随机坐标，并更新 vr_neighbors
            for new_neighbor in unique_new_neighbors:
                coord = (np.random.uniform(1, 2,size=gamma))
                vr_neighbors.append({
                    "VR_ID": new_neighbor,
                    "Coordinates": coord,
                    "Neighbor_VRs": ""  # 不计算距离或排序
                })

                # 直接追加新邻居
                if vr["Neighbor_VRs"]:
                    vr["Neighbor_VRs"] += f",{new_neighbor}"
                else:
                    vr["Neighbor_VRs"] = new_neighbor


# 初始化两个字典和一个新的字典
point_and_neighbors_coords_dict = {}  # 存储当前点和邻居的 Coordinates
all_related_coords_dict = {}  # 存储当前点、邻居和邻居的邻居的 Coordinates（去重）
final_related_coords_dict = {}  # 存储当前点、邻居、邻居的邻居以及再往下的 Coordinates（去重）

# Helper function: 获取指定深度的邻居的 Coordinates
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

# 遍历 vr_neighbors，提取数据
for vr in vr_neighbors:
    current_point_id = vr["VR_ID"]  # 当前点的 VR_ID
    current_point_coords = vr["Coordinates"]  # 当前点的 Coordinates
    neighbors = vr["Neighbor_VRs"].split(",") if vr["Neighbor_VRs"] != "None" else []

    # Step 1: 当前点和邻居的 Coordinates
    neighbors_coords = {
        neighbor: next((r["Coordinates"] for r in vr_neighbors if r["VR_ID"] == neighbor), None) for neighbor in neighbors
    }
    neighbors_coords = {k: v for k, v in neighbors_coords.items() if v is not None}  # 去掉 None
    point_and_neighbors_coords_dict[current_point_id] = {
        "Coordinates": current_point_coords,
        "Neighbors": neighbors_coords
    }

    # Step 2: 当前点、邻居和邻居的邻居的 Coordinates
    all_coords_dict = {current_point_id: current_point_coords}  # 存储当前点的 Coordinates
    all_coords_dict.update(neighbors_coords)  # 添加邻居的 Coordinates

    for neighbor in neighbors:
        neighbor_row = next((r for r in vr_neighbors if r["VR_ID"] == neighbor), None)
        if neighbor_row:
            neighbor_neighbors = neighbor_row["Neighbor_VRs"].split(",") if neighbor_row["Neighbor_VRs"] != "None" else []
            for nn in neighbor_neighbors:
                nn_coord = next((r["Coordinates"] for r in vr_neighbors if r["VR_ID"] == nn), None)
                if nn_coord:
                    all_coords_dict[nn] = nn_coord

    all_related_coords_dict[current_point_id] = all_coords_dict

    # Step 3: 当前点及递归深度范围内的所有 Coordinates
    depth = 3  # 递归深度
    final_coords_dict = get_deep_neighbors_coords(current_point_id, depth, vr_neighbors)
    final_coords_dict[current_point_id] = current_point_coords  # 添加当前点的 Coordinates
    final_related_coords_dict[current_point_id] = final_coords_dict


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

# 输出结果
print("Point and Neighbors' Coordinates (Dictionary):", point_and_neighbors_coords_dict)
print("All Related Coordinates (Dictionary):", all_related_coords_dict)
print("Final Related Coordinates (Dictionary):", final_related_coords_dict)

print(cell_voronoi_mapping)
print()
print(vr_neighbors)
ckks=Ckks()
ckks.load_keys()
aes_key = open("../Data/AES_key.bin", 'rb').read()


vr_id_to_coordinates=process_and_encrypt_coordinates_aes(vr_neighbors, aes_key)


grid_mappings = generate_grid_mappings(cell_voronoi_mapping, vr_neighbors, ckks)
independent_mappings = generate_independent_mappings(point_and_neighbors_coords_dict, ckks)
# all_mappings = generate_all_mappings(all_related_coords_dict, ckks)
# final_mappings = generate_final_mappings(final_related_coords_dict, ckks)
splits_dict = split_and_encrypt_voronoi_data(cell_voronoi_mapping, num_splits=5)

save_mappings_to_file(vr_id_to_coordinates, f'vr_id_to_coordinates_AES{d_value}.pkl')
save_mappings_to_file(grid_mappings, f'grid_mappings{d_value}.pkl')
save_mappings_to_file(independent_mappings, f'independent_mappings{d_value}.pkl')
# save_mappings_to_file(all_mappings, 'all_mappings.pkl')
# save_mappings_to_file(final_mappings, 'final_mappings.pkl')
save_mappings_to_file(splits_dict, f'splits_dict{d_value}.pkl')


