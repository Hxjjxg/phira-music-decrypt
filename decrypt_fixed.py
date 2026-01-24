import os

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False
    print("警告: 未安装 zstandard 库，无法解压。请运行: pip install zstandard")


def decrypt_block(block):
    """解密一个8字节块"""
    v11 = bytearray(block)
    
    # === 步骤1: 初始交换 (IDA: 0x7ff7e27f428b - 0x7ff7e27f42bd) ===
    # 交换 v11[1] 和 v11[4]
    v11[1], v11[4] = v11[4], v11[1]
    # 交换 v11[2] 和 v11[6]
    v11[2], v11[6] = v11[6], v11[2]
    
    # === 步骤2: 位反转置换 (IDA: 0x7ff7e27f42d8 - 0x7ff7e27f4318) ===
    # 这是一个原地交换，只有当 i < target 时才交换
    for i in range(8):
        # ROL bl, 4 (左循环移位4位)
        bl = ((i << 4) | (i >> 4)) & 0xFF
        
        # 第一次变换: (bl & 0x33) << 2 | (bl >> 2) & 0x33
        temp1 = ((bl & 0x33) << 2) | ((bl >> 2) & 0x33)
        
        # 第二次变换: (temp1 & 0x50) << 1 | (temp1 >> 1) & 0x40
        temp2 = ((temp1 & 0x50) << 1) | ((temp1 >> 1) & 0x40)
        
        # 右移5位得到目标索引
        target = temp2 >> 5
        
        # 只在 i < target 时交换（避免重复交换）
        if i < target:
            v11[i], v11[target] = v11[target], v11[i]
    
    # === 步骤3: 三层蝴蝶减法 (IDA: 0x7ff7e27f4341 - 0x7ff7e27f443c) ===
    
    # 第一层: v11[i|1] -= v11[i], 对于 i = 0, 2, 4, 6
    # 注意循环逻辑：i=0, 然后 i=2, 4, 6
    for i in range(0, 8, 2):
        v11[i | 1] = (v11[i | 1] - v11[i]) & 0xFF
    
    # 第二层: v11[i|2] -= v11[i], v11[i|3] -= v11[i|1], 对于 i = 0, 4
    for i in range(0, 8, 4):
        v11[i | 2] = (v11[i | 2] - v11[i]) & 0xFF
        v11[i | 3] = (v11[i | 3] - v11[i | 1]) & 0xFF
    
    # 第三层: 对于 i = 0 (只执行一次)
    # v11[4] -= v11[0], v11[5] -= v11[1], v11[6] -= v11[2], v11[7] -= v11[3]
    v11[4] = (v11[4] - v11[0]) & 0xFF
    v11[5] = (v11[5] - v11[1]) & 0xFF
    v11[6] = (v11[6] - v11[2]) & 0xFF
    v11[7] = (v11[7] - v11[3]) & 0xFF
    
    # === 步骤4: 结尾交换 (IDA: 0x7ff7e27f4250 - 0x7ff7e27f425b) ===
    # 交换 v11[3] 和 v11[5]
    v11[3], v11[5] = v11[5], v11[3]
    
    return bytes(v11)


def phira_bgm_decrypt(input_path, output_path):
    """解密Phira BGM文件"""
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    size = len(data)
    print(f"原始文件大小: {size} 字节")
    
    # 每8字节为一个块进行解密
    block_count = size // 8
    for i in range(block_count):
        offset = i * 8
        data[offset:offset + 8] = decrypt_block(data[offset:offset + 8])
    
    # 尾部长度修正 (IDA: 0x7ff7e27f4463 - 0x7ff7e27f4475)
    # v30 = v3 + (unsigned __int8)v5[v3 - 1] - 8
    # 即: new_size = original_size + last_byte - 8
    if size > 0:
        last_byte = data[size - 1]
        new_size = size + last_byte - 8
        
        print(f"最后一字节 (padding): {last_byte}")
        print(f"计算后大小: {new_size} 字节")
        
        # 只有当 original_size >= new_size 时才截断
        if size >= new_size and new_size > 0:
            data = data[:new_size]
            print(f"已截断到: {new_size} 字节")
    
    # 保存解密后的文件
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"解密完成: {output_path}")
    
    # 检查是否是 zstd 压缩数据 (魔数: 28 B5 2F FD)
    if len(data) >= 4 and data[0:4] == b'\x28\xb5\x2f\xfd':
        print("检测到 Zstandard 压缩数据，正在解压...")
        if HAS_ZSTD:
            try:
                dctx = zstd.ZstdDecompressor()
                # 使用流式解压，因为可能没有内容大小信息
                reader = dctx.stream_reader(bytes(data))
                decompressed = reader.read()
                reader.close()
                
                # 确定输出文件扩展名
                decompressed_path = output_path.replace('.mp3', '_final.mp3')
                if decompressed_path == output_path:
                    decompressed_path = output_path + '.decompressed'
                
                with open(decompressed_path, 'wb') as f:
                    f.write(decompressed)
                
                print(f"解压完成: {decompressed_path} ({len(decompressed)} 字节)")
                return decompressed_path
            except Exception as e:
                print(f"解压失败: {e}")
        else:
            print("请安装 zstandard 库: pip install zstandard")
    
    return output_path


if __name__ == "__main__":
    input_file = "assets\\res\\bgm"
    output_file = "music_decrypted.mp3"
    
    if os.path.exists(input_file):
        phira_bgm_decrypt(input_file, output_file)
    else:
        print(f"错误: 找不到输入文件 {input_file}")
