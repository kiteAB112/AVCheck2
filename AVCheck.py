#!/usr/bin/env python3
import argparse
import os

banner = '''

     ___   ____    ____  ______  __    __   _______   ______  __  ___ 
    /   \  \   \  /   / /      ||  |  |  | |   ____| /      ||  |/  / 
   /  ^  \  \   \/   / |  ,----'|  |__|  | |  |__   |  ,----'|  '  /  
  /  /_\  \  \      /  |  |     |   __   | |   __|  |  |     |    <   
 /  _____  \  \    /   |  `----.|  |  |  | |  |____ |  `----.|  .  \  
/__/     \__\  \__/     \______||__|  |__| |_______| \______||__|\__\ 

                                                       --by 想走安全的小白
                                                                      
'''

print(banner)

def check_antivirus(tar_file):
    # 存储已识别的杀软（去重）
    detected_avs = set()
    
    # 1. 读取杀软识别列表到内存并预处理
    try:
        with open('杀软识别.txt', 'r', encoding='utf-8') as f:
            av_list = []
            for line in f.readlines():
                line = line.strip('\n')
                if not line:  # 跳过空行
                    continue
                # 分割并验证格式（确保包含足够的双引号）
                parts = line.split('"')
                if len(parts) >= 4:
                    av_process = parts[1].strip()  # 进程名（去空格）
                    av_name = parts[3].strip()      # 杀软名称（去空格）
                    av_list.append((av_process, av_name))
                else:
                    print(f"警告：杀软识别列表格式错误，跳过此行：{line}")
    except FileNotFoundError:
        print("错误：未找到 '杀软识别.txt' 文件，请确保该文件存在")
        return
    except Exception as e:
        print(f"读取杀软识别列表时出错：{str(e)}")
        return

    # print(av_list)

    # 2. 处理进程列表文件
    if not os.path.exists(tar_file):
        print(f"错误：进程列表文件 '{tar_file}' 不存在")
        return

    try:
        with open(tar_file, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file.readlines(), 1):
                line = line.strip('\n')
                if not line:  # 跳过空行
                    continue
                
                # 提取进程名（优化分割逻辑，处理可能的空格）
                # 只按第一个空格分割，避免进程名含空格时出错
                parts = line.split(maxsplit=1)
                if len(parts) == 0:
                    continue
                target = parts[0].strip()  # 进程名（去空格）

                # 3. 与杀软列表比对
                for av_process, av_name in av_list:
                    if target == av_process:
                        detected_avs.add(av_name)
                        # 找到匹配后跳出当前循环，避免重复匹配
                        break

    except Exception as e:
        print(f"读取进程列表文件时出错：{str(e)}")
        return

    # 4. 输出最终结果
    if detected_avs:
        print("\n检测到以下杀毒软件：")
        for av in sorted(detected_avs):  # 排序后输出
            print(f"- {av}")
    else:
        print("\n未检测到已知的杀毒软件")



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AVCheck')
    parser.add_argument('-f', '--file', help='input file', required=True)
    args = parser.parse_args()

    tar_file = args.file
    check_antivirus(tar_file)


