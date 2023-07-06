import base64
import concurrent
import os
import random
import re
import secrets
import string
import subprocess
import tkinter as tk
import uuid
from datetime import datetime
from tkinter import filedialog, messagebox

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

file_name_dict = {'name': ''}


# 解密函数 str-password,bytes secretcont
def decrypt(password, ciphertext):
    # generate key from password
    arr = getIV(password)
    key = arr[0]
    # create cipher object using the same algorithm, key and iv from encryption
    backend = default_backend()
    algorithm = algorithms.AES(key)
    mode = modes.CTR(arr[1])
    cipher = Cipher(algorithm, mode, backend=backend)
    # create a decryptor object
    decryptor = cipher.decryptor()
    fuck = decryptor.update(ciphertext)
    # decrypt ciphertext
    plaintext = fuck + decryptor.finalize()
    # return decrypted plaintext
    return plaintext


# 根据年月日、当前时间、输入的字符串生成的绝对唯一uuid
def generate_only_uuid(my_string):
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d%H%M%S%f")
    unique_str = f"{timestamp}-{my_string}"
    serial_number = uuid.uuid5(uuid.NAMESPACE_URL, unique_str)
    return str(serial_number)


def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


# 生成订阅链接加密密码,字符串密码
def generateEncryptPassword():
    return generate_password() + "paperbluster" + base64.b64encode(os.urandom(16)).decode('utf-8')


# 返回字符串密码和比特流iv
def getIV(passwordStr):
    arr = passwordStr.split("paperbluster")
    iv_decoded = base64.b64decode(arr[1])
    return arr[0].encode('utf-8'), iv_decoded


# 加密函数   # bytes ciphertext
def encrypt2(plaintext, password):
    arr = getIV(password)
    # generate key and iv
    key = arr[0]
    # iv = os.urandom(16)
    # create cipher object
    backend = default_backend()
    algorithm = algorithms.AES(key)
    mode = modes.CTR(arr[1])
    cipher = Cipher(algorithm, mode, backend=backend)
    # encrypt plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # return ciphertext, iv, algorithm, and mode
    return ciphertext


# 使用线程池把bytes流内容写入本地文件
def thread_write_bytes_to_file(filename, bytesContent):
    if len(bytesContent) == 0:
        return
    if os.path.exists(filename):
        os.remove(filename)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(write_bytes_to_file, filename, bytesContent)
        future.result()
    # 等待所有任务完成
    concurrent.futures.wait([future])


def write_bytes_to_file(filename, plaintext):
    with open(filename, 'wb') as f:
        f.write(plaintext)


def check_files_in_path(path):
    if os.path.exists(path):  # 判断路径是否存在
        files = os.listdir(path)  # 获取路径下的所有文件和文件夹
        if files:  # 判断文件列表是否为空
            return True  # 存在文件
    return False  # 不存在文件


def is_success_write_file(filepath):
    with open(filepath, "rb") as f2:
        data = f2.read()
    if len(data) == 0:
        return False
    return True


class MyFrame(tk.Frame):
    def read_video_file(self):
        file_path = self.file_path.get()
        with open(file_path, 'rb') as f:
            video_bytes = f.read()
        return video_bytes

    def on_convert_click_mkv_to_mp4(self):
        file_path = self.file_path.get()
        if not os.path.exists(file_path):
            messagebox.showerror('错误', '视频文件不存在')
            return
        file_path = self.file_path.get()
        # 提取目录路径
        dir_path = os.path.dirname(file_path)
        # 提取文件名
        file_name = os.path.basename(file_path)
        video_types = file_name.split('.')[-1]
        new_file_name = file_name.replace(video_types, 'ts')
        slices_path = os.path.join(dir_path,
                                   f"{new_file_name}")

        # Windows系统下需要将路径分隔符从/替换成\
        if os.name == 'nt':
            escaped_path = file_path.replace('/', '\\\\')
            escaped_path2 = file_path.replace('/', '\\\\')
            slices_path = slices_path.replace('\\', '\\\\')
            slices_path = slices_path.replace('/', '\\\\')
        ss = '\:'
        gputype = self.ts_type_gpu.get()
        if gputype == '0':
            cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k  -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" -r 23.976 \"{slices_path}\""
        else:  # gpu解码,编码,有字幕
            cmd = f"ffmpeg -hwaccel cuvid -c:v hevc_cuvid   -i \"{escaped_path}\"  -map 0:v:0 -map 0:a:0 -c:v h264_nvenc -b:v 2M -pix_fmt yuv420p -c:a aac -b:a 128k  -vf  \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" -r 23.976 \"{slices_path}\""
        # cmd = f"ffmpeg  -i \"{escaped_path}\" -map 0:v:0 -map 0:a:0 -r 25 -g 60 -c:v libx265 -preset medium -c:a aac -b:a 128k -ac 2  -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" \"{slices_path}\""
        if not os.path.exists(slices_path):
            process = subprocess.Popen(cmd, shell=True)
            process.communicate()  # Wait for process to finish
            if not is_success_write_file(slices_path):
                os.remove(slices_path)
                if gputype == '1':  # cpu解码,gpu编码，有字幕
                    cmd = f"ffmpeg -i \"{escaped_path}\"  -map 0:v:0 -map 0:a:0 -c:v hevc_nvenc -b:v 2M -pix_fmt yuv420p -c:a aac -b:a 128k   -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" -r 23.976  \"{slices_path}\""
                    process = subprocess.Popen(cmd, shell=True)
                    process.communicate()  # Wait for process to finish
                if not is_success_write_file(slices_path):
                    os.remove(slices_path)
                    # cpu解码,cpu编码,有字幕
                    cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k  -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" -r 23.976 \"{slices_path}\""
                    process = subprocess.Popen(cmd, shell=True)
                    process.communicate()  # Wait for process to finish
                    if not is_success_write_file(slices_path):
                        os.remove(slices_path)
                        if gputype == '0':  # cpu解码,cpu编码
                            cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k  -r 23.976 \"{slices_path}\""
                        else:  # gpu解码,gpu编码
                            cmd = f"ffmpeg -hwaccel cuvid -c:v hevc_cuvid -i \"{escaped_path}\"  -map 0:v:0 -map 0:a:0 -c:v h264_nvenc -b:v 2M -pix_fmt yuv420p -c:a aac -b:a 128k   -r 23.976 \"{slices_path}\""
                        process = subprocess.Popen(cmd, shell=True)
                        process.communicate()  # Wait for process to finish
                        if not is_success_write_file(slices_path):
                            os.remove(slices_path)
                            if gputype == '0':  # cpu解码,cpu编码
                                cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k  -r 23.976 \"{slices_path}\""
                            else:  # cpu解码,gpu编码
                                cmd = f"ffmpeg  -i \"{escaped_path}\"  -map 0:v:0 -map 0:a:0 -c:v h264_nvenc -b:v 2M -pix_fmt yuv420p -c:a aac -b:a 128k   -r 23.976 \"{slices_path}\""
                            process = subprocess.Popen(cmd, shell=True)
                            process.communicate()  # Wait for process to finish
                            if not is_success_write_file(slices_path):
                                os.remove(slices_path)
                                cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k  -r 23.976 \"{slices_path}\""
                                process = subprocess.Popen(cmd, shell=True)
                                process.communicate()  # Wait for process to finish
        else:
            if slices_path.endswith('ts'):
                # cmd = f"ffmpeg  -i \"{escaped_path}\" -map 0:v:0 -map 0:a:0 -c:v libx265 -preset slow -crf 18 -c:a aac -b:a 128k -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\':force_style='FontName=微软雅黑,FontSize=19,PrimaryColour=&Hffffff,SecondaryColour=&H000000,TertiaryColour=&H800080,BackColour=&H0f0f0f,Bold=-1,Italic=0,BorderStyle=1,Outline=3,Shadow=2,Alignment=2,MarginL=30,MarginR=30,MarginV=12,AlphaLevel=0,Encoding=134'\" \"{slices_path.replace('.mp4', '2.mp4')}\""
                if gputype == '0':
                    cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k  -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" -r 23.976  \"{slices_path.replace('.ts', '2.ts')}\""
                else:  # gpu解码,gpu编码，有字幕
                    cmd = f"ffmpeg -hwaccel cuvid -c:v hevc_cuvid    -i \"{escaped_path}\"  -map 0:v:0 -map 0:a:0 -c:v h264_nvenc -b:v 2M -pix_fmt yuv420p -c:a aac -b:a 128k   -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" -r 23.976  \"{slices_path.replace('.ts', '2.ts')}\""
                new_file_name = new_file_name.replace('.ts', '2.ts')
            process = subprocess.Popen(cmd, shell=True)
            process.communicate()  # Wait for process to finish
            if not is_success_write_file(slices_path.replace('.ts', '2.ts')):
                os.remove(slices_path.replace('.ts', '2.ts'))
                if gputype == '1':  # cpu解码,gpu编码，有字幕
                    cmd = f"ffmpeg -i \"{escaped_path}\"  -map 0:v:0 -map 0:a:0 -c:v hevc_nvenc -b:v 2M -pix_fmt yuv420p -c:a aac -b:a 128k   -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" -r 23.976  \"{slices_path.replace('.ts', '2.ts')}\""
                    process = subprocess.Popen(cmd, shell=True)
                    process.communicate()  # Wait for process to finish
                if not is_success_write_file(slices_path.replace('.ts', '2.ts')):
                    os.remove(slices_path.replace('.ts', '2.ts'))
                    cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k  -vf \"subtitles=filename=\'{escaped_path2.replace(':', ss)}\'\" -r 23.976  \"{slices_path.replace('.ts', '2.ts')}\""
                    process = subprocess.Popen(cmd, shell=True)
                    process.communicate()  # Wait for process to finish
                    if not is_success_write_file(slices_path.replace('.ts', '2.ts')):
                        os.remove(slices_path.replace('.ts', '2.ts'))
                        if gputype == '0':  # cpu解码,cpu编码
                            cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k   -r 23.976  \"{slices_path.replace('.ts', '2.ts')}\""
                        else:  # gpu解码,gpu编码
                            cmd = f"ffmpeg -hwaccel cuvid -c:v hevc_cuvid    -i \"{escaped_path}\"  -map 0:v:0 -map 0:a:0 -c:v h264_nvenc -b:v 2M -pix_fmt yuv420p -c:a aac -b:a 128k    -r 23.976  \"{slices_path.replace('.ts', '2.ts')}\""
                        process = subprocess.Popen(cmd, shell=True)
                        process.communicate()  # Wait for process to finish
                        if not is_success_write_file(slices_path.replace('.ts', '2.ts')):
                            os.remove(slices_path.replace('.ts', '2.ts'))
                            if gputype == '0':  # cpu解码,cpu编码
                                cmd = f"ffmpeg -i \"{escaped_path}\" -pix_fmt yuv420p -map 0:v:0 -map 0:a:0 -c:v libx265 -b:v 2M -c:a aac -b:a 128k   -r 23.976  \"{slices_path.replace('.ts', '2.ts')}\""
                            else:  # cpu解码,gpu编码
                                cmd = f"ffmpeg -i \"{escaped_path}\"  -map 0:v:0 -map 0:a:0 -c:v h264_nvenc -b:v 2M -pix_fmt yuv420p -c:a aac -b:a 128k    -r 23.976  \"{slices_path.replace('.ts', '2.ts')}\""
                            process = subprocess.Popen(cmd, shell=True)
                            process.communicate()  # Wait for process to finish
        # self.file_path = os.path.join(dir_path,
        #                               f"{new_file_name}")
        self.file_path.delete(0, 'end')
        self.file_path.insert(0, os.path.join(dir_path,
                                              f"{new_file_name}"))
        # 将按钮变成绿色
        self.convert_button2.config(bg='green')
        with open('/gpu.txt', "wb") as f2:
            pass
        with open('/gpu.txt', "wb") as f2:
            f2.write(gputype.encode('utf-8'))
        return 'video_bytes'

    def read_video_file_to_slices(self):
        try:
            file_path = self.file_path.get().replace('mkv', 'ts')
            # 视频格式
            videoType = file_path.split('.')[-1]
            # 提取目录路径
            dir_path = os.path.dirname(file_path)
            # 提取文件名
            file_name = os.path.basename(file_path)
            new_file_and_path_name = generate_only_uuid(file_name)
            # 创建新文件夹
            new_folder_path = os.path.join(dir_path, new_file_and_path_name)
            os.makedirs(new_folder_path, exist_ok=True)
            slices_path = os.path.join(new_folder_path,
                                       f"{new_file_and_path_name}_%05d.ts")
            if os.name == 'nt':
                slices_path = slices_path.replace('/', '\\')
            escaped_path = file_path
            # Windows系统下需要将路径分隔符从/替换成\
            if os.name == 'nt':
                escaped_path = escaped_path.replace('/', '\\')
            outputfilepath = os.path.join(new_folder_path, new_file_and_path_name)
            if os.name == 'nt':
                outputfilepath = outputfilepath.replace('/', '\\')
            ts_type = self.ts_type.get()
            if not ts_type or ts_type == '':
                ts_type = 'copy'
            cmd = f"ffmpeg -i \"{escaped_path}\"  -c:v {ts_type} -c:a copy  -map 0:v:0 -map 0:a:0? -hls_time 10 -hls_list_size 0 -hls_segment_filename {slices_path} -f hls {outputfilepath}.m3u8"
            process = subprocess.Popen(cmd, shell=True)
            process.communicate()  # Wait for process to finish
            if not check_files_in_path(new_folder_path):
                cmd = f"ffmpeg -i \"{escaped_path}\"  -c:v {ts_type} -c:a aac  -map 0:v:0 -map 0:a:0? -hls_time 10 -hls_list_size 0 -hls_segment_filename {slices_path} -f hls {outputfilepath}.m3u8"
                process = subprocess.Popen(cmd, shell=True)
                process.communicate()  # Wait for process to finish
            match = re.search(r'(.+?)\.[^.]*$', file_name)
            if match:
                result = match.group(1)
            video_file_name_tag = b'#my_video_true_name_is=' + result.encode()
            video_type = self.video_type.get()
            if video_type and video_type != '':
                video_file_name_tag += b'\n'
                video_file_name_tag += b'#my_video_group_name_is='
                video_file_name_tag += video_type.encode()
                with open('/cdcdf.txt', "wb") as f2:
                    pass
                with open('/cdcdf.txt', "wb") as f2:
                    f2.write(video_type.encode('utf-8'))
            # 读取M3U8播放列表文件并返回给客户端
            with open(f'{outputfilepath}.m3u8', "rb") as f:
                m3u8_data = f.read()
            # 在字符串的第一行插入标签信息
            m3u8_data = m3u8_data + b'\n' + video_file_name_tag
            # 将修改后的字符串重新写回到m3u8文件中
            thread_write_bytes_to_file(f'{outputfilepath}.m3u8', m3u8_data)
            self.uuid_text.delete(0, 'end')
            self.uuid_text.insert(0, new_file_and_path_name)
            self.uuid_text.config(bg='green')
            file_name_dict['name'] = result
            return 'video_bytes'
        except Exception as e:
            messagebox.showerror('错误', 'ts视频文件不存在')

    def undone(self):
        file_path = self.file_path.get()
        if not os.path.exists(file_path):
            messagebox.showerror('错误', '加密文件不存在')
            return
        password = self.password_text.get()
        text2 = self.uuid_text.get()
        if password == '' or text2 == '':
            messagebox.showerror('错误', '密码或者uuid为空')
            return
        # 提取目录路径
        dir_path = os.path.dirname(file_path)
        # 提取文件名
        file_name = os.path.basename(file_path)
        # uuid
        uuid = file_name.split('_')[0]
        if not uuid:
            uuid = text2
        # 还原m3u8文件
        dir_path2 = os.path.join(dir_path,
                                 f"{uuid}")
        if os.name == 'nt':
            dir_path2 = dir_path2.replace('/', '\\')
        with open(dir_path2, "rb") as f2:
            m3u8_data_secret = f2.read()
        m3u8_data = decrypt(password, m3u8_data_secret)
        # 还原m3u8文件内容
        dir_path3 = os.path.join(dir_path,
                                 f"{uuid}.m3u8")
        if os.name == 'nt':
            dir_path3 = dir_path3.replace('/', '\\')
        # 恢复明文m3u8
        thread_write_bytes_to_file(dir_path3, m3u8_data)
        # 根据m3u8文件内容恢复每个明文ts切块
        # 恢复的ts列表记录
        ts_list = b''
        source_file_name = ''
        ss = '\:'
        for line in m3u8_data.splitlines():
            if uuid.encode() in line:
                slices_path_ts = os.path.join(dir_path, line.decode())
                if os.name == 'nt':
                    slices_path_ts = slices_path_ts.replace('/', '\\')
                # 读取密文ts切块
                with open(slices_path_ts, "rb") as f2:
                    ts_data_secret = f2.read()
                ts_data = decrypt(password, ts_data_secret)
                # 恢复明文ts
                thread_write_bytes_to_file(slices_path_ts + '.ts', ts_data)
                ts_list += f'file {line.decode()}.ts\n'.encode()
            else:
                if line.startswith(b"#my_video_true_name_is="):
                    source_file_name = line.split(b"=")[1].decode()
        list_path = os.path.join(dir_path, 'list.txt')
        if os.name == 'nt':
            list_path = list_path.replace('/', '\\')
        # 生成恢复列表
        thread_write_bytes_to_file(list_path, ts_list)
        # 恢复成一个mp4
        mp4_path = os.path.join(dir_path,
                                f"{source_file_name}.mp4")
        if os.name == 'nt':
            mp4_path = mp4_path.replace('/', '\\')
        cmd = f"ffmpeg -f concat -safe 0 -i \"{list_path}\" -c copy \"{mp4_path}\""
        process = subprocess.Popen(cmd, shell=True)
        process.communicate()  # Wait for process to finish
        # messagebox.showinfo("读取结果", f"文本框1内容：{text1}\n文本框2内容：{text2}")
        self.convert_button5.config(bg='green')
        # 删除全部切片
        removePaths = os.listdir(dir_path)
        for filename in removePaths:
            # 不是以uuid开始的文件，包括m3u8和ts文件
            if filename.startswith(uuid) or filename.startswith('list.txt'):
                removePath = os.path.join(dir_path, filename)
                if os.name == 'nt':
                    removePath = removePath.replace('/', '\\')
                os.remove(removePath)

    def __init__(self, parent, title):
        super().__init__(parent)

        self.master.title(title)
        self.master.geometry("500x900")

        self.file_path = tk.Entry(self, state='readonly')
        self.file_path.pack(fill='x', padx=10, pady=10)

        self.file_button = tk.Button(self, text="第一步:选择视频文件", command=self.on_file_click)
        self.file_button.pack(fill='x', padx=10, pady=10)

        self.convert_button2 = tk.Button(self, text="第二步:转换成ts视频(字幕硬转码)",
                                         command=self.on_convert_click_mkv_to_mp4)
        self.convert_button2.pack(fill='x', padx=10, pady=10)

        self.convert_button = tk.Button(self, text="第三步:转换成ts切片", command=self.on_convert_click)
        self.convert_button.pack(fill='x', padx=10, pady=10)

        self.convert_button3 = tk.Button(self, text="第四步:ts切片数据加密", command=self.on_convert_click_secret)
        self.convert_button3.pack(fill='x', padx=10, pady=10)

        self.convert_button4 = tk.Button(self, text="一键生成加密ts切片", command=self.onekey)
        self.convert_button4.pack(fill='x', padx=10, pady=10)

        self.convert_button5 = tk.Button(self, text="还原加密切片为完整解密视频", command=self.undone)
        self.convert_button5.pack(fill='x', padx=10, pady=10)

        # 创建一个Label小部件，用于显示文本框的用途
        label = tk.Label(self, text="密码:")
        # 将Label和Entry小部件放置到窗口中
        label.pack()
        self.password_text = tk.Entry(self)
        self.password_text.pack(fill='x', padx=10, pady=10)
        if os.path.exists('/dhjfkhjag.txt'):
            with open('/dhjfkhjag.txt', "rb") as f2:
                password = f2.read()
            self.password_text.delete(0, 'end')
            self.password_text.insert(0, password.decode('utf-8'))
            self.password_text.config(bg='green')
        self.uuid_text = tk.Entry(self)
        self.uuid_text.pack(fill='x', padx=1, pady=1)

        # 创建一个Label小部件，用于显示文本框的用途
        label = tk.Label(self, text="设置视频分类:")
        # 将Label和Entry小部件放置到窗口中
        label.pack()
        self.video_type = tk.Entry(self)
        self.video_type.pack(fill='x', padx=10, pady=10)
        if os.path.exists('/cdcdf.txt'):
            with open('/cdcdf.txt', "rb") as f2:
                typev = f2.read()
            self.video_type.delete(0, 'end')
            self.video_type.insert(0, typev.decode('utf-8'))
            self.video_type.config(bg='green')
        # 创建一个Label小部件，用于显示文本框的用途
        label = tk.Label(self, text="设置视频切片格式(libx264/copy/libx265):")
        # 将Label和Entry小部件放置到窗口中
        label.pack()
        self.ts_type = tk.Entry(self)
        self.ts_type.pack(fill='x', padx=10, pady=10)

        # 创建一个Label小部件，用于显示文本框的用途
        label = tk.Label(self, text="设置硬件加速(0-cpu/1-gpu):")
        # 将Label和Entry小部件放置到窗口中
        label.pack()
        self.ts_type_gpu = tk.Entry(self)
        self.ts_type_gpu.pack(fill='x', padx=10, pady=10)
        if os.path.exists('/gpu.txt'):
            with open('/gpu.txt', "rb") as f2:
                typev = f2.read()
            self.ts_type_gpu.delete(0, 'end')
            self.ts_type_gpu.insert(0, typev.decode('utf-8'))
            self.ts_type_gpu.config(bg='green')

    def on_file_click(self):
        file_path = filedialog.askopenfilename(initialdir=os.getcwd(), title="选择视频文件",
                                               filetypes=(("all files", "*.*"),
                                                          ("mkv files", "*.mkv"), ("mp4 files", "*.mp4"),
                                                          ("avi files", "*.avi"), ("rm files", "*.rm"),
                                                          ("rmvb files", "*.rmvb"), ("fly files", "*.fly")))
        if file_path:
            self.file_path.configure(state='normal')
            self.file_path.delete(0, 'end')
            self.file_path.insert(0, file_path)
            self.file_path.configure(state='readonly')

        # 将所有按钮颜色重置为原来的颜色
        self.convert_button2.config(bg=self.master.cget('bg'))
        self.convert_button.config(bg=self.master.cget('bg'))
        self.password_text.config(bg=self.master.cget('bg'))
        self.uuid_text.config(bg=self.master.cget('bg'))
        self.convert_button3.config(bg=self.master.cget('bg'))
        self.file_button.config(bg='green')
        # self.password_text.delete(0, 'end')
        self.uuid_text.delete(0, 'end')
        self.convert_button5.config(bg=self.master.cget('bg'))
        self.convert_button4.config(bg=self.master.cget('bg'))
        file_name_dict['name'] = ''

    def onekey(self):
        self.on_convert_click_mkv_to_mp4()
        self.on_convert_click()
        self.on_convert_click_secret()
        self.convert_button4.config(bg='green')

    def on_convert_click_secret(self):
        file_path = self.file_path.get()
        # 提取目录路径
        dir_path = os.path.dirname(file_path)
        dir_path2 = os.path.join(dir_path,
                                 f"{self.uuid_text.get()}")
        if os.name == 'nt':
            dir_path2 = dir_path2.replace('/', '\\')
        slices_path = os.path.join(dir_path2,
                                   f"{self.uuid_text.get()}.m3u8")
        if os.name == 'nt':
            slices_path = slices_path.replace('/', '\\')
        if not os.path.exists(slices_path):
            self.on_convert_click()
        dir_path2 = os.path.join(dir_path,
                                 f"{self.uuid_text.get()}")
        if os.name == 'nt':
            dir_path2 = dir_path2.replace('/', '\\')
        slices_path = os.path.join(dir_path2,
                                   f"{self.uuid_text.get()}.m3u8")
        if os.name == 'nt':
            slices_path = slices_path.replace('/', '\\')
        # 读取M3U8播放列表文件并返回给客户端
        with open(slices_path, "rb") as f:
            m3u8_data = f.read()
        # m3u8的uuid
        slices_path2 = os.path.join(dir_path2,
                                    f"{self.uuid_text.get()}")
        if os.name == 'nt':
            slices_path2 = slices_path2.replace('/', '\\')
        data = b''
        password = self.password_text.get()
        if password == '':
            password = generateEncryptPassword()
        for line in m3u8_data.splitlines():
            if self.uuid_text.get().encode() in line:
                slices_path_ts = os.path.join(dir_path2, line.decode())
                if os.name == 'nt':
                    slices_path_ts = slices_path_ts.replace('/', '\\')
                # 读取明文ts切块
                with open(slices_path_ts, "rb") as f2:
                    ts_data = f2.read()
                    secretContent = encrypt2(ts_data, password)
                    new_file = line.decode().split('.')[0]
                    slices_path_secret = os.path.join(dir_path2, new_file)
                    if os.name == 'nt':
                        slices_path_secret = slices_path_secret.replace('/', '\\')
                    # 密文ts切块
                    thread_write_bytes_to_file(slices_path_secret, secretContent)
                    data += new_file.encode()
                    data += b'\n'
                os.remove(slices_path_ts)
            else:
                data += line
                data += b'\n'
        # 明文m3u8
        # thread_write_bytes_to_file(slices_path2, data)
        secretContent = encrypt2(data, password)
        # 密文m3u8
        thread_write_bytes_to_file(f'{dir_path}/{self.uuid_text.get()}C', secretContent)
        # 将按钮变成绿色
        self.convert_button3.config(bg='green')
        self.password_text.delete(0, 'end')
        self.password_text.insert(0, password)
        self.password_text.config(bg='green')
        with open('/dhjfkhjag.txt', "wb") as f2:
            pass
        with open('/dhjfkhjag.txt', "wb") as f2:
            f2.write(password.encode('utf-8'))
        # 密码和文件名字，uuid记录
        # uuid_password_data = self.uuid_text.get() + '\n' + self.password_text.get() + '\n' + file_name_dict.get('name')
        # # m3u8的uuid
        # slices_path2 = os.path.join(dir_path2,
        #                             f"uuid_password.txt")
        # if os.name == 'nt':
        #     slices_path2 = slices_path2.replace('/', '\\')
        # thread_write_bytes_to_file(slices_path2, uuid_password_data.encode())
        os.remove(slices_path)
        file_name_dict['name'] = ''

    def on_convert_click(self):
        file_path = self.file_path.get().replace('mkv', 'ts')
        file_path = file_path.replace('avi', 'ts')
        if not os.path.exists(file_path):
            if not os.path.exists(file_path):
                messagebox.showerror('错误', '视频文件不存在')
                return
        # TODO: 根据需要实现视频处理代码
        self.read_video_file_to_slices()
        # 将按钮变成绿色
        self.convert_button.config(bg='green')


if __name__ == '__main__':
    root = tk.Tk()
    frame = MyFrame(root, "视频切片加密转换工具")
    frame.pack(fill='both', expand=True)
    root.mainloop()
