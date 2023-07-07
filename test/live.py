import requests
import re


# 83
def get_m3u8_link(id):
    url = f"https://hklive.tv/{id}"

    headers = {
        "Referer": f"https://hklive.tv/{id}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67",
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        content = response.content.decode("utf-8")  # 解码为字符串
        # 使用正则表达式提取file对应的字符串
        pattern = r'file:\s*"(.*?)"'
        match = re.search(pattern, content)
        if match:
            file_url = match.group(1)
            print("提取的file对应的字符串:", file_url)
            return file_url
        else:
            print("未找到file对应的字符串")
            return None
    else:
        print("请求失败，状态代码:", response.status_code)
        return None


def get_m3u8_raw_content(url, id):
    if not url:
        return None
    headers = {
        "Referer": f"https://hkdtmb.com/{id}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        content = response.content.decode('utf-8')
        ts_url = f"https://hklive.tv/dtmb/{id}/"
        new_m3u8_data = ''
        for line in content.splitlines():
            if line.startswith(
                    ('#EXTM3U', '#EXT-X-VERSION:', '#EXT-X-MEDIA-SEQUENCE', '#EXT-X-TARGETDURATION', '#EXTINF')):
                new_m3u8_data += line
                new_m3u8_data += '\n'
            else:
                new_m3u8_data += ts_url
                new_m3u8_data += line
                new_m3u8_data += '\n'
        print("内容下载完成")
        return new_m3u8_data
    else:
        print("请求失败，状态代码:", response.status_code)
        return None


if __name__ == '__main__':
    m3u8_link = get_m3u8_link(83)
    if m3u8_link:
        m3u8_data = get_m3u8_raw_content(m3u8_link, 83)
        print(m3u8_data)
