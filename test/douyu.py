import hashlib
import re
import time
import urllib.parse

import requests


class DouYu:
    """
    可用来替换返回链接中的主机部分
    两个阿里的CDN：
    dyscdnali1.douyucdn.cn
    dyscdnali3.douyucdn.cn
    墙外不用带尾巴的akm cdn：
    hls3-akm.douyucdn.cn
    hlsa-akm.douyucdn.cn
    hls1a-akm.douyucdn.cn
    """

    def __init__(self, rid):
        """
        房间号通常为1~8位纯数字，浏览器地址栏中看到的房间号不一定是真实rid.
        Args:
            rid:
        """
        self.did = '10000000000000000000000000001501'
        self.t10 = str(int(time.time()))
        self.t13 = str(int((time.time() * 1000)))

        self.s = requests.Session()
        self.res = self.s.get('https://m.douyu.com/' + str(rid)).text
        result = re.search(r'rid":(\d{1,8}),"vipId', self.res)

        if result:
            self.rid = result.group(1)
        else:
            raise Exception('房间号错误')

    @staticmethod
    def md5(data):
        return hashlib.md5(data.encode('utf-8')).hexdigest()

    def get_pre(self):
        url = 'https://playweb.douyucdn.cn/lapi/live/hlsH5Preview/' + self.rid
        data = {
            'rid': self.rid,
            'did': self.did
        }
        auth = DouYu.md5(self.rid + self.t13)
        headers = {
            'rid': self.rid,
            'time': self.t13,
            'auth': auth
        }
        res = self.s.post(url, headers=headers, data=data).json()
        error = res['error']
        data = res['data']
        key = ''
        if data:
            rtmp_live = data['rtmp_live']
            key = re.search(r'(\d{1,8}[0-9a-zA-Z]+)_?\d{0,4}(/playlist|.m3u8)', rtmp_live).group(1)
        return error, key

    def get_js(self):
        result = re.search(r'(function ub98484234.*)\s(var.*)', self.res).group()
        func_ub9 = re.sub(r'eval.*;}', 'strc;}', result)

        # 替换掉所有调用 eval 的语句，解析出 JavaScript 代码字符串
        pattern = re.compile(r'eval\((.*?)\)', re.S)
        js_str = pattern.sub(lambda m: m.group(1)[1:-1], func_ub9)

        # 将所有 '[x2]-' 前缀的字符替换为 '_'
        js_str = js_str.replace('[x2]-', '_')

        v = re.search(r'v=(\d+)', js_str).group(1)
        rb = DouYu.md5(self.rid + self.did + self.t10 + v)

        # 构造 sign 函数
        def sign(rid, did, time):
            str1 = 'room/{0}?cdn={1}&nofan=yes&_t={2}&sign='.format(rid, 'ws-h5', time)
            sha1 = hashlib.sha1((str1 + rb).encode('utf-8')).hexdigest()
            str2 = '{0}-{1}-'.format(time, did) + sha1
            return urllib.parse.quote_plus(str2)

        # 调用 sign 函数生成签名参数
        params = 'cdn={0}&rate=-1&ver=219032101&_t={1}&did={2}&sign={3}'.format('ws-h5', self.t10, self.did, sign(self.rid, self.did, self.t10))

        url = 'https://m.douyu.com/api/room/ratestream'
        res = self.s.post(url, data=params).text
        key = re.search(r'(\d{1,8}[0-9a-zA-Z]+)_?\d{0,4}(.m3u8|/playlist)', res).group(1)

        return key

    def get_pc_js(self, cdn='ws-h5', rate=0):
        """
        通过PC网页端的接口获取完整直播源。
        :param cdn: 主线路ws-h5、备用线路tct-h5
        :param rate: 1流畅；2高清；3超清；4蓝光4M；0蓝光8M或10M
        :return: JSON格式
        """
        res = self.s.get('https://www.douyu.com/' + str(self.rid)).text
        result = re.search(r'(vdwdae325w_64we[\s\S]*function ub98484234[\s\S]*?)function', res).group(1)
        func_ub9 = re.sub(r'eval.*?;}', 'strc;}', result)

        # 替换掉所有调用 eval 的语句，解析出 JavaScript 代码字符串
        pattern = re.compile(r'eval\((.*?)\)', re.S)
        js_str = pattern.sub(lambda m: m.group(1)[1:-1], func_ub9)

        # 将所有 '[x2]-' 前缀的字符替换为 '_'
        js_str = js_str.replace('[x2]-', '_')

        v = re.search(r'v=(\d+)', js_str).group(1)
        rb = DouYu.md5(self.rid + self.did + self.t10 + v)

        # 构造 sign 函数
        def sign(rid, did, time):
            str1 = 'room/{0}?cdn={1}&nofan=yes&_t={2}&sign='.format(rid, 'ws-h5', time)
            sha1 = hashlib.sha1((str1 + rb).encode('utf-8')).hexdigest()
            str2 = '{0}-{1}-'.format(time, did) + sha1
            return urllib.parse.quote_plus(str2)

        # 调用 sign 函数生成签名参数
        params = 'cdn={0}&rate={1}&ver=219032101&_t={2}&did={3}&sign={4}'.format(cdn, rate, self.t10, self.did,
                                                                                 sign(self.rid, self.did, self.t10))

        url = 'https://www.douyu.com/lapi/live/getH5Play/{}'.format(self.rid)
        res = self.s.post(url, data=params).json()

        return res

    def get_real_url(self):
        error, key = self.get_pre()
        if error == 0:
            pass
        elif error == 102:
            raise Exception('房间不存在')
        elif error == 104:
            raise Exception('房间未开播')
        else:
            key = self.get_js()

        real_url = {}
        real_url["flv"] = "http://vplay1a.douyucdn.cn/live/{}.flv?uuid=".format(key)
        real_url["x-p2p"] = "http://tx2play1.douyucdn.cn/live/{}.xs?uuid=".format(key)

        return real_url
if __name__ == '__main__':
    r = input('输入斗鱼直播间号：\n')
    s = DouYu(r)
    print(s.get_real_url())
