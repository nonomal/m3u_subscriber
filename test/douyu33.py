import hashlib
import json
import re
import time
import requests
import js2py


class Douyu:
    def __init__(self, rid, stream_type, cdn_type):
        self.rid = rid
        self.stream_type = stream_type
        self.cdn_type = cdn_type

    def md5V3(self, s):
        m = hashlib.md5()
        m.update(s.encode('utf-8'))
        return m.hexdigest()

    def get_did(self):
        client = requests.session()
        timestamp = str(int(time.time() * 1000))
        url = f"https://passport.douyu.com/lapi/did/api/get?client_id=25&_=\
               {timestamp}&callback=axiosJsonpCallback1"
        headers = {
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) \
                            AppleWebKit/605.1.15 (KHTML, like Gecko) \
                            Version/16.3 Mobile/15E148 Safari/604.1",
            "referer": "https://m.douyu.com/",
        }
        resp = client.get(url, headers=headers)
        resp.encoding = 'utf-8'
        body = resp.text
        match = re.findall(r'axiosJsonpCallback1\((.*)\)', body)
        result = json.loads(match[0])
        return result["data"]["did"]

    def get_real_url(self):
        did = self.get_did()
        timestamp = int(time.time())
        liveurl = f"https://m.douyu.com/{self.rid}"
        client = requests.session()
        headers = {
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) \
                            AppleWebKit/605.1.15 (KHTML, like Gecko) \
                            Version/16.3 Mobile/15E148 Safari/604.1",
            "upgrade-insecure-requests": "1",
        }
        resp = client.get(liveurl, headers=headers)
        resp.encoding = 'utf-8'
        body = resp.text
        roomidreg = re.findall(r'(?i)rid":(\d{1,8}),"vipId', body)
        if not roomidreg:
            return None
        realroomid = roomidreg[0]
        reg = re.findall(r'(?i)(function ub98484234.*)\s(var.*)', body)
        nreg = re.compile(r'(?i)eval.*;}')
        strfn = nreg.sub("strc;}", reg[0][0])
        vm = js2py.EvalJs()
        input_arr_str = reg[0][1]
        name = input_arr_str.split('=')[0].split('var ')[1]
        # 创建 EvalJs 对象并执行 JavaScript 代码
        vm3 = js2py.EvalJs()
        vm3.execute(input_arr_str)
        # 获取数组对象
        js_array = vm3.eval(name)
        setattr(vm, name, js_array)
        vm.execute(strfn)
        jsfn = vm.eval('ub98484234')
        # 调用 ub98484234 函数并传入参数
        result = jsfn(realroomid, did, timestamp)
        nres = str(result)
        # nnreg = re.compile(r'(?i)v=(\d+)')
        nnreg = re.compile(r'v=(\d+)')
        nnres = nnreg.findall(nres)
        unrb = f"{realroomid}{did}{timestamp}{nnres[0]}"
        rb = self.md5V3(unrb)
        nnnreg = re.compile(r'(?i)return rt;}\);?')
        strfn2 = nnnreg.sub("return rt;}", nres)
        strfn3 = strfn2.replace("(function (", "function sign(")
        strfn4 = strfn3.replace('CryptoJS.MD5(cb).toString()', f'"{rb}"')
        vm2 = js2py.EvalJs()
        vm2.execute(strfn4)
        jsfn2 = vm2.eval('sign')
        param = jsfn2(realroomid, did, timestamp)
        realparam = f"{param}&ver=22107261&rid={realroomid}&rate=-1"
        headers = {
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) \
                            AppleWebKit/605.1.15 (KHTML, like Gecko) \
                            Version/16.3 Mobile/15E148 Safari/604.1",
        }
        r1 = client.post("https://m.douyu.com/api/room/ratestream", headers=headers, data=realparam)
        body1 = r1.content
        s1 = json.loads(body1)
        hls_url = ""
        for k, v in s1.items():
            if k == "code":
                if s1[k] != 0:
                    return None
            if isinstance(v, dict):
                for k1, v1 in v.items():
                    if k1 == "url":
                        hls_url = v1
        n4reg = re.compile(r'(?i)(\d{1,8}[0-9a-zA-Z]+)_?\d{0,4}(.m3u8|/playlist)')
        houzhui = n4reg.findall(hls_url)[0]
        flv_url = f"http://{self.cdn_type}.douyucdn2.cn/dyliveflv1/{houzhui[0]}.flv?uuid="
        xs_url = f"http://{self.cdn_type}.douyucdn2.cn/dyliveflv1/{houzhui[0]}.xs?uuid="
        if self.stream_type == "hls":
            real_url = hls_url
        elif self.stream_type == "flv":
            real_url = flv_url
        elif self.stream_type == "xs":
            real_url = xs_url
        else:
            return None
        return real_url


if __name__ == '__main__':
    r = '56666'
    # r = input('输入斗鱼直播间号：\n')
    s = Douyu(r, 'flv', 'vplay1a')
    print(s.get_real_url())
