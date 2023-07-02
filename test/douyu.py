import hashlib
import json
import re

import js2py
import requests
import time


class Douyu:
    def __init__(self, rid, stream_type, cdn_type):
        self.Rid = rid
        self.Stream_type = stream_type
        self.Cdn_type = cdn_type

    def md5V3(self, string):
        m = hashlib.md5()
        m.update(string.encode('utf-8'))
        return m.hexdigest()

    def getDid(self):
        headers = {
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1',
            'referer': 'https://m.douyu.com/'
        }
        response = requests.get('https://passport.douyu.com/lapi/did/api/get?client_id=25&_=' + str(
            int(time.time() * 1000)) + '&callback=axiosJsonpCallback1', headers=headers)
        match = re.search(r'axiosJsonpCallback1\((.*)\)', response.text)
        result = json.loads(match.group(1))
        return result['data']['did']

    def getRealUrl(self):
        did = self.getDid()
        timestamp = int(time.time())
        liveurl = f"https://m.douyu.com/{self.Rid}"
        headers = {
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1',
            'upgrade-insecure-requests': '1'
        }
        response = requests.get(liveurl, headers=headers)
        body = response.text
        roomidreg = re.search(r'(?i)rid":(\d{1,8}),"vipId', body)
        if roomidreg is None:
            return None
        realroomid = roomidreg.group(1)
        reg = re.search(r'(?i)(function ub98484234.*)\s(var.*)', body)
        res = reg.group()
        nreg = re.compile(r'(?i)eval.*;}')
        strfn = nreg.sub('strc;}', res)
        vm = js2py.EvalJs()
        vm.execute(strfn)
        jsfn = vm.ub98484234
        result = jsfn('ub98484234')
        nres = str(result)
        nnreg = re.compile(r'(?i)v=(\d+)')
        nnres = nnreg.findall(nres)
        unrb = f"{realroomid}{did}{timestamp}{nnres[0]}"
        rb = self.md5V3(unrb)
        nnnreg = re.compile(r'(?i)return rt;}\);?')
        strfn2 = nnnreg.sub('return rt;}', nres)
        strfn3 = strfn2.replace('(function (', 'function sign(').replace('CryptoJS.MD5(cb).toString()', '"' + rb + '"')
        vm2 = js2py.EvalJs()
        vm2.execute(strfn3)
        jsfn2 = vm2.sign
        result2 = jsfn2(realroomid, did, timestamp)
        param = str(result2)
        realparam = f"{param}&ver=22107261&rid={realroomid}&rate=-1"
        r1 = requests.post('https://m.douyu.com/api/room/ratestream', data=realparam, headers=headers)
        s1 = json.loads(r1.text)
        hls_url = None
        for k, v in s1.items():
            if k == "code":
                if s1[k] != 0:
                    return None
            if isinstance(v, dict):
                for k, v in v.items():
                    if k == "url":
                        if isinstance(v, str):
                            hls_url = v
        n4reg = re.compile(r'(?i)(\d{1,8}[0-9a-zA-Z]+)_?\d{0,4}(.m3u8|/playlist)')
        houzhui = n4reg.findall(hls_url)
        real_url = ''
        flv_url = f"http://{self.Cdn_type}.douyucdn2.cn/dyliveflv1/{houzhui[0][0]}.flv?uuid="
        xs_url = f"http://{self.Cdn_type}.douyucdn2.cn/dyliveflv1/{houzhui[0][0]}.xs?uuid="

        if self.Stream_type == "hls":
            real_url = hls_url
        elif self.Stream_type == "flv":
            real_url = flv_url
        elif self.Stream_type == "xs":
            real_url = xs_url
        else:
            real_url = None

        return real_url


if __name__ == '__main__':
    r = Douyu('98406', 'hls', 'openhls-tct.douyucdn2.cn')
    print(r.getRealUrl())
