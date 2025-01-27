import abc
import asyncio
import base64
import io
import random
import secrets
import string
import concurrent
import ipaddress
import json
import math
import os
import queue
import re
import uuid
from datetime import datetime
import threading
import hashlib
import urllib
import zipfile
from concurrent.futures import ThreadPoolExecutor
from functools import wraps

import chardet
import m3u8
import aiohttp
import aiofiles
import requests
import time
from urllib.parse import urlparse, urlencode

from bs4 import BeautifulSoup
from flask import Flask, jsonify, request, send_file, render_template, send_from_directory, \
    after_this_request, redirect, Response

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 存放数据库文件的路径
DB_PATH = "/app/db"


def get_single(file_path):
    try:
        with open(file_path, "rb") as f:
            data_bytes = f.read()
        return jsonify({'result': data_bytes.decode('utf-8')})
    except Exception as e:
        return jsonify({'result': ''})


def get_single_local(file_path):
    try:
        with open(file_path, "rb") as f:
            data_bytes = f.read()
        return data_bytes.decode('utf-8')
    except Exception as e:
        return ''


def add_single(file_path, value):
    try:
        try:
            # 如果文件存在，清除文件中的所有数据
            with open(file_path, "wb") as f:
                pass
        except:
            # 如果文件不存在，创建一个新文件
            open(file_path, "wb").close()
        # 复写数据
        with open(file_path, "wb") as f:
            f.write(value.encode('utf-8'))
        return jsonify({'result': 1})
    except Exception as e:
        return jsonify({'result': 0})


def add_single_local(file_path, value):
    try:
        try:
            # 如果文件存在，清除文件中的所有数据
            with open(file_path, "wb") as f:
                pass
        except:
            # 如果文件不存在，创建一个新文件
            open(file_path, "wb").close()
        # 复写数据
        with open(file_path, "wb") as f:
            f.write(value.encode('utf-8'))
    except Exception as e:
        pass


def add_map(file_path, add_dict):
    try:
        if len(add_dict) == 0:
            return jsonify({'result': 0})
        old_dict = {}
        try:
            with open(file_path, "rb") as f:
                data_bytes = f.read()
            old_dict = json.loads(data_bytes.decode('utf-8'))
        except Exception as e:
            # 如果文件不存在，创建一个新文件
            open(file_path, "wb").close()
        old_dict.update(add_dict)
        # 清除文件中的所有数据
        with open(file_path, "wb") as f:
            pass
        # 复写数据
        with open(file_path, "wb") as f:
            f.write(json.dumps(old_dict).encode('utf-8'))
        return jsonify({'result': 1})
    except Exception as e:
        return jsonify({'result': 0})


def add_map_local(file_path, add_dict):
    try:
        if len(add_dict) == 0:
            return
        old_dict = {}
        try:
            with open(file_path, "rb") as f:
                data_bytes = f.read()
            old_dict = json.loads(data_bytes.decode('utf-8'))
        except Exception as e:
            # 如果文件不存在，创建一个新文件
            open(file_path, "wb").close()
        old_dict.update(add_dict)
        # 清除文件中的所有数据
        with open(file_path, "wb") as f:
            pass
        # 复写数据
        with open(file_path, "wb") as f:
            f.write(json.dumps(old_dict).encode('utf-8'))
    except Exception as e:
        pass


def delete_cache(file_path):
    try:
        os.remove(file_path)
        return jsonify({'result': 1})
    except Exception as e:
        return jsonify({'result': 0})


def delete_cache_local(file_path):
    try:
        os.remove(file_path)
    except Exception as e:
        pass


def delete_keys(file_path, dict_data):
    try:
        with open(file_path, "rb") as f:
            data_bytes = f.read()
        dict = json.loads(data_bytes.decode('utf-8'))
        new_dict = {}
        for key, value in dict.items():
            if key in dict_data:
                continue
            new_dict[key] = value
        # 清除文件中的所有数据
        with open(file_path, "wb") as f:
            pass
        # 复写数据
        with open(file_path, "wb") as f:
            f.write(json.dumps(new_dict).encode('utf-8'))
        return jsonify({'result': 1})
    except Exception as e:
        return jsonify({'result': 0})


def delete_keys_local(file_path, dict_data):
    try:
        with open(file_path, "rb") as f:
            data_bytes = f.read()
        dict = json.loads(data_bytes.decode('utf-8'))
        new_dict = {}
        for key, value in dict.items():
            if key in dict_data:
                continue
            new_dict[key] = value
        # 清除文件中的所有数据
        with open(file_path, "wb") as f:
            pass
        # 复写数据
        with open(file_path, "wb") as f:
            f.write(json.dumps(new_dict).encode('utf-8'))
    except Exception as e:
        pass


def get_map(file_path):
    try:
        with open(file_path, "rb") as f:
            data_bytes = f.read()
        return jsonify(json.loads(data_bytes.decode('utf-8')))
    except Exception as e:
        return jsonify({})


def get_map_local(file_path):
    try:
        with open(file_path, "rb") as f:
            data_bytes = f.read()
        return json.loads(data_bytes.decode('utf-8'))
    except Exception as e:
        return {}


def init_db():
    try:
        # 把数据库直播源logo数据导入内存
        CHANNEL_LOGO.update(redis_get_map(REDIS_KEY_M3U_EPG_LOGO))
    except:
        print("no logo in redis")
    try:
        # 把直播源分组数据导入内存
        CHANNEL_GROUP.update(redis_get_map(REDIS_KEY_M3U_EPG_GROUP))
    except:
        print("no group in redis")
    initProxyModel()
    initProxyServer()
    init_threads_num()
    init_china_dns_port()
    init_china_dns_server()
    init_extra_dns_server()
    init_extra_dns_port()
    init_m3u_whitelist()
    init_m3u_blacklist()
    init_IP()
    init_pass('proxy')
    init_pass('ipv6')
    init_pass('ipv4')
    init_pass('blacklist')
    init_pass('whitelist')
    init_pass('m3u')
    initReloadCacheForSpecial()
    initReloadCacheForNormal()


##########################################################redis key#############################################
REDIS_KEY_M3U_LINK = "m3ulink"
REDIS_KEY_M3U_DATA = "localm3u"
REDIS_KEY_M3U_EPG_LOGO = "m3uepglogo"
REDIS_KEY_M3U_EPG_GROUP = "m3uepggroup"
# 白名单下载链接
REDIS_KEY_WHITELIST_LINK = "whitelistlink"
# 白名单adguardhome
REDIS_KEY_WHITELIST_DATA = "whitelistdata"
# 白名单dnsmasq
REDIS_KEY_WHITELIST_DATA_DNSMASQ = "whitelistdatadnsmasq"
# 黑名单下载链接
REDIS_KEY_BLACKLIST_LINK = "blacklistlink"
# 黑名单openclash-fallback-filter-domain
REDIS_KEY_BLACKLIST_OPENCLASH_FALLBACK_FILTER_DOMAIN_DATA = "blacklistopfallbackfilterdomaindata"
# 黑名单blackdomain
REDIS_KEY_BLACKLIST_DOMAIN_DATA = "blackdomain"
# 白名单中国大陆IPV4下载链接
REDIS_KEY_WHITELIST_IPV4_LINK = "whitelistipv4link"
# 白名单中国大陆IPV4下载数据
REDIS_KEY_WHITELIST_IPV4_DATA = "whitelistipv4data"
# 白名单中国大陆IPV6下载链接
REDIS_KEY_WHITELIST_IPV6_LINK = "whitelistipv6link"
# 白名单中国大陆IPV6下载数据
REDIS_KEY_WHITELIST_IPV6_DATA = "whitelistipv6data"
# 密码本下载链接
REDIS_KEY_PASSWORD_LINK = "passwordlink"
# 节点下载链接
REDIS_KEY_PROXIES_LINK = "proxieslink"
# 代理类型
REDIS_KEY_PROXIES_TYPE = "proxiestype"
# 代理转换配置模板(本地组+网络组):url,name
REDIS_KEY_PROXIES_MODEL = "proxiesmodel"
# 代理转换配置选择的模板:name
REDIS_KEY_PROXIES_MODEL_CHOSEN = "proxiesmodelchosen"
# 代理转换服务器订阅:url,name
REDIS_KEY_PROXIES_SERVER = "proxiesserver"
# 代理转换选择的服务器订阅:url,name
REDIS_KEY_PROXIES_SERVER_CHOSEN = "proxiesserverchosen"
# m3u白名单:关键字,分组
REDIS_KEY_M3U_WHITELIST = "m3uwhitelist"
# m3u白名单:分组,排名
REDIS_KEY_M3U_WHITELIST_RANK = "m3uwhitelistrank"
# m3u黑名单:关键字,
REDIS_KEY_M3U_BLACKLIST = "m3ublacklist"
# 简易DNS域名白名单
REDIS_KEY_DNS_SIMPLE_WHITELIST = "dnssimplewhitelist"
# 简易DNS域名黑名单
REDIS_KEY_DNS_SIMPLE_BLACKLIST = "dnssimpleblacklist"
# 加密订阅密码历史记录,包括当前密码组
REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS = "secretSubscribeHistoryPass"

# 加密订阅密码当前配置
REDIS_KEY_SECRET_PASS_NOW = 'secretpassnow'

redisKeySecretPassNow = {'m3u': '', 'whitelist': '', 'blacklist': '', 'ipv4': '', 'ipv6': '', 'proxy': ''}

# # gitee账号:用户名,仓库名字,path,access Token
REDIS_KEY_GITEE = 'redisKeyGitee'
redisKeyGitee = {'username': '', 'reponame': '', 'path': '', 'accesstoken': ''}

# # github账号:用户名,仓库名字,path,access Token
REDIS_KEY_GITHUB = 'redisKeyGithub'
redisKeyGithub = {'username': '', 'reponame': '', 'path': '', 'accesstoken': ''}

# # webdav账号:ip,端口，用户名，密码，路径,协议(http/https)
REDIS_KEY_WEBDAV = 'redisKeyWebdav'
redisKeyWebDav = {'ip': '', 'port': '', 'username': '', 'password': '', 'path': '', 'agreement': ''}

REDIS_KEY_FUNCTION_DICT = "functiondict"
# 功能开关字典
function_dict = {}

# 白名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
REDIS_KEY_WHITELIST_DATA_SP = "whitelistdatasp"
# 白名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
whitelistSpData = {}

# 黑名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
REDIS_KEY_BLACKLIST_DATA_SP = "blacklistdatasp"
# 黑名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
blacklistSpData = {}

REDIS_KEY_FILE_NAME = "redisKeyFileName"
# 订阅文件名字字典，命名自由化
file_name_dict = {'allM3u': 'allM3u', 'allM3uSecret': 'allM3uSecret', 'aliveM3u': 'aliveM3u', 'healthM3u': 'healthM3u',
                  'tvDomainForAdguardhome': 'tvDomainForAdguardhome',
                  'tvDomainForAdguardhomeSecret': 'tvDomainForAdguardhomeSecret',
                  'whiteListDnsmasq': 'whiteListDnsmasq', 'whiteListDnsmasqSecret': 'whiteListDnsmasqSecret',
                  'whiteListDomian': 'whiteListDomian',
                  'whiteListDomianSecret': 'whiteListDomianSecret',
                  'blackListDomain': 'blackListDomain',
                  'blackListDomainSecret': 'blackListDomainSecret', 'ipv4': 'ipv4', 'ipv4Secret': 'ipv4Secret',
                  'ipv6': 'ipv6',
                  'ipv6Secret': 'ipv6Secret', 'proxyConfig': 'proxyConfig', 'proxyConfigSecret': 'proxyConfigSecret',
                  'whitelistDirectRule': 'whitelistDirectRule', 'blacklistProxyRule': 'blacklistProxyRule',
                  'simpleOpenclashFallBackFilterDomain': 'simpleOpenclashFallBackFilterDomain',
                  'simpleblacklistProxyRule': 'simpleblacklistProxyRule', 'simpleDnsmasq': 'simpleDnsmasq',
                  'simplewhitelistProxyRule': 'simplewhitelistProxyRule', 'minTimeout': '5', 'maxTimeout': '30',
                  'usernameSys': 'admin', 'passwordSys': 'password', 'normalM3uClock': '7200',
                  'normalSubscriberClock': '10800',
                  'failTs': 'https://raw.githubusercontent.com/paperbluster/ppap/main/update.mp4',
                  'proxySubscriberClock': '3600', 'autoDnsSwitchClock': '600',
                  'reliveAlistTsTime': '600', 'recycle': '7200', 'chinaTopDomain': 'cn,中国', 'foreignTopDomain':
                      'xyz,club,online,site,top,win', 'dnsMode': '0', 'dnsLimitRecordSecondDomain': '15',
                  'dnsLimitRecordSecondLenDomain': '15', 'lastaliveport': '0'}

# 单独导入导出使用一个配置,需特殊处理:{{url:{pass,name}}}
# 下载网络配置并且加密后上传:url+加密密钥+加密文件名字
REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME = 'downloadAndSecretUploadUrlPasswordAndName'
downAndSecUploadUrlPassAndName = {}

# 下载加密网络配置并且解密还原成源文件:加密url+加密密钥+源文件名字
REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME = 'downloadAndDeSecretUrlPasswordAndName'
downAndDeSecUrlPassAndName = {}

# youtube直播源
REDIS_KEY_YOUTUBE = 'redisKeyYoutube'
# youtube直播源地址，频道名字
redisKeyYoutube = {}

# bilibili直播源
REDIS_KEY_BILIBILI = 'redisKeyBilibili'
# bilibili直播源地址，频道名字
redisKeyBilili = {}

# huya直播源
REDIS_KEY_HUYA = 'redisKeyHuya'
# huya直播源地址，频道名字
redisKeyHuya = {}

# YY直播源
REDIS_KEY_YY = 'redisKeyYY'
# YY直播源地址，频道名字
redisKeyYY = {}

# DOUYIN直播源
REDIS_KEY_DOUYIN = 'redisKeyDOUYIN'
# DOUYIN直播源地址，频道名字
redisKeyDOUYIN = {}

# TWITCH直播源
REDIS_KEY_TWITCH = 'redisKeyTWITCH'
# TWITCH直播源地址，频道名字
redisKeyTWITCH = {}

# normal直播源
REDIS_KEY_NORMAL = 'redisKeyNormal'
# normal直播源地址，频道名字
redisKeyNormal = {}
# normal真实m3u8地址
REDIS_KEY_NORMAL_M3U = 'redisKeyNormalM3U'
# normal频道名字,真实m3u8地址
redisKeyNormalM3U = {}

# alist直播源
REDIS_KEY_ALIST = 'redisKeyAlist'
# alist直播源网站某个子路径，该路径通用密码
redisKeyAlist = {}
# alist真实m3u8地址
REDIS_KEY_Alist_M3U = 'redisKeyAlistM3u'
# alist uuid,请求url地址，主要是查找m3u8路径下全部文件是否有sign属性
redisKeyAlistM3u = {}
# alist真实m3u8地址
REDIS_KEY_Alist_M3U_TS_PATH = 'redisKeyAlistM3uTsPath'
# alist uuid,相对路径，主要是配合是否存在sign拼接出真实的ts url
redisKeyAlistM3uTsPath = {}

port_live = 22771
# 存放alist的m3u8文件目录
SLICES_ALIST_M3U8 = "/app/m3u8"

NORMAL_REDIS_KEY = 'normalRedisKey'
# 全部有redis备份字典key-普通redis结构，重要且数据量比较少的
allListArr = [REDIS_KEY_M3U_LINK, REDIS_KEY_WHITELIST_LINK, REDIS_KEY_BLACKLIST_LINK, REDIS_KEY_WHITELIST_IPV4_LINK,
              REDIS_KEY_WHITELIST_IPV6_LINK, REDIS_KEY_PASSWORD_LINK, REDIS_KEY_PROXIES_LINK, REDIS_KEY_PROXIES_TYPE,
              REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN, REDIS_KEY_PROXIES_SERVER,
              REDIS_KEY_PROXIES_SERVER_CHOSEN, REDIS_KEY_GITEE, REDIS_KEY_GITHUB,
              REDIS_KEY_SECRET_PASS_NOW, REDIS_KEY_WEBDAV, REDIS_KEY_FILE_NAME,
              REDIS_KEY_FUNCTION_DICT, REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS]

# 数据巨大的redis配置,一键导出时单独导出每个配置
hugeDataList = [REDIS_KEY_BILIBILI, REDIS_KEY_DNS_SIMPLE_WHITELIST, REDIS_KEY_DNS_SIMPLE_BLACKLIST, REDIS_KEY_YOUTUBE,
                REDIS_KEY_M3U_WHITELIST_RANK, REDIS_KEY_M3U_BLACKLIST, REDIS_KEY_M3U_WHITELIST, REDIS_KEY_HUYA,
                REDIS_KEY_YY, REDIS_KEY_TWITCH, REDIS_KEY_DOUYIN, REDIS_KEY_ALIST, REDIS_KEY_NORMAL]

SPECIAL_REDIS_KEY = 'specialRedisKey'
specialRedisKey = [REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME,
                   REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME]

# Adguardhome屏蔽前缀
BLACKLIST_ADGUARDHOME_FORMATION = "0.0.0.0 "
# dnsmasq白名单前缀
BLACKLIST_DNSMASQ_FORMATION_LEFT = "server=/"
# dnsmasq白名单后缀
BLACKLIST_DNSMASQ_FORMATION_right = "/114.114.114.114"
# 用于匹配纯粹域名的正则表达式
domain_regex = r'^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$'
# 用于匹配泛化匹配的域名规则的正则表达式
wildcard_regex = r'^\*\.[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$'
# 用于匹配泛化匹配的域名规则的正则表达式
wildcard_regex2 = r'^\+\.[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$'
# 用于匹配dnsmasq白名单格式
pattern = r'^server=\/[a-zA-Z0-9.-]+\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+)$'
OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT = "    - \""
OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT = "\""

# name,logo
CHANNEL_LOGO = {}
# name,group
CHANNEL_GROUP = {}
defalutname = "佚名"

# 订阅模板转换服务器地址API
URL = "http://192.168.5.1:25500/sub"
# m3u下载处理时提取直播源域名在adguardhome放行，只放行m3u域名不管分流
white_list_adguardhome = {}
# 白名单总缓存，数据大量，是全部规则缓存
white_list_nameserver_policy = {}
# DOMAIN-SUFFIX,域名,DIRECT--以该域名结尾的全部直连
white_list_Direct_Rules = {}
# 黑名单总缓存，数据大量，是全部规则缓存
black_list_nameserver_policy = {}
# DOMAIN-SUFFIX,域名,DIRECT--以该域名结尾的全部代理
black_list_Proxy_Rules = {}

# 下载的域名白名单存储到redis服务器里
REDIS_KEY_WHITE_DOMAINS = "whitedomains"
# 下载的域名黑名单存储到redis服务器里
REDIS_KEY_BLACK_DOMAINS = "blackdomains"

# 0-数据未更新 1-数据已更新 max-所有服务器都更新完毕(有max个服务器做负载均衡)
REDIS_KEY_UPDATE_THREAD_NUM_FLAG = "updatethreadnumflag"
REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG = "updatechinadnsserverflag"
REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG = "updatechinadnsportflag"
REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG = "updateextradnsserverflag"
REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG = "updateextradnsportflag"
REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG = "updatesimplewhitelistflag"
REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG = "updatesimpleblacklistflag"
REDIS_KEY_UPDATE_WHITE_LIST_SP_FLAG = "updatewhitelistspflag"
REDIS_KEY_UPDATE_BLACK_LIST_SP_FLAG = "updateblacklistspflag"
REDIS_KEY_UPDATE_CHINA_DOMAIN_FLAG = "updatechinadomainflag"
REDIS_KEY_UPDATE_FOREIGN_DOMAIN_FLAG = "updateforeigndomainflag"
REDIS_KEY_UPDATE_DNS_MODE_FLAG = "updatednsmodeflag"
REDIS_KEY_UPDATE_DNS_LIMIT_SECOND_DOMAIN_FLAG = "updatednslimitseconddomainflag"
REDIS_KEY_UPDATE_DNS_LIMIT_SECOND_DOMAIN_LEN_FLAG = "updatednslimitseconddomainlenflag"
REDIS_KEY_OPEN_AUTO_UPDATE_SIMPLE_WHITE_AND_BLACK_LIST_FLAG = 'openAutoUpdateSimpleWhiteAndBlackList'

REDIS_KEY_THREADS = "threadsnum"
threadsNum = {REDIS_KEY_THREADS: 1000}

REDIS_KEY_CHINA_DNS_SERVER = "chinadnsserver"
chinadnsserver = {REDIS_KEY_CHINA_DNS_SERVER: ""}

REDIS_KEY_CHINA_DNS_PORT = "chinadnsport"
chinadnsport = {REDIS_KEY_CHINA_DNS_PORT: 0}

REDIS_KEY_EXTRA_DNS_SERVER = "extradnsserver"
extradnsserver = {REDIS_KEY_EXTRA_DNS_SERVER: ""}

REDIS_KEY_EXTRA_DNS_PORT = "extradnsport"
extradnsport = {REDIS_KEY_EXTRA_DNS_PORT: 0}

REDIS_KEY_DNS_QUERY_NUM = "dnsquerynum"
dnsquerynum = {REDIS_KEY_DNS_QUERY_NUM: 1000}

REDIS_KEY_DNS_TIMEOUT = "dnstimeout"
dnstimeout = {REDIS_KEY_DNS_TIMEOUT: 30}

REDIS_KEY_IP = "ip"
ip = {REDIS_KEY_IP: ""}


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


def check_auth(username, password):
    usernameSys = getFileNameByTagName('usernameSys')
    passwordSys = getFileNameByTagName('passwordSys')
    if username == usernameSys and password == passwordSys:
        return True
    # 进行用户名和密码验证的逻辑
    # 如果验证通过，返回True；否则返回False
    return False


def authenticate():
    message = {'message': "Authentication failed."}
    resp = jsonify(message)
    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
    return resp


# 公共路径，放的全部是加密文件，在公共服务器开放这个路径访问
public_path = '/app/ini/'
# 隐私路径，放的全部是明文文件，在公共服务器不要开放这个路径访问
secret_path = '/app/secret/'

tv_dict_youtube = {}

tv_dict_bilibili = {}

tv_dict_huya = {}

tv_dict_yy = {}

tv_dict_douyin = {}

tv_dict_twitch = {}

tv_dict_normal = {}


##############################################################bilibili############################################
async def pingM3u(session, value, real_dict, key, mintimeout, maxTimeout, now_uuid, uuid_cache):
    try:
        if not is_same_action_uuid(now_uuid, uuid_cache):
            return
        async with  session.get(value, timeout=mintimeout) as response:
            if response.status == 200:
                real_dict[key] = value
    except asyncio.TimeoutError:
        try:
            if not is_same_action_uuid(now_uuid, uuid_cache):
                return
            async with  session.get(value, timeout=maxTimeout) as response:
                if response.status == 200:
                    real_dict[key] = value
        except Exception as e:
            pass
    except Exception as e:
        pass


##########################################################redis数据库操作#############################################
# redis增加和修改

url_flask = '/api/data2'


def redis_add(key, value):
    count = 0
    while count < 3:
        try:
            data = {
                'cacheKey': key,
                'action': 'add_single',
                'dict_data': value
            }
            with app.test_client() as client:
                response = client.post(url_flask, data=data)
                if response.status_code == 200:
                    break
            count += 1
            time.sleep(1)
        except Exception as e:
            count += 1
            time.sleep(1)


# redis查询
def redis_get(key):
    count = 0
    while count < 3:
        try:
            data = {
                'cacheKey': key,
                'action': 'get_single',
            }
            with app.test_client() as client:
                response = client.post(url_flask, data=data)
                # 字符串格式的json数据
                response_data = response.get_json()
                return response_data['result']
        except:
            count += 1
            time.sleep(1)
    return None
    # file_path = os.path.join(DB_PATH, f'{key}.txt')
    # count = 0
    # while count < 3:
    #     try:
    #         return get_single_local(file_path)
    #     except:
    #         count += 1
    # return None


# redis存储map字典，字典主键唯一，重复主键只会复写
def redis_add_map(key, my_dict):
    count = 0
    while count < 3:
        try:
            data = {
                'cacheKey': key,
                'action': 'add_map',
                'dict_data': json.dumps(my_dict).encode('utf-8')
            }
            with app.test_client() as client:
                response = client.post(url_flask, data=data)
                if response.status_code == 200:
                    break
            count += 1
            time.sleep(1)
        except Exception as e:
            count += 1
            time.sleep(1)
    # file_path = os.path.join(DB_PATH, f'{key}.txt')
    # add_map_local(file_path, my_dict)


# redis取出map字典
def redis_get_map(key):
    count = 0
    while count < 3:
        try:
            data = {
                'cacheKey': key,
                'action': 'get_map'
            }
            with app.test_client() as client:
                response = client.post(url_flask, data=data)
                # 字符串格式的json数据
                response_data = response.get_json()
                return response_data
        except Exception as e:
            count += 1
            time.sleep(1)
    return {}
    # file_path = os.path.join(DB_PATH, f'{key}.txt')
    # dict = get_map_local(file_path)
    # if len(dict) == 0:
    #     return {}
    # return dict


# redis取出map字典key
def redis_get_map_keys(key):
    try:
        redis_dict = redis_get_map(key)
        array = [key for key in redis_dict.keys()]
        return array, redis_dict
    except:
        return [], {}


# redis删除map字典
def redis_del_map(key):
    count = 0
    while count < 3:
        try:
            data = {
                'cacheKey': key,
                'action': 'delete'
            }
            with app.test_client() as client:
                response = client.post(url_flask, data=data)
                if response.status_code == 200:
                    break
            count += 1
            time.sleep(1)
        except Exception as e:
            count += 1
            time.sleep(1)
    # file_path = os.path.join(DB_PATH, f'{key}.txt')
    # delete_cache_local(file_path)


# redis删除字典单个键值对
def redis_del_map_key(key, map_key):
    try:
        return redis_del_map_keys(key, [map_key])
    except Exception as e:
        return 0


# redis删除字典多个键值对
def redis_del_map_keys(key, map_keys):
    count = 0
    while count < 3:
        try:
            data = {
                'cacheKey': key,
                'action': 'delete_keys',
                'dict_data': json.dumps(map_keys).encode('utf-8')
            }
            with app.test_client() as client:
                response = client.post(url_flask, data=data)
                if response.status_code == 200:
                    break
            count += 1
            time.sleep(1)
        except Exception as e:
            count += 1
            time.sleep(1)
    # file_path = os.path.join(DB_PATH, f'{key}.txt')
    # delete_keys_local(file_path, map_keys)


def redis_public_message(message):
    count = 0
    while count < 3:
        try:
            url = 'http://localhost:22772/api/data'
            data = {
                'message': message
            }
            with app.test_client() as client:
                response = client.post(url, data=data)
                if response.status_code == 200:
                    break
            count += 1
            time.sleep(1)
        except Exception as e:
            count += 1
            time.sleep(1)
    # global message_dict
    # message_dict[message] = ''


#########################################################通用工具区#################################################
# 上传订阅配置
def upload_json_base(rediskey, file_content):
    try:
        json_dict = json.loads(file_content)
        if rediskey not in specialRedisKey:
            if rediskey == REDIS_KEY_M3U_WHITELIST:
                dict_final = {}
                for key, value in json_dict.items():
                    dict_final[key.lower()] = value
                redis_add_map(rediskey, dict_final)
                importToReloadCache(rediskey, dict_final)
            else:
                redis_add_map(rediskey, json_dict)
                importToReloadCache(rediskey, json_dict)
        else:
            importToReloadCacheForSpecial(rediskey, json_dict)
        if 'dnssimpleblacklist' == rediskey:
            redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG}_3_1')
        elif 'dnssimplewhitelist' == rediskey:
            redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG}_3_1')
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred: ", e)
        return jsonify({'success': False})


# 上次更新时间戳
time_clock_update_dict = {'proxySubscriberClock': '0', 'normalM3uClock': '0',
                          'autoDnsSwitchClock': '0', 'normalSubscriberClock': '0', 'recycle': '0',
                          'checkAlive': '0', 'migu': '0', 'miguId': '0', 'cq': '0', 'cqId': '0', 'youtubeId': '0',
                          'bilibiliId': '0', 'huyaId': '0', 'yyId': '0', 'twitchId': '0', 'douyinId': '0',
                          'youtubelockuuid': '0', 'twitchlockuuid': '0',
                          'bilibililockuuid': '0', 'huyalockuuid': '0', 'yylockuuid': '0', 'douyinlockuuid': '0'}


def is_same_action_uuid(old_uuid, cachekey):
    global time_clock_update_dict
    now_uuid = time_clock_update_dict[cachekey]
    if now_uuid == old_uuid:
        return True
    return False


# true-需要更新 false-不需要更新
def is_update_clock_live(cachekey):
    lastUpdateTime = float(time_clock_update_dict[cachekey])
    if cachekey == 'migu' or cachekey == 'cq':
        if (time.time() - lastUpdateTime) >= 600:
            return True
    else:
        if (time.time() - lastUpdateTime) >= 3600:
            return True
    return False


# true-需要更新 false-不需要更新
def is_update_clock(cachekey):
    lastUpdateTime = float(time_clock_update_dict[cachekey])
    sysTime = int(getFileNameByTagName(cachekey))
    if (time.time() - lastUpdateTime) >= sysTime:
        return True
    return False


def update_clock(cachekey):
    time_clock_update_dict[cachekey] = str(time.time())


def recycle():
    past_list_item.clear()
    CHANNEL_LOGO.clear()
    CHANNEL_GROUP.clear()


def clock_thread():
    init_db()
    while True:
        # 回收内存
        if is_update_clock('recycle'):
            recycle()
            update_clock('recycle')
        # 节点订阅下载
        if is_update_clock('proxySubscriberClock'):
            chaoronghe6()
            update_clock('proxySubscriberClock')
        # 自动简易dns订阅文件生成
        if isOpenFunction('switch24') and is_update_clock('autoDnsSwitchClock'):
            chaoronghe7()
            chaoronghe8()
            update_clock('autoDnsSwitchClock')
        # 通常直播源下载定时器
        if isOpenFunction('switch25') and is_update_clock('normalM3uClock'):
            chaoronghe()
            update_clock('normalM3uClock')
        if is_update_clock('normalSubscriberClock'):
            if isOpenFunction('switch26'):
                # 执行方法-域名白名单
                chaoronghe2()
            if isOpenFunction('switch13'):
                # 执行方法-域名黑名单
                chaoronghe3()
            if isOpenFunction('switch27'):
                # 执行方法-ipv4
                chaoronghe4()
            if isOpenFunction('switch28'):
                # 执行方法-ipv6
                chaoronghe5()
            if isOpenFunction('switch33'):
                # 执行方法-下载加密上传
                chaoronghe9()
            if isOpenFunction('switch34'):
                # 执行方法-下载解密
                chaoronghe10()
            update_clock('normalSubscriberClock')
        time.sleep(3600)


def update_git(file_name, uploadGitee, uploadGithub, uploadWebdav):
    # 加密文件上传至gitee,
    if uploadGitee:
        updateFileToGitee(file_name)
    # 加密文件上传至github,
    if uploadGithub:
        updateFileToGithub(file_name)
    # 加密文件上传至webdav,
    if uploadWebdav:
        updateFileToWebDAV(file_name)


def toggle_m3u(functionId, value):
    global function_dict
    if functionId == 'switch24':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
        redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG}_3_1')
    elif functionId == 'switch25':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch26':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch13':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch27':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch28':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch33':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch34':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)


async def checkWriteHealthM3u(url):
    # 关闭白名单直播源生成
    if not isOpenFunction('switch5'):
        return
    name = tmp_url_tvg_name_dict.get(url)
    if name:
        path2 = f"{secret_path}{getFileNameByTagName('healthM3u')}.m3u"
        async with aiofiles.open(path2, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
            await f.write(f'{name}{url}\n')
        del tmp_url_tvg_name_dict[url]
    else:
        return


async def download_url(session, url, value, now_uuid):
    try:
        if not is_same_action_uuid(now_uuid, 'checkAlive'):
            return
        async with session.get(url) as resp:  # 使用asyncio.Semaphore限制TCP连接的数量
            if resp.status == 200:
                path = f"{secret_path}{getFileNameByTagName('aliveM3u')}.m3u"
                async with aiofiles.open(path, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
                    await f.write(f'{value}{url}\n')
                await checkWriteHealthM3u(url)
    except Exception as e:
        print(f"Error occurred while downloading {url}: {e}")


def update_uuid_action(cachekey):
    global time_clock_update_dict
    now_uuid = time_clock_update_dict[cachekey]
    while True:
        new_uuid = generate_only_uuid(random.randrange(0, int(time.time())))
        if new_uuid == now_uuid:
            continue
        time_clock_update_dict[cachekey] = new_uuid
        break
    return time_clock_update_dict.get(cachekey)


async def asynctask(m3u_dict):
    now_uuid = update_uuid_action('checkAlive')
    # sem = asyncio.Semaphore(100)  # 限制TCP连接的数量为100个
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url, value in m3u_dict.items():
            task = asyncio.create_task(download_url(session, url, value, now_uuid))
            tasks.append(task)
        await asyncio.gather(*tasks)


def copyAndRename(source_file):
    with open(source_file, 'rb') as fsrc:
        return fsrc.read()


def check_file(m3u_dict):
    try:
        """
            检查直播源文件是否存在且没有被占用
            """
        # chaoronghe24()
        # chaoronghe25()
        oldChinaChannelDict = redis_get_map(REDIS_KET_TMP_CHINA_CHANNEL)
        if oldChinaChannelDict and len(oldChinaChannelDict) > 0:
            tmp_url_tvg_name_dict.update(oldChinaChannelDict)
        if len(tmp_url_tvg_name_dict.keys()) > 0:
            redis_add_map(REDIS_KET_TMP_CHINA_CHANNEL, tmp_url_tvg_name_dict)
        path = f"{secret_path}{getFileNameByTagName('aliveM3u')}.m3u"
        if os.path.exists(path):
            os.remove(path)
        path3 = f"{secret_path}youtube.m3u"
        path4 = f"{secret_path}bilibili.m3u"
        path5 = f"{secret_path}huya.m3u"
        path6 = f"{secret_path}YY.m3u"
        path7 = f"{secret_path}TWITCH.m3u"
        path8 = f"{secret_path}Douyin.m3u"
        # path9 = f"{secret_path}alist.m3u"
        path10 = f"{secret_path}normal.m3u"
        source = ''
        if os.path.exists(path3):
            source += copyAndRename(path3).decode()
        if os.path.exists(path4):
            source += '\n'
            source += copyAndRename(path4).decode()
        if os.path.exists(path5):
            source += '\n'
            source += copyAndRename(path5).decode()
        if os.path.exists(path6):
            source += '\n'
            source += copyAndRename(path6).decode()
        if os.path.exists(path7):
            source += '\n'
            source += copyAndRename(path7).decode()
        if os.path.exists(path8):
            source += '\n'
            source += copyAndRename(path8).decode()
        # if os.path.exists(path9):
        #     source += '\n'
        #     source += copyAndRename(path9).decode()
        if os.path.exists(path10):
            source += '\n'
            source += copyAndRename(path10).decode()
        with open(path, 'wb') as fdst:
            fdst.write(source.encode('utf-8'))
        path2 = f"{secret_path}{getFileNameByTagName('healthM3u')}.m3u"
        if isOpenFunction('switch5'):
            if os.path.exists(path2):
                os.remove(path2)
            source2 = ''
            if os.path.exists(path3):
                source2 += copyAndRename(path3).decode()
            if os.path.exists(path4):
                source2 += copyAndRename(path4).decode()
            if os.path.exists(path5):
                source2 += copyAndRename(path5).decode()
            if os.path.exists(path6):
                source2 += copyAndRename(path6).decode()
            if os.path.exists(path7):
                source2 += copyAndRename(path7).decode()
            if os.path.exists(path8):
                source2 += copyAndRename(path8).decode()
            # if os.path.exists(path9):
            #     source2 += copyAndRename(path9).decode()
            if os.path.exists(path10):
                source2 += copyAndRename(path10).decode()
            with open(path2, 'wb') as fdst:
                fdst.write(source2.encode('utf-8'))
            # 异步缓慢检测出有效链接
        if len(m3u_dict) == 0:
            return
        asyncio.run(asynctask(m3u_dict))
    except:
        pass


def checkbytes(url):
    if isinstance(url, bytes):
        return decode_bytes(url).strip()
    else:
        return url


# 判断是否需要解密
def checkToDecrydecrypt(url, redis_dict, m3u_string):
    password = redis_dict.get(url)
    if password:
        password = password.decode()
        if password != "":
            blankContent = decrypt(password, m3u_string)
            return blankContent
    return m3u_string


# 判断是否需要解密
def checkToDecrydecrypt3(url, redis_dict, m3u_string, filenameDict):
    password = redis_dict.get(url)
    if password:
        if password != "":
            blankContent = decrypt(password, m3u_string)
            thread_write_bytes_to_file(filenameDict[url], checkbytes(blankContent).encode())
    else:
        if isinstance(m3u_string, bytes):
            thread_write_bytes_to_file(filenameDict[url], m3u_string)
        else:
            thread_write_bytes_to_file(filenameDict[url], m3u_string.encode())


# 判断是否需要加密
def checkToDecrydecrypt2(url, redis_dict, m3u_string, filenameDict, secretNameDict, uploadGitee,
                         uploadGithub, uploadWebdav):
    password = redis_dict.get(url)
    if password:
        if password != "":
            secretContent = encrypt2(m3u_string, password)
            secretFileName = secretNameDict[url]
            thread_write_bytes_to_file(secretFileName, secretContent)
            update_git(os.path.basename(secretFileName), uploadGitee, uploadGithub, uploadWebdav)
    if isinstance(m3u_string, bytes):
        thread_write_bytes_to_file(filenameDict[url], m3u_string)
    else:
        thread_write_bytes_to_file(filenameDict[url], m3u_string.encode('utf-8'))


def write_to_file(data, file):
    with open(file, 'a', encoding='utf-8') as f:
        for k, v in data:
            f.write(f'{v}{k}\n')


def worker(queue, file):
    while True:
        data = queue.get()
        if data is None:
            break
        write_to_file(data, file)
        queue.task_done()


def write_to_file2(data, file):
    with open(file, 'a', ) as f:
        for line in data:
            f.write(f'{line}')


def worker2(queue, file):
    while True:
        data = queue.get()
        if data is None:
            break
        write_to_file2(data, file)
        queue.task_done()


def download_files(urls, redis_dict):
    if len(urls) == 0:
        return ''
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {executor.submit(fetch_url, url, redis_dict): url for url in urls}
        # 获取各个future对象的返回值并存储在字典中
        results = []
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
            except Exception as exc:
                print('%r generated an exception: %s' % (url, exc))
            else:
                results.append(result)
    # 将结果按照原始URL列表的顺序排序并返回它们
    return "".join(results)


def fetch_url(url, redis_dict):
    try:
        response = requests.get(url, timeout=30, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        m3u_string = checkToDecrydecrypt(url, redis_dict, m3u_string)
        # 转换成字符串格式返回
        m3u_string = checkbytes(m3u_string)
        m3u_string += "\n"
        # print(f"success to fetch URL: {url}")
        return m3u_string
    except requests.exceptions.Timeout:
        response = requests.get(url, timeout=60, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        m3u_string = checkToDecrydecrypt(url, redis_dict, m3u_string)
        # 转换成字符串格式返回
        m3u_string = checkbytes(m3u_string)
        m3u_string += "\n"
        return m3u_string
    except requests.exceptions.RequestException as e:
        try:
            url = url.decode('utf-8')
        except:
            pass
        response = requests.get(url, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        m3u_string = checkToDecrydecrypt(url, redis_dict, m3u_string)
        # 转换成字符串格式返回
        m3u_string = checkbytes(m3u_string)
        # print(f"success to fetch URL: {url}")
        m3u_string += "\n"
        return m3u_string
        # print("other error: " + url, e)
    except:
        pass


def fetch_url2(url, passwordDict, filenameDict, secretNameDict, uploadGitee, uploadGithub, uploadWebdav):
    try:
        response = requests.get(url, timeout=30, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt2(url, passwordDict, m3u_string, filenameDict, secretNameDict, uploadGitee,
                             uploadGithub, uploadWebdav)
    except requests.exceptions.Timeout:
        response = requests.get(url, timeout=60, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt2(url, passwordDict, m3u_string, filenameDict, secretNameDict, uploadGitee,
                             uploadGithub, uploadWebdav)
    except requests.exceptions.RequestException as e:
        try:
            url = url.decode('utf-8')
        except:
            pass
        response = requests.get(url, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt2(url, passwordDict, m3u_string, filenameDict, secretNameDict, uploadGitee,
                             uploadGithub, uploadWebdav)
    except Exception as e:
        print("fetch_url2 error:", e)
        pass


def fetch_url3(url, passwordDict, filenameDict):
    try:
        response = requests.get(url, timeout=30, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt3(url, passwordDict, m3u_string, filenameDict)
    except requests.exceptions.Timeout:
        response = requests.get(url, timeout=60, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt3(url, passwordDict, m3u_string, filenameDict)
    except requests.exceptions.RequestException as e:
        try:
            url = url.decode('utf-8')
        except:
            pass
        response = requests.get(url, headers=headers_YY)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt3(url, passwordDict, m3u_string, filenameDict)
    except Exception as e:
        print("fetch_url3 error:", e)
        pass


#
def download_files2(urls, passwordDict, filenameDict, secretNameDict, uploadGitee, uploadGithub,
                    uploadWebdav):
    if len(urls) == 0:
        return
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {
            executor.submit(fetch_url2, url, passwordDict, filenameDict, secretNameDict, uploadGitee,
                            uploadGithub, uploadWebdav): url for
            url in urls}
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)


def download_files3(urls, passwordDict, filenameDict):
    if len(urls) == 0:
        return
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {
            executor.submit(fetch_url3, url, passwordDict, filenameDict): url for
            url in urls}
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)


# 添加一条数据进入字典
def addlist(request, rediskey):
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map(rediskey, my_dict)
    return jsonify({'addresult': "add success"})


# update 开启m3u域名白名单加密文件上传gitee
# secretfile 开启m3u域名白名单生成加密文件
def writeTvList(fileName, secretfilename):
    distribute_data(white_list_adguardhome, fileName, 10)
    white_list_adguardhome.clear()
    download_secert_file(fileName, secretfilename, 'm3u',
                         isOpenFunction('switch8'), isOpenFunction('switch7'), isOpenFunction('switch30'),
                         isOpenFunction('switch31'), isOpenFunction('switch32'))


# whitelist-加密上传   switch11
# whitelist-加密生成   switch12
def writeOpenclashNameServerPolicy():
    if white_list_nameserver_policy and len(white_list_nameserver_policy) > 0:
        # 更新redis数据库白名单三级分层字典
        redis_del_map(REDIS_KEY_WHITELIST_DATA_SP)
        global whitelistSpData
        redis_add_map(REDIS_KEY_WHITELIST_DATA_SP, whitelistSpData)
        whitelistSpData.clear()
        # 通知dns服务器更新内存
        redis_public_message(REDIS_KEY_UPDATE_WHITE_LIST_SP_FLAG)
        # redis_add(REDIS_KEY_UPDATE_WHITE_LIST_FLAG, 1)
        # 更新redis数据库白名单
        # redis_add_map(REDIS_KEY_WHITE_DOMAINS, white_list_nameserver_policy)
        path = f"{secret_path}{getFileNameByTagName('whiteListDomian')}.txt"
        distribute_data(white_list_nameserver_policy, path, 10)
        white_list_nameserver_policy.clear()
        path2 = f"{secret_path}{getFileNameByTagName('whitelistDirectRule')}.txt"
        distribute_data(white_list_Direct_Rules, path2, 10)
        white_list_Direct_Rules.clear()

        # 白名单加密
        download_secert_file(path, f"{public_path}{getFileNameByTagName('whiteListDomianSecret')}.txt", 'whitelist',
                             isOpenFunction('switch12'), isOpenFunction('switch11'),
                             isOpenFunction('switch30'), isOpenFunction('switch31'), isOpenFunction('switch32'))


def writeBlackList():
    if black_list_nameserver_policy and len(black_list_nameserver_policy) > 0:
        # 更新redis数据库白名单三级分层字典
        redis_del_map(REDIS_KEY_BLACKLIST_DATA_SP)
        global blacklistSpData
        redis_add_map(REDIS_KEY_BLACKLIST_DATA_SP, blacklistSpData)
        blacklistSpData.clear()
        # 通知dns服务器更新内存
        redis_public_message(REDIS_KEY_UPDATE_BLACK_LIST_SP_FLAG)
        # 更新redis数据库黑名单
        # redis_add_map(REDIS_KEY_BLACK_DOMAINS, black_list_nameserver_policy)
        # 通知dns服务器更新内存
        # redis_add(REDIS_KEY_UPDATE_BLACK_LIST_FLAG, 1)
        path = f"{secret_path}{getFileNameByTagName('blackListDomain')}.txt"
        distribute_data(black_list_nameserver_policy, path, 10)
        black_list_nameserver_policy.clear()

        path2 = f"{secret_path}{getFileNameByTagName('blacklistProxyRule')}.txt"
        distribute_data(black_list_Proxy_Rules, path2, 10)
        black_list_Proxy_Rules.clear()

        # 黑名单加密
        download_secert_file(path, f"{public_path}{getFileNameByTagName('blackListDomainSecret')}.txt", 'blacklist',
                             isOpenFunction('switch16'),
                             isOpenFunction('switch17'),
                             isOpenFunction('switch30'), isOpenFunction('switch31'), isOpenFunction('switch32'))


def updateAdguardhomeWithelistForM3us(urls):
    if len(urls) == 0:
        return
    for url in urls:
        updateAdguardhomeWithelistForM3u(url.decode("utf-8"))


def chaoronghebase2(redisKeyData, fileName, left1, right1, fileName2, left2):
    old_dict = redis_get_map(redisKeyData)
    if not old_dict or len(old_dict) == 0:
        return "empty"
    newDict = {}
    newDict2 = {}
    for key, value in old_dict.items():
        newDict[left1 + key + right1] = ""
        newDict2[left2 + key] = ''
    # 同步方法写出全部配置
    distribute_data(newDict, fileName, 10)
    distribute_data(newDict2, fileName2, 10)
    return "result"


def fuck_m3u_to_txt(file_path, txt_path):
    # 数据源，字典（词库+新分组名字），新分组名字
    resultContent = m3uToTxt(copyAndRename(file_path).splitlines())
    if os.path.exists(txt_path):
        os.remove(txt_path)
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(resultContent)


def chaorongheBase(redisKeyLink, processDataMethodName, redisKeyData, fileName=None):
    results, redis_dict = redis_get_map_keys(redisKeyLink)
    ism3u = processDataMethodName == 'process_data_abstract'
    global CHANNEL_LOGO
    global CHANNEL_GROUP
    # 生成直播源域名-无加密
    if ism3u:
        thread = threading.Thread(target=updateAdguardhomeWithelistForM3us, args=(results,))
        thread.start()
        tmp_url_tvg_name_dict.clear()
    result = download_files(results, redis_dict)
    if len(result) > 0:
        # 格式优化
        # my_dict = formattxt_multithread(result.split("\n"), 100)
        my_dict = formattxt_multithread(result.splitlines(), processDataMethodName)
        # my_dict = formattxt_multithread(result.splitlines(), 100)
        if ism3u:
            CHANNEL_LOGO.clear()
            CHANNEL_GROUP.clear()
            CHANNEL_LOGO = redis_get_map(REDIS_KEY_M3U_EPG_LOGO)
            CHANNEL_GROUP = redis_get_map(REDIS_KEY_M3U_EPG_GROUP)
    else:
        if not ism3u:
            return "empty"
        else:
            my_dict = {}
    if len(my_dict) == 0:
        if not ism3u:
            return "empty"
    if ism3u:
        old_dict = redis_get_map(redisKeyData)
        my_dict.update(old_dict)
    else:
        redis_del_map(redisKeyData)
    if ism3u:
        if isOpenFunction('switch4'):
            if len(my_dict) > 0 and fileName:
                distribute_data(my_dict, fileName, 10)
                fuck_m3u_to_txt(fileName, f"{secret_path}allM3u.txt")
    else:
        if fileName:
            # 同步方法写出全部配置
            distribute_data(my_dict, fileName, 10)
    if ism3u:
        if len(my_dict) > 0:
            redis_add_map(redisKeyData, my_dict)
        # M3U域名tvlist - 无加密
        if isOpenFunction('switch6'):
            # 生成直播源域名-无加密
            thread = threading.Thread(target=writeTvList,
                                      args=(f"{secret_path}{getFileNameByTagName('tvDomainForAdguardhome')}.txt",
                                            f"{public_path}{getFileNameByTagName('tvDomainForAdguardhomeSecret')}.txt"))
            thread.start()
        if isOpenFunction('switch'):
            # 神速直播源有效性检测
            thread2 = threading.Thread(target=check_file, args=(my_dict,))
            thread2.start()
        if len(CHANNEL_LOGO) > 0:
            # logo,group更新
            redis_add_map(REDIS_KEY_M3U_EPG_LOGO, CHANNEL_LOGO)
            CHANNEL_LOGO.clear()
        if len(CHANNEL_GROUP) > 0:
            redis_add_map(REDIS_KEY_M3U_EPG_GROUP, CHANNEL_GROUP)
            CHANNEL_GROUP.clear()
        # 开启直播源加密:
        # 加密全部直播源
        thread3 = threading.Thread(target=download_secert_file,
                                   args=(
                                       fileName, f"{public_path}{getFileNameByTagName('allM3uSecret')}.txt", 'm3u',
                                       isOpenFunction('switch2'),
                                       isOpenFunction('switch3'), isOpenFunction('switch30'),
                                       isOpenFunction('switch31'), isOpenFunction('switch32')))
        thread3.start()
        return "result"
    # 域名白名单
    if processDataMethodName == 'process_data_abstract3':
        # whitelist,白名单域名写入redis
        thread = threading.Thread(target=writeOpenclashNameServerPolicy)
        # 生成dnsmasq加密
        thread2 = threading.Thread(target=download_secert_file,
                                   args=(
                                       fileName, f"{public_path}{getFileNameByTagName('whiteListDnsmasqSecret')}.txt",
                                       'whitelist',
                                       isOpenFunction('switch9'), isOpenFunction('switch10'),
                                       isOpenFunction('switch30'), isOpenFunction('switch31'),
                                       isOpenFunction('switch32')))
        thread.start()
        thread2.start()
        return "result"
    # 域名黑名单
    if processDataMethodName == 'process_data_abstract7':
        # blackList.txt
        thread = threading.Thread(target=writeBlackList)
        thread.start()
        return "result"
    # ipv4
    if processDataMethodName == 'process_data_abstract5':
        # 通知dns服务器更新内存,不给dns分流器使用，数据太大了
        # redis_add(REDIS_KEY_UPDATE_IPV4_LIST_FLAG, 1)
        # ipv4-加密
        thread = threading.Thread(target=download_secert_file,
                                  args=(
                                      fileName, f"{public_path}{getFileNameByTagName('ipv4Secret')}.txt", 'ipv4',
                                      isOpenFunction('switch18'),
                                      isOpenFunction('switch19'), isOpenFunction('switch30'),
                                      isOpenFunction('switch31'), isOpenFunction('switch32')))
        thread.start()
        return "result"
    # ipv6加密
    if processDataMethodName == 'process_data_abstract6':
        # 加密
        thread = threading.Thread(target=download_secert_file,
                                  args=(
                                      fileName, f"{public_path}{getFileNameByTagName('ipv6Secret')}.txt", 'ipv6',
                                      isOpenFunction('switch20'),
                                      isOpenFunction('switch21'), isOpenFunction('switch30'),
                                      isOpenFunction('switch31'), isOpenFunction('switch32')))
        thread.start()
        return "result"
    return "result"


# 纠正url重复/问题
def getCorrectUrl(bakenStr):
    url_parts = bakenStr.split('/')
    cleaned_parts = [part for part in url_parts if part != '']
    cleaned_url = '/'.join(cleaned_parts)
    return cleaned_url


# 检查文件是否已经存在于gitee仓库，存在的话删除旧数据
def removeIfExist(username, repo_name, path, access_token, file_name):
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://gitee.com/api/v5/repos/{getCorrectUrl(bakenStr)}'
    headers = {'Authorization': f'token {access_token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        file_details = response.json()
        sha = file_details['sha']
        commit_message = 'Delete existing file'
        data = {
            "message": commit_message,
            "sha": sha,
        }
        response = requests.delete(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f'Successfully deleted file {file_name} in GITEE repository.')
        else:
            print(f'Error deleting file {file_name} from GITEE repository.')
        #
        # files = response.json()
        # for file in files:
        #     if file['name'] == file_name:
        #         # Delete the existing file
        #         url = file['url']
        #         sha = file['sha']
        #         message = 'Delete existing file'
        #         data = {'message': message, 'sha': sha}
        #         response = requests.delete(url, headers=headers, json=data)
        #         if response.status_code != 204:
        #             print(f'Failed to delete file. Status code: {response.status_code}')
        #         else:
        #             print('Existing file deleted successfully.')


# 上传新文件到gitee
def uploadNewFileToGitee(username, repo_name, path, access_token, file_name):
    # # 读取要上传的文件内容（bytes比特流）
    with open(f'{public_path}{file_name}', 'rb') as f:
        file_content = f.read()
    # 构建API请求URL和headers
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://gitee.com/api/v5/repos/{getCorrectUrl(bakenStr)}'
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': f'token {access_token}',
    }
    # 构建POST请求数据
    data = {
        'message': 'Upload a file',
        'content': base64.b64encode(file_content).decode('utf-8'),
    }
    # 发送POST请求
    response = requests.post(url, headers=headers, json=data)
    # 处理响应结果
    if response.status_code == 201:
        print('File uploaded to gitee successfully!')
    else:
        print(f'Failed to upload file to gitee. Status code: {response.status_code}')


def updateFileToGitee(file_name):
    # REDIS_KEY_GITEE
    # redisKeyGitee = {'username': '', 'reponame': '', 'path': '', 'accesstoken': ''}
    global redisKeyGitee
    username = init_gitee('username', REDIS_KEY_GITEE, redisKeyGitee)
    repo_name = init_gitee('reponame', REDIS_KEY_GITEE, redisKeyGitee)
    path = init_gitee('path', REDIS_KEY_GITEE, redisKeyGitee)
    access_token = init_gitee('accesstoken', REDIS_KEY_GITEE, redisKeyGitee)
    now = time.time()
    while time.time() - now < 15:
        try:
            removeIfExist(username, repo_name, path, access_token, file_name)
        except:
            pass
        try:
            uploadNewFileToGitee(username, repo_name, path, access_token, file_name)
            break
        except:
            continue


def removeIfExistGithub(username, repo_name, path, access_token, file_name):
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://api.github.com/repos/{getCorrectUrl(bakenStr)}'
    headers = {'Authorization': f'token {access_token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        file_details = response.json()
        sha = file_details['sha']
        commit_message = 'Delete existing file'
        data = {
            "message": commit_message,
            "sha": sha,
        }
        response = requests.delete(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f'Successfully deleted file {file_name} in Github repository.')
        else:
            print(f'Error deleting file {file_name} from Github repository.')


def uploadNewFileToGithub(username, repo_name, path, access_token, file_name):
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://api.github.com/repos/{getCorrectUrl(bakenStr)}'
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': f'token {access_token}',
    }
    with open(public_path + file_name, 'rb') as f:
        file_content = f.read()
    b64_file_content = base64.b64encode(file_content).decode('utf-8')
    commit_message = 'Upload a file'
    data = {
        'message': commit_message,
        'content': b64_file_content,
    }
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 201:
        print(f'Successfully uploaded file {file_name} to Github repository.')
    else:
        print(f'Error uploading file {file_name} to Github repository.')


def updateFileToGithub(file_name):
    global redisKeyGithub
    username = init_gitee('username', REDIS_KEY_GITHUB, redisKeyGithub)
    repo_name = init_gitee('reponame', REDIS_KEY_GITHUB, redisKeyGithub)
    path = init_gitee('path', REDIS_KEY_GITHUB, redisKeyGithub)
    access_token = init_gitee('accesstoken', REDIS_KEY_GITHUB, redisKeyGithub)
    now = time.time()
    while time.time() - now < 15:
        try:
            removeIfExistGithub(username, repo_name, path, access_token, file_name)
        except:
            pass
        try:
            uploadNewFileToGithub(username, repo_name, path, access_token, file_name)
            break
        except:
            continue


########################webdav##################################

def getAgreement(agreement):
    if "https" in agreement:
        return 'https'
    return 'http'


def purgeAgreement(serverUrl):
    if 'http' in serverUrl:
        return serverUrl.split('//')[1]
    else:
        return serverUrl


# Function to remove a file if it exists in the WebDAV repository
def removeIfExistWebDav(server_url, username, password, base_path, file_name, port, agreement):
    url = f"{purgeAgreement(server_url)}:{port}/{base_path}/{file_name}"
    url = f'{getAgreement(agreement)}://{getCorrectUrl(url)}'
    response = requests.head(url, auth=(username, password))
    if response.status_code == 200:
        response = requests.delete(url, auth=(username, password))
        if response.status_code == 204:
            print(f"Successfully deleted file {file_name} in WebDAV repository.")
    else:
        print(f"File {file_name} does not exist in WebDAV repository, skipping deletion.")


# Function to upload a new file to the WebDAV repository
def uploadNewFileToWebDAV(server_url, username, password, base_path, file_name, port, agreement):
    url = f"{purgeAgreement(server_url)}:{port}/{base_path}/{file_name}"
    url = f'{getAgreement(agreement)}://{getCorrectUrl(url)}'
    with open(public_path + file_name, "rb") as f:
        file_content = f.read()
    response = requests.put(url, auth=(username, password), data=file_content)
    if response.status_code == 201:
        print(f"Successfully uploaded file {file_name} to WebDAV repository.")


def updateFileToWebDAV(file_name):
    global redisKeyWebDav
    username = init_gitee('username', REDIS_KEY_WEBDAV, redisKeyWebDav)
    ip = init_gitee('ip', REDIS_KEY_WEBDAV, redisKeyWebDav)
    port = init_gitee('port', REDIS_KEY_WEBDAV, redisKeyWebDav)
    password = init_gitee('password', REDIS_KEY_WEBDAV, redisKeyWebDav)
    path = init_gitee('path', REDIS_KEY_WEBDAV, redisKeyWebDav)
    agreement = init_gitee('agreement', REDIS_KEY_WEBDAV, redisKeyWebDav)
    now = time.time()
    while time.time() - now < 15:
        try:
            removeIfExistWebDav(ip, username, password, path, file_name, port, agreement)
        except Exception as e:
            pass
        try:
            uploadNewFileToWebDAV(ip, username, password, path, file_name, port, agreement)
            break
        except Exception as e:
            continue


def isOpenFunction(functionId):
    global function_dict
    vaule = function_dict.get(functionId)
    if vaule == '1':
        return True
    else:
        return False


# 把自己本地文件加密生成对应的加密文本
def download_secert_file(fileName, secretFileName, cachekey, openJiaMi, openUpload, uploadGitee,
                         uploadGithub, uploadWebdav):
    try:
        if openJiaMi:
            # 读取文件内容
            with open(fileName, 'rb') as f:
                ciphertext = f.read()
            secretContent = encrypt(ciphertext, cachekey)
            thread_write_bytes_to_file(secretFileName, secretContent)
        # 开启上传
        if openUpload:
            update_git(os.path.basename(secretFileName), uploadGitee, uploadGithub, uploadWebdav)
    except FileNotFoundError:
        print(f"File not found: {fileName}")
    except:
        pass


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


def init_function_dict():
    global function_dict
    dict = redis_get_map(REDIS_KEY_FUNCTION_DICT)
    if dict and len(dict.keys()) > 0:
        keys = dict.keys()
        # 生成有效M3U
        if 'switch' not in keys:
            dict['switch'] = '1'
        # M3U加密
        if 'switch2' not in keys:
            dict['switch2'] = '0'
        # 完整M3U加密上传
        if 'switch3' not in keys:
            dict['switch3'] = '0'
        # 生成全部M3U
        if 'switch4' not in keys:
            dict['switch4'] = '1'
        # 生成白名单M3U
        if 'switch5' not in keys:
            dict['switch5'] = '1'
        # M3U域名-无加密-tvlist
        if 'switch6' not in keys:
            dict['switch6'] = '1'
        # m3u域名加密文件上传
        if 'switch7' not in keys:
            dict['switch7'] = '0'
        # m3u域名加密文件生成
        if 'switch8' not in keys:
            dict['switch8'] = '0'
        # 域名白名单生成dnsmasq加密文件
        if 'switch9' not in keys:
            dict['switch9'] = '0'
        # dnsmasq加密文件上传
        if 'switch10' not in keys:
            dict['switch10'] = '0'
        # 域名白名单-加密上传
        if 'switch11' not in keys:
            dict['switch11'] = '0'
        # 域名白名单-加密
        if 'switch12' not in keys:
            dict['switch12'] = '0'
        # 域名黑名单-定时器
        if 'switch13' not in keys:
            dict['switch13'] = '1'
        # 域名黑名单-openclash-加密
        if 'switch14' not in keys:
            dict['switch14'] = '0'
        # 域名黑名单-openclash-加密-上传
        if 'switch15' not in keys:
            dict['switch15'] = '0'
        # 域名黑名单-加密
        if 'switch16' not in keys:
            dict['switch16'] = '0'
        # 域名黑名单-加密-上传
        if 'switch17' not in keys:
            dict['switch17'] = '0'
        # ipv4-加密
        if 'switch18' not in keys:
            dict['switch18'] = '0'
        # ipv4-加密-上传
        if 'switch19' not in keys:
            dict['switch19'] = '0'
        # ipv6-加密
        if 'switch20' not in keys:
            dict['switch20'] = '0'
        # ipv6-加密-上传
        if 'switch21' not in keys:
            dict['switch21'] = '0'
        # 节点订阅-加密
        if 'switch22' not in keys:
            dict['switch22'] = '1'
        # 节点订阅+-加密-上传
        if 'switch23' not in keys:
            dict['switch23'] = '1'
        # 自动生成简易DNS黑白名单
        if 'switch24' not in keys:
            dict['switch24'] = '1'
        # m3u-定时器
        if 'switch25' not in keys:
            dict['switch25'] = '0'
        # 域名白名单-定时器
        if 'switch26' not in keys:
            dict['switch26'] = '0'
        # ipv4-定时器
        if 'switch27' not in keys:
            dict['switch27'] = '0'
        # ipv6-定时器
        if 'switch28' not in keys:
            dict['switch28'] = '0'
        # 上传至Gitee
        if 'switch30' not in keys:
            dict['switch30'] = '0'
        # 上传至Github
        if 'switch31' not in keys:
            dict['switch31'] = '0'
        # 上传至Webdav
        if 'switch32' not in keys:
            dict['switch32'] = '0'
        # 下载加密上传-定时器
        if 'switch33' not in keys:
            dict['switch33'] = '0'
        # 下载解密-定时器
        if 'switch34' not in keys:
            dict['switch34'] = '0'
        redis_add_map(REDIS_KEY_FUNCTION_DICT, dict)
        function_dict = dict.copy()
    else:
        dict = {'switch': '1', 'switch2': '0', 'switch3': '0', 'switch4': '1', 'switch5': '1', 'switch6': '1',
                'switch7': '0',
                'switch8': '0', 'switch9': '0', 'switch10': '0', 'switch11': '0', 'switch12': '0', 'switch13': '1',
                'switch14': '0',
                'switch15': '0', 'switch16': '0', 'switch17': '0', 'switch18': '0', 'switch19': '0', 'switch20': '0',
                'switch21': '0',
                'switch22': '1', 'switch23': '1', 'switch24': '1', 'switch25': '0', 'switch26': '0', 'switch27': '0'
            , 'switch28': '0', 'switch30': '0', 'switch31': '0', 'switch32': '0', 'switch33': '0',
                'switch34': '0'}
        redis_add_map(REDIS_KEY_FUNCTION_DICT, dict)
        function_dict = dict.copy()


# 初始化节点后端服务器
def initProxyServer():
    # 开服时判断是不是初次挂载容器，是的话添加默认配置文件
    models = redis_get_map(REDIS_KEY_PROXIES_SERVER)
    if models and len(models.items()) > 0:
        return
    else:
        try:
            update_dict = {
                "http://127.0.0.1:25500/sub": "host模式:本地服务器",
                "http://192.168.5.1:25500/sub": "bridge模式:本地服务器"}
            redis_add_map(REDIS_KEY_PROXIES_SERVER, update_dict)
            # 设定默认选择的模板
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = "bridge模式:本地服务器"
            redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, tmp_dict)
        except:
            pass


# 初始化节点模板
def initProxyModel():
    # 开服时判断是不是初次挂载容器，是的话添加默认配置文件
    models = redis_get_map(REDIS_KEY_PROXIES_MODEL)
    if models and len(models.items()) > 0:
        return
    else:
        try:
            update_dict = {
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini": "ACL4SSR_Online 默认版 分组比较全(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini": "ACL4SSR_Online_AdblockPlus 更多去广告(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_MultiCountry.ini": "ACL4SSR_Online_MultiCountry 多国分组(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoAuto.ini": "ACL4SSR_Online_NoAuto 无自动测速(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoReject.ini": "ACL4SSR_Online_NoReject 无广告拦截规则(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini": "ACL4SSR_Online_Mini 精简版(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_AdblockPlus.ini": "ACL4SSR_Online_Mini_AdblockPlus.ini 精简版 更多去广告(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_NoAuto.ini": "ACL4SSR_Online_Mini_NoAuto.ini 精简版 不带自动测速(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_Fallback.ini": "ACL4SSR_Online_Mini_Fallback.ini 精简版 带故障转移(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini": "ACL4SSR_Online_Mini_MultiMode.ini 精简版 自动测速、故障转移、负载均衡(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiCountry.ini": "ACL4SSR_Online_Mini_MultiCountry.ini 精简版 带港美日国家(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini": "ACL4SSR_Online_Full 全分组 重度用户使用(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_MultiMode.ini": "ACL4SSR_Online_Full_MultiMode.ini 全分组 多模式 重度用户使用(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_NoAuto.ini": "ACL4SSR_Online_Full_NoAuto.ini 全分组 无自动测速 重度用户使用(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_AdblockPlus.ini": "ACL4SSR_Online_Full_AdblockPlus 全分组 重度用户使用 更多去广告(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Netflix.ini": "ACL4SSR_Online_Full_Netflix 全分组 重度用户使用 奈飞全量(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Google.ini": "ACL4SSR_Online_Full_Google 全分组 重度用户使用 谷歌细分(与Github同步)"}
            # update_dict = {unquote("/ACL4SSR_Online_Full_Mannix.ini"): "本地配置"}
            redis_add_map(REDIS_KEY_PROXIES_MODEL, update_dict)
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = "ACL4SSR_Online 默认版 分组比较全(本地离线模板)"
            # 设定默认选择的模板
            redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, tmp_dict)
        except:
            pass


# 多线程写入
def distribute_data(data, file, num_threads):
    if len(data.items()) == 0:
        return
    if os.path.exists(file):
        os.remove(file)
    # 将字典转换为元组列表，并按照键的顺序排序
    items = sorted(data.items())
    # 计算每个线程处理的数据大小
    chunk_size = (len(items) + num_threads - 1) // num_threads

    # 将数据切分为若干个块，每个块包含 chunk_size 个键值对
    chunks = [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]

    # 创建一个任务队列，并向队列中添加任务
    task_queue = queue.Queue()
    for chunk in chunks:
        task_queue.put(chunk)

    # 创建线程池
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(task_queue, file))
        t.start()
        threads.append(t)

    # 等待任务队列中的所有任务完成
    task_queue.join()

    # 向任务队列中添加 num_threads 个 None 值，以通知线程退出
    for i in range(num_threads):
        task_queue.put(None)

    # 等待所有线程退出
    for t in threads:
        t.join()



# 抽象类，定义抽象方法process_data_abstract
class MyAbstractClass(abc.ABC):
    @abc.abstractmethod
    def process_data_abstract(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract2(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract3(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract4(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract5(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract6(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract7(self, data, index, step, my_dict):
        pass


# 处理数据的实现类
class MyConcreteClass(MyAbstractClass):
    # 实现抽象方法
    # 处理M3U数据的实现类
    def process_data_abstract(self, data, index, step, my_dict):
        process_data(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理域名名单转换Adguardhome的实现类
    def process_data_abstract2(self, data, index, step, my_dict):
        process_data_domain(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理域名名单转换dnsmasq的实现类
    def process_data_abstract3(self, data, index, step, my_dict):
        process_data_domain_dnsmasq(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理域名合并的实现类
    def process_data_abstract4(self, data, index, step, my_dict):
        process_data_domain_collect(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理合并ipv4的实现类
    def process_data_abstract5(self, data, index, step, my_dict):
        process_data_ipv4_collect(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理合并ipv6的实现类
    def process_data_abstract6(self, data, index, step, my_dict):
        process_data_ipv6_collect(data, index, step, my_dict)
        # 实现代码
        pass

    # 黑名单转换成openclash-fallbackfilter-domain
    def process_data_abstract7(self, data, index, step, my_dict):
        process_data_domain_openclash_fallbackfilter(data, index, step, my_dict)
        # 实现代码
        pass


def formattxt_multithread(data, method_name):
    num_threads = 10
    my_dict = {}
    # 计算每个线程处理的数据段大小
    step = math.ceil(len(data) / num_threads)
    # 创建线程池对象
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # 提交任务到线程池中
        for i in range(num_threads):
            start_index = i * step
            executor.submit(getattr(MyConcreteClass(), method_name), data, start_index, step, my_dict)
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)
    return my_dict


PROXY_RULE_LEFT = 'DOMAIN-SUFFIX,'
PROXY_RULE_RIGHT = ',PROXY'


def updateBlackList(url):
    black_list_nameserver_policy[url] = ""
    black_list_Proxy_Rules[PROXY_RULE_LEFT + url] = ''


def updateBlackListSpData(domain):
    # 一级域名，类似:一级域名名字.顶级域名名字
    domain_name_str = stupidThink(domain)
    if domain_name_str != '':
        global blacklistSpData
        blacklistSpData[domain_name_str] = ''


# 字符串内容处理-域名转openclash-fallbackfilter-domain
# openclash-fallback-filter-domain 填写需要代理的域名
# 可以使用通配符*,但是尽可能少用，可能出问题
def process_data_domain_openclash_fallbackfilter(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # dns分流需要的外国域名一级数据
        updateBlackListSpData(line)
        # 判断是不是+.域名
        lineEncoder = line.encode()
        if re.match(wildcard_regex2, line):
            # 外国域名+第三方规则-外国域名关键字
            updateBlackList((lineEncoder.substring(2)).decode())
            # my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            # my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "*." + (
            #     lineEncoder.substring(2)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + (
                lineEncoder.substring(2)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        # 判断是不是域名
        elif re.match(domain_regex, line):
            # 全部使用通配符+.可以匹配所有子域名包括自身，适合openclash-fallback-filter配置外国域名组
            my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            if not lineEncoder.startswith(b"www"):
                # 自用dns分流器外国域名，只取最高父域名
                updateBlackList(line)
                # my_dict[
                #     OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
                # my_dict[
                #     OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "*." + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            else:
                updateBlackList((lineEncoder.substring(4)).decode())
                my_dict[
                    OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + (
                        lineEncoder.substring(4)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
                # my_dict[
                #     OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "*." + (
                #         lineEncoder.substring(4)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        # 判断是不是*.域名
        elif re.match(wildcard_regex, line):
            updateBlackList((lineEncoder.substring(2)).decode())
            # my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            my_dict[
                OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + (
                    lineEncoder.substring(2)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        elif lineEncoder.startswith(b"."):
            updateBlackList((lineEncoder.substring(1)).decode())
            my_dict[
                OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + (
                    lineEncoder.substring(1)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            # my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "*" + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""


# 字符串内容处理-域名转adguardhome屏蔽
def process_data_domain(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是域名或者*.域名
        if re.match(domain_regex, line) or re.match(wildcard_regex, line):
            my_dict["||" + line + "^"] = ""
            if not line.encode().startswith((b"www", b".", b"*")):
                my_dict["||" + "*." + line + "^"] = ""
            if line.encode().startswith(b"."):
                my_dict["||" + "*" + line + "^"] = ""


def is_ipv4_network(ipv4_str):
    try:
        network = ipaddress.IPv4Network(ipv4_str)
        return True
    except ValueError:
        return False


def is_ipv6_network(ipv6_str):
    try:
        network = ipaddress.IPv6Network(ipv6_str)
        return True
    except ValueError:
        return False


# 字符串内容处理-ipv4合并
def process_data_ipv4_collect(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是ipv4
        if is_ipv4_network(line):
            my_dict[line] = ""
            # 转换成ipv4-整数数组字典
            # update_ipv4_int_range(line)


# 字符串内容处理-ipv6合并
def process_data_ipv6_collect(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是域名或者*.域名
        if is_ipv6_network(line):
            my_dict[line] = ""


# 字符串内容处理-域名合并
def process_data_domain_collect(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是域名或者*.域名
        if re.match(domain_regex, line) or re.match(wildcard_regex, line):
            my_dict[line] = ""


# 黑白名单最大取到二级域名，防止数据太多
def updateWhiteListSpData(domain):
    # 二级域名, 一级域名，类似:一级域名名字.顶级域名名字
    domain_name_str = stupidThink(domain)
    if domain_name_str != '':
        global whitelistSpData
        whitelistSpData[domain_name_str] = ''



# 字符串内容处理-域名转dnsmasq白名单
# openclash dnsmasq不支持+，支持*.和.
# 最简单的做法是*域名*
# 第三方规则不支持+,支持*.和.
# openclash域名白名单全部使用*.域名
def process_data_domain_dnsmasq(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # dns分流使用的域名白名单
        updateWhiteListSpData(line)
        # 普通域名
        if re.match(domain_regex, line):
            lineEncoder = line.encode()
            # www域名
            if lineEncoder.startswith(b"www."):
                # 大陆域名白名单+第三方规则直连生成
                updateOpenclashNameServerPolicy((lineEncoder.substring(4)).decode())
                # openclash-dnsmasq域名全部使用通配符*.，用于直接筛查大陆域名
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + '*.' + (
                    lineEncoder.substring(4)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + (
                    lineEncoder.substring(4)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""
            else:
                updateOpenclashNameServerPolicy(line)
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + '*.' + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""
        # *.域名
        elif re.match(wildcard_regex, line):
            lineEncoder = line.encode()
            updateOpenclashNameServerPolicy((lineEncoder.substring(2)).decode())
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + (
                lineEncoder.substring(2)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""

        # +.域名
        elif re.match(wildcard_regex2, line):
            lineEncoder = line.encode()
            updateOpenclashNameServerPolicy((lineEncoder.substring(2)).decode())
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + (
                lineEncoder.substring(2)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + '*' + (
                lineEncoder.substring(2)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""


DIRECT_RULE_LEFT = 'DOMAIN-SUFFIX,'
DIRECT_RULE_RIGHT = ',DIRECT'


def updateOpenclashNameServerPolicy(url):
    white_list_nameserver_policy[url] = ""
    white_list_Direct_Rules[DIRECT_RULE_LEFT + url] = ''


def updateAdguardhomeWithelistForM3u(url):
    # 没有开启tvlist生成
    if not isOpenFunction('switch6'):
        return
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(':')[0] if ':' in parsed_url.netloc else parsed_url.netloc  # 提取IP地址或域名
    if domain.replace('.', '').isnumeric():  # 判断是否为IP地址
        return
    else:
        # 是域名，但不知道是国内还是国外域名
        white_list_adguardhome["@@||" + domain + "^"] = ""
    # 是ip


def decode_bytes(text):
    # define a list of possible encodings
    encodings = ['utf-8', 'gbk', 'iso-8859-1', 'ascii', 'cp936', 'big5', 'shift_jis', 'koi8-r',
                 'utf-16', 'utf-32', 'euc-jp', 'gb18030', 'iso-2022-jp', 'windows-1250', 'windows-1251']

    # try each encoding until one works
    for encoding in encodings:
        try:
            return text.decode(encoding).strip()
        except (TypeError, UnicodeDecodeError):
            continue

    # if none of the above worked, use chardet to detect the encoding
    result = chardet.detect(text)
    decoded_text = text.decode(result['encoding']).strip()
    return decoded_text


def pureUrl(s):
    result = s.split('$', 1)[0]
    return result


# m3u转换txt
def m3uToTxt(lines):
    result = []
    # 组名,频道名字,url
    group = {}
    url_dict = {}
    for i in range(len(lines)):
        line = decode_bytes(lines[i]).strip()
        if line == '':
            continue
        # 假定直播名字和直播源不在同一行
        if line.startswith("#EXTINF"):
            continue
        if not line.startswith(("http", "rtsp", "rtmp", 'P2p', 'mitv')):
            continue
        # http开始
        else:
            searchurl = pureUrl(line)
            if searchurl in url_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0:
                continue
            preline = decode_bytes(lines[i - 1]).strip()
            # 没有名字
            if not preline:
                continue
            # 不是名字
            if not preline.startswith("#EXTINF"):
                continue
            try:
                last_comma_index = preline.rfind(",")
                if last_comma_index == -1:
                    raise ValueError("字符串中不存在逗号")
                tvg_name = preline[last_comma_index + 1:].strip()
            except Exception as e:
                try:
                    tvg_name = re.search(r'tvg-name="([^"]+)"', preline)
                    if tvg_name is None:
                        raise ValueError("未找到 tvg-name 属性")
                    tvg_name = tvg_name.group(1)
                except Exception as e:
                    continue
            group_title = re.search(r'group-title="([^"]+)"', preline)
            group_title = group_title.group(1) if group_title else ''
            if group_title == "":
                group_title = '未分组'
            url_dict[searchurl] = ''
            if group_title not in group.keys():
                group[group_title] = tvg_name + ',' + searchurl
            else:
                group[group_title] = group[group_title] + '\n' + tvg_name + ',' + searchurl
    for groupName, nameDict in group.items():
        result.append(f'{groupName},#genre#')
        result.append(f'{nameDict}')
    return '\n'.join(result)


# 数据源，字典（词库+新分组名字），新分组名字
def find_m3u_name_txt(lines, name_dict, def_group):
    for line in lines:
        line = decode_bytes(line).strip()
        if line == '':
            continue
        if not line.startswith(("http", "rtsp", "rtmp", 'P2p', 'mitv')):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp|P2p|mitv)", line):
                name, url = getChannelAndUrl(",", line)
                if name:
                    name_dict[name] = def_group
                else:
                    continue
            elif re.match(r"^[^#].*，(http|rtsp|rtmp|P2p|mitv)", line):
                name, url = getChannelAndUrl("，", line)
                if name:
                    name_dict[name] = def_group
                else:
                    continue
            else:
                continue
        else:
            continue


# 上传m3u文件bytes格式规整
def format_data(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        # print(type(data[i]))
        line = decode_bytes(data[i]).strip()
        if not line:
            continue
        # 假定直播名字和直播源不在同一行
        if line.startswith("#EXTINF"):
            continue
        if jumpBlackM3uList(line):
            continue
        # 不是http开头，可能是直播源
        if not line.startswith(("http", "rtsp", "rtmp")):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp)", line):
                name, url = getChannelAndUrl(",", line)
                searchurl = pureUrl(url)
                if searchurl in my_dict.keys():
                    continue
                if name:
                    name = name.lower()
                    fullName = update_epg_by_name(name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(name, searchurl, fullName)
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
            elif re.match(r"^[^#].*，(http|rtsp|rtmp)", line):
                name, url = getChannelAndUrl("，", line)
                searchurl = pureUrl(url)
                if searchurl in my_dict.keys():
                    continue
                if name:
                    name = name.lower()
                    fullName = update_epg_by_name(name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(name, searchurl, fullName)
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
        # http开始
        else:
            # 去重复
            searchurl = pureUrl(line)
            if searchurl in my_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0 and index == 0:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                continue
            preline = decode_bytes(data[i - 1]).strip()
            # preline = data[i - 1].decode("utf-8").strip()
            # 没有名字
            if not preline:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                continue
            # 不是名字
            if not preline.startswith("#EXTINF"):
                try:
                    last_comma_index = preline.rfind(",")
                    if last_comma_index == -1:
                        raise ValueError("字符串中不存在逗号")
                    tvg_name = preline[last_comma_index + 1:].strip().lower()
                    fullName = update_epg_by_name(tvg_name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(tvg_name, searchurl, fullName)
                except Exception as e:
                    tvg_name = defalutname
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{tvg_name}",{tvg_name}\n'
                continue
            # 有名字
            else:
                my_dict[searchurl] = update_epg_nope(preline)
                continue


# url,tvg-name
tmp_url_tvg_name_dict = {}
REDIS_KET_TMP_CHINA_CHANNEL = 'tmpChinaChannel'


def addChinaChannel(tvg_name, url, fullName):
    # 关闭有效直播源生成
    if not isOpenFunction('switch'):
        return
    # 关闭白名单直播源生成
    if not isOpenFunction('switch5'):
        return
    for name in m3u_whitlist.keys():
        if name in tvg_name:
            tmp_url_tvg_name_dict[url] = fullName
            return


def jumpBlackM3uList(tvg_name):
    for name in m3u_blacklist.keys():
        if name in tvg_name:
            return True
    return False


def getChannelAndUrl(split, str):
    arr = str.split(split)
    length = len(arr)
    if length == 2:
        return arr[0], arr[1]
    name = ''
    for i in range(0, length - 2):
        name += arr[i]
    return name, arr[length - 1]


# 超融合-直播源字符串内容处理-m3u
def process_data(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        # print(type(data[i]))
        line = data[i].strip()
        # 空行
        if not line:
            continue
        lineEncoder = line.encode()
        line = decode_bytes(lineEncoder).strip()
        # 假定直播名字和直播源不在同一行，跳过频道名字
        if lineEncoder.startswith(b"#EXTINF"):
            continue
        if jumpBlackM3uList(line):
            continue
        # 不是http开头，也可能是直播源
        if not lineEncoder.startswith((b"http", b"rtsp", b"rtmp")):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp)", line):
                name, url = getChannelAndUrl(",", line)
                searchurl = pureUrl(url)
                if searchurl in my_dict.keys():
                    continue
                if name:
                    name = name.lower()
                    fullName = update_epg_by_name(name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(name, searchurl, fullName)
                    updateAdguardhomeWithelistForM3u(searchurl)
                else:
                    fullName = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                    my_dict[searchurl] = fullName
                    updateAdguardhomeWithelistForM3u(searchurl)
            # 匹配格式：频道，url
            elif re.match(r"^[^#].*，(http|rtsp|rtmp)", line):
                name, url = getChannelAndUrl("，", line)
                searchurl = pureUrl(url)
                if searchurl in my_dict.keys():
                    continue
                if name:
                    name = name.lower()
                    fullName = update_epg_by_name(name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(name, searchurl, fullName)
                    updateAdguardhomeWithelistForM3u(searchurl)
                else:
                    fullName = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                    my_dict[searchurl] = fullName
                    updateAdguardhomeWithelistForM3u(searchurl)
        # http|rtsp|rtmp开始，跳过P2p
        elif not lineEncoder.startswith(b"P2p"):
            searchurl = pureUrl(line)
            if searchurl in my_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0 and index == 0:
                fullName = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                my_dict[searchurl] = fullName
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            preline = data[i - 1].strip()
            prelineEncoder = preline.encode()
            preline = decode_bytes(prelineEncoder).strip()
            # 没有名字
            if not preline:
                fullName = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                my_dict[searchurl] = fullName
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            # 不是名字
            if not prelineEncoder.startswith(b"#EXTINF"):
                try:
                    last_comma_index = preline.rfind(",")
                    if last_comma_index == -1:
                        raise ValueError("字符串中不存在逗号")
                    tvg_name = preline[last_comma_index + 1:].strip().lower()
                    fullName = update_epg_by_name(tvg_name)
                    addChinaChannel(tvg_name, searchurl, fullName)
                except Exception as e:
                    tvg_name = defalutname
                    fullName = f'#EXTINF:-1  tvg-name="{tvg_name}",{tvg_name}\n'
                my_dict[searchurl] = fullName
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            # 有裸名字或者#EXTINF开始但是没有tvg-name\tvg-id\group-title
            else:
                # if not any(substring in line for substring in ["tvg-name", "tvg-id", "group-title"]):
                # my_dict[searchurl] = f'{preline}\n'
                my_dict[searchurl] = update_epg(preline, searchurl)
                updateAdguardhomeWithelistForM3u(searchurl)
                continue


# 已经排序的直播源分组名单,关键字，分组
ranked_m3u_whitelist_set = []


def getRankWhiteList():
    global m3u_whitlist_rank
    global m3u_whitlist
    global ranked_m3u_whitelist_set
    ranked_m3u_whitelist_set.clear()
    ranked_m3u_whitelist = {}
    restSetDict = {}
    for key, value in m3u_whitlist.items():
        if value not in m3u_whitlist_rank.keys():
            restSetDict[key] = value
        if value == '':
            restSetDict[key] = value
    for group, rank in m3u_whitlist_rank.items():
        if group not in m3u_whitlist.values():
            continue
        if group == '':
            continue
        rank = int(rank)
        dict = {}
        for key, value in m3u_whitlist.items():
            if value == group:
                dict[key] = value
        ranked_m3u_whitelist[rank] = dict
    seta = sorted(ranked_m3u_whitelist.keys())  # 对字典的键进行排序
    for key in seta:
        ranked_m3u_whitelist_set.append(ranked_m3u_whitelist[key])  # 将排序后的值依次添加到有序集合中
    ranked_m3u_whitelist_set.append(restSetDict)


# 获取白名单分组
def getMyGroup(str):
    try:
        for dict in ranked_m3u_whitelist_set:
            for key, group in dict.items():
                if key in str:
                    return group
    except Exception as e:
        pass
    return ''


def update_epg_by_name(tvg_name):
    newStr = "#EXTINF:-1 "
    group_title = getMyGroup(tvg_name)
    if group_title == '':
        group_title = CHANNEL_GROUP.get(tvg_name)
    if group_title is not None and group_title != "":
        newStr += f'group-title="{group_title}"  '
        if tvg_name not in CHANNEL_GROUP:
            CHANNEL_GROUP[tvg_name] = group_title
    tvg_logo = CHANNEL_LOGO.get(tvg_name)
    if tvg_logo is not None and tvg_logo != "":
        newStr += f'tvg-logo="{tvg_logo}" '
    newStr += f'tvg-name="{tvg_name}",{tvg_name}\n'
    return newStr


def update_epg_nope(s):
    try:
        last_comma_index = s.rfind(",")
        if last_comma_index == -1:
            raise ValueError("字符串中不存在逗号")
        tvg_name = s[last_comma_index + 1:].strip().lower()
    except Exception as e:
        try:
            tvg_name = re.search(r'tvg-name="([^"]+)"', s)
            if tvg_name is None:
                raise ValueError("未找到 tvg-name 属性")
            tvg_name = tvg_name.group(1).lower()
        except Exception as e:
            # 处理异常
            tvg_name = ""
    if tvg_name != "":
        newStr = "#EXTINF:-1 "
        tvg_id = re.search(r'tvg-id="([^"]+)"', s)
        tvg_id = tvg_id.group(1) if tvg_id else ''
        if tvg_id != "":
            newStr += f'tvg-id="{tvg_id}" '
        tvg_logo = re.search(r'tvg-logo="([^"]+)"', s)
        tvg_logo = tvg_logo.group(1) if tvg_logo else ''
        if tvg_logo == "":
            tvg_logo = CHANNEL_LOGO.get(tvg_name)
        if tvg_logo is not None and tvg_logo != "":
            newStr += f'tvg-logo="{tvg_logo}" '
            if tvg_name not in CHANNEL_LOGO:
                CHANNEL_LOGO[tvg_name] = tvg_logo
        group_title = getMyGroup(s)
        if group_title == '':
            group_title = re.search(r'group-title="([^"]+)"', s)
            group_title = group_title.group(1) if group_title else ''
        if group_title == "":
            group_title = CHANNEL_GROUP.get(tvg_name)
        if group_title is not None and group_title != "":
            newStr += f'group-title="{group_title}"  '
            if tvg_name not in CHANNEL_GROUP:
                CHANNEL_GROUP[tvg_name] = group_title
        newStr += f'tvg-name="{tvg_name}",{tvg_name}\n'
        return newStr
    else:
        return f'{s}\n'


def update_epg(s, searchurl):
    try:
        last_comma_index = s.rfind(",")
        if last_comma_index == -1:
            raise ValueError("字符串中不存在逗号")
        tvg_name = s[last_comma_index + 1:].strip().lower()
    except Exception as e:
        try:
            tvg_name = re.search(r'tvg-name="([^"]+)"', s)
            if tvg_name is None:
                raise ValueError("未找到 tvg-name 属性")
            tvg_name = tvg_name.group(1).lower()
        except Exception as e:
            # 处理异常
            tvg_name = ""
    if tvg_name != "":
        newStr = "#EXTINF:-1 "
        tvg_id = re.search(r'tvg-id="([^"]+)"', s)
        tvg_id = tvg_id.group(1) if tvg_id else ''
        if tvg_id != "":
            newStr += f'tvg-id="{tvg_id}" '
        tvg_logo = re.search(r'tvg-logo="([^"]+)"', s)
        tvg_logo = tvg_logo.group(1) if tvg_logo else ''
        if tvg_logo == "":
            tvg_logo = CHANNEL_LOGO.get(tvg_name)
        if tvg_logo is not None and tvg_logo != "":
            newStr += f'tvg-logo="{tvg_logo}" '
            if tvg_name not in CHANNEL_LOGO:
                CHANNEL_LOGO[tvg_name] = tvg_logo
        group_title = getMyGroup(s)
        if group_title == '':
            group_title = re.search(r'group-title="([^"]+)"', s)
            group_title = group_title.group(1) if group_title else ''
        if group_title == "":
            group_title = CHANNEL_GROUP.get(tvg_name)
        if group_title is not None and group_title != "":
            newStr += f'group-title="{group_title}"  '
            if tvg_name not in CHANNEL_GROUP:
                CHANNEL_GROUP[tvg_name] = group_title
        newStr += f'tvg-name="{tvg_name}",{tvg_name}\n'
        addChinaChannel(tvg_name, searchurl, newStr)
        return newStr
    else:
        addChinaChannel(defalutname, searchurl, f'{s}\n')
        return f'{s}\n'


def generate_json_string(mapname):
    if mapname not in specialRedisKey:
        m3ulink = redis_get_map(mapname)
    else:
        # 从Redis中读取JSON字符串
        m3ulink = redis_get(mapname)
        m3ulink = json.loads(m3ulink)
    # 将字典转换为JSON字符串并返回
    json_str = json.dumps(m3ulink)
    return json_str


# 一键导出全部json配置
def generate_multi_json_string(mapnameArr):
    finalDict = {}
    # 普通python字典结构统一转换成对应的redis结构
    for name in mapnameArr:
        m3ulink = redis_get_map(name)
        if m3ulink and len(m3ulink.keys()) > 0:
            finalDict[name] = m3ulink
    outDict1 = {}
    outDict1[NORMAL_REDIS_KEY] = finalDict

    # 特殊python字典结构存入redis统一转换成string
    finalDict2 = {}
    for name in specialRedisKey:
        try:
            # 从Redis中读取JSON字符串
            json_string_redis = redis_get(name)
            # 反序列化成Python对象
            my_dict_redis = json.loads(json_string_redis)
            if len(my_dict_redis.keys()) > 0:
                finalDict2[name] = my_dict_redis
        except Exception as e:
            pass
    outDict2 = {}
    outDict2[SPECIAL_REDIS_KEY] = finalDict2
    # 合并字典
    merged_dict = {**outDict1, **outDict2}
    # 将合并后的字典导出成json字符串
    json_string = json.dumps(merged_dict)
    return json_string


CACHE_KEY_TO_GLOBAL_VAR = {
    REDIS_KEY_GITEE: 'redisKeyGitee',
    REDIS_KEY_FILE_NAME: 'file_name_dict',
    REDIS_KEY_GITHUB: 'redisKeyGithub',
    REDIS_KEY_WEBDAV: 'redisKeyWebDav',
    REDIS_KEY_SECRET_PASS_NOW: 'redisKeySecretPassNow',
    REDIS_KEY_FUNCTION_DICT: 'function_dict',
    REDIS_KEY_YOUTUBE: 'redisKeyYoutube',
    REDIS_KEY_BILIBILI: 'redisKeyBilili',
    REDIS_KEY_HUYA: 'redisKeyHuya',
    REDIS_KEY_YY: 'redisKeyYY',
    REDIS_KEY_TWITCH: 'redisKeyTWITCH',
    REDIS_KEY_DOUYIN: 'redisKeyDOUYIN',
    REDIS_KEY_ALIST: 'redisKeyAlist',
    REDIS_KEY_NORMAL: 'redisKeyNormal'
}


def importToReloadCache(cachekey, dict):
    if cachekey in CACHE_KEY_TO_GLOBAL_VAR:
        global_var = globals()[CACHE_KEY_TO_GLOBAL_VAR[cachekey]]
        # global_var.clear()
        global_var.update(dict)

    # Define mapping between cache keys and global variables


CACHE_KEY_TO_GLOBAL_VAR_SPECIAL = {
    REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME: 'downAndSecUploadUrlPassAndName',
    REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME: 'downAndDeSecUrlPassAndName'
}


def importToReloadCacheForSpecial(finalKey22, finalDict22):
    # Check cache key and update global variable accordingly
    if finalKey22 in CACHE_KEY_TO_GLOBAL_VAR_SPECIAL:
        global_var = globals()[CACHE_KEY_TO_GLOBAL_VAR_SPECIAL[finalKey22]]
        global_var.update(finalDict22)
        # Serialize global variable to JSON string and store in Redis
        json_string = json.dumps(global_var)
        redis_add(finalKey22, json_string)


# 上传订阅配置
def upload_oneKey_json(request):
    try:
        json_dict = json.loads(request.get_data())
        # 批量写入数据
        for key, value in json_dict.items():
            if key in NORMAL_REDIS_KEY:
                for finalKey11, finalDict11 in value.items():
                    if len(finalDict11) > 0:
                        redis_add_map(finalKey11, finalDict11)
                        importToReloadCache(finalKey11, finalDict11)
            elif key in SPECIAL_REDIS_KEY:
                for finalKey22, finalDict22 in value.items():
                    if len(finalDict22) > 0:
                        importToReloadCacheForSpecial(finalKey22, finalDict22)
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred in upload_oneKey_json: ", e)
        return jsonify({'success': False})


def dellist(request, rediskey):
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    redis_del_map_key(rediskey, deleteurl)
    return jsonify({'deleteresult': "delete success"})


def download_json_file_base(redislinkKey):
    # 生成JSON文件数据
    json_data = generate_json_string(redislinkKey)
    filename = f'{secret_path}{redislinkKey}.json'
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w') as f:
        f.write(json_data)
    # 发送JSON文件到前端
    return send_file(filename, as_attachment=True)


def formatdata_multithread(data, num_threads):
    my_dict = {}
    # 计算每个线程处理的数据段大小
    step = math.ceil(len(data) / num_threads)
    # 创建线程池对象
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # 提交任务到线程池中
        for i in range(num_threads):
            start_index = i * step
            executor.submit(format_data, data, start_index, step, my_dict)
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)
    return my_dict


def getProxyButton():
    dict = redis_get_map(REDIS_KEY_PROXIES_TYPE)
    if not dict:
        button = "button-1"
        dict = {}
        dict[REDIS_KEY_PROXIES_TYPE] = button
        redis_add_map(REDIS_KEY_PROXIES_TYPE, dict)
        return button
    return dict[REDIS_KEY_PROXIES_TYPE]


# 获取自己选择的代理服务器文件,要么本地url，要么远程配置url
def getProxyServerChosen():
    # 根据选择的代理配置名字获取代理配置的url
    dict = redis_get_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    if dict and len(dict.keys()) > 0:
        model = dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]
        models = redis_get_map(REDIS_KEY_PROXIES_SERVER)
        for url, name in models.items():
            if model == name:
                return url
        return URL
    else:
        return URL


# 获取自己选择的代理配置文件,要么本地url，要么远程配置url
def getProxyModelChosen():
    # 根据选择的代理配置名字获取代理配置的url
    dict = redis_get_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    if dict and len(dict.keys()) > 0:
        model = dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]
        models = redis_get_map(REDIS_KEY_PROXIES_MODEL)
        for url, name in models.items():
            if model == name:
                return url
        return ""
    else:
        return ""


# 代理转换配置字典生成
def generateProxyConfig(urlStr):
    params = {
        "url": urlStr,
        "insert": False,
        "config": getProxyModelChosen()
    }
    button = getProxyButton()
    # Clash新参数
    if button == "button-1":
        params["target"] = "clash"
        params["new_name"] = True
    # ClashR新参数
    elif button == "button-2":
        params["target"] = "clashr"
        params["new_name"] = True
    # Clash
    elif button == "button-3":
        params["target"] = "clash"
    # Surge3
    elif button == "button-4":
        params["target"] = "surge"
        params["ver"] = 3
    # Surge4
    elif button == "button-5":
        params["target"] = "surge"
        params["ver"] = 4
    # Quantumult
    elif button == "button-6":
        params["target"] = "quan"
    # Surfboard
    elif button == "button-7":
        params["target"] = "surfboard"
    # Loon
    elif button == "button-8":
        params["target"] = "loon"
    # SSAndroid
    elif button == "button-9":
        params["target"] = "sssub"
    # V2Ray
    elif button == "button-10":
        params["target"] = "v2ray"
    # ss
    elif button == "button-11":
        params["target"] = "ss"
    # ssr
    elif button == "button-12":
        params["target"] = "ssr"
    # ssd
    elif button == "button-13":
        params["target"] = "ssd"
    # ClashR
    elif button == "button-14":
        params["target"] = "clashr"
    # Surge2
    elif button == "button-15":
        params["target"] = "surge"
        params["ver"] = 2
    # QuantumultX
    elif button == "button-16":
        params["target"] = "quanx"
    return params


nameArr = ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'z', 'x', 'c',
           'v', 'b', 'n', 'm']


def download_files_for_encryp_proxy(urls, redis_dict):
    if len(urls) == 0:
        return {}
    ip = init_IP()
    # 新生成的本地url
    proxy_dict = {}
    current_timestamp = int(time.time())
    i = 0
    round = 1
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {executor.submit(fetch_url, url, redis_dict): url for url in urls}
        # 获取各个future对象的返回值并存储在字典中
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                index = 0
                middleStr = ""
                if i > 0 and i % 25 == 0:
                    round = round + 1
                while index < round:
                    middleStr += nameArr[i]
                    index = index + 1
                tmp_file = f"{current_timestamp}{middleStr}.yaml"
                with open(f"{secret_path}{tmp_file}", 'w'):
                    pass
                write_content_to_file(result.encode("utf-8"), f"{secret_path}{tmp_file}", 10)
                proxy_dict[f"http://{ip}:22771/secret/" + tmp_file] = f"{secret_path}{tmp_file}"
                i = i + 1
            except Exception as exc:
                print('%r generated an exception: %s' % (url, exc))
    return proxy_dict


def chaorongheProxies(filename):
    redis_dict = redis_get_map(REDIS_KEY_PROXIES_LINK)
    urlStr = ""
    urlAes = []
    for key in redis_dict.keys():
        url = key
        if urlStr != "":
            urlStr += "|"
        # 提取加密的订阅
        password = redis_dict.get(key)
        if password and password != "":
            urlAes.append(key)
        else:
            urlStr += url
    remoteToLocalUrl = download_files_for_encryp_proxy(urlAes, redis_dict)
    for key in remoteToLocalUrl.keys():
        if urlStr != "":
            urlStr += "|"
        urlStr += key
    params = generateProxyConfig(urlStr)
    # 本地配置   urllib.parse.quote("/path/to/clash/config_template.yaml"
    # 网络配置   "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini"
    try:
        response = requests.get(getProxyServerChosen(), params=params, timeout=360)
        if response.status_code == 200 and response.content != '':
            # 合并加密下载的和普通的
            # 订阅成功处理逻辑
            # print(response.text)
            if os.path.exists(filename):
                os.remove(filename)
            with open(filename, 'w'):
                pass
            write_content_to_file(response.content, filename, 10)
            thread = threading.Thread(target=download_secert_file,
                                      args=(
                                          filename, f"{public_path}{getFileNameByTagName('proxyConfigSecret')}.txt",
                                          'proxy', isOpenFunction('switch22'),
                                          isOpenFunction('switch23'), isOpenFunction('switch30'),
                                          isOpenFunction('switch31'), isOpenFunction('switch32')))
            thread.start()
            thread_remove(remoteToLocalUrl)
            return "result"
        else:
            try:
                # 使用转换器失败不能合并就直接把下载的一个订阅拿来用
                for key, filePath in remoteToLocalUrl.items():
                    os.rename(filePath, filename)
                    return "result"
                # 订阅失败处理逻辑
                print("Error:", response.status_code, response.reason)
                return "empty"
            except Exception as e:
                print("Error: fail to chaorongheProxy,instead,we download a remote yaml as the final proxy\n")
                pass
            finally:
                thread_remove(remoteToLocalUrl)
    except Exception as e:
        # 转换服务器找不到
        try:
            # 使用转换器失败不能合并就直接把下载的一个订阅拿来用
            for key, filePath in remoteToLocalUrl.items():
                if os.path.exists(filename):
                    os.remove(filename)
                os.rename(filePath, filename)
                return "result"
            # 订阅失败处理逻辑
            print("Error: fail to connect to proxy server")
            return "empty"
        except Exception as e:
            print("Error: fail to chaorongheProxy,instead,we download a remote yaml as the final proxy\n")
            pass
        finally:
            thread_remove(remoteToLocalUrl)


def thread_remove(remoteToLocalUrl):
    # url = ""
    for key in remoteToLocalUrl.values():
        try:
            if os.path.exists(key):
                os.remove(key)
        except Exception as e:
            pass


# 线程池切分下载的内容写入本地
def write_chunk(chunk, filename, offset):
    with open(filename, 'r+b') as f:
        f.seek(offset)
        f.write(chunk)


def write_file_thread(content, filename, start, end):
    write_chunk(content[start:end], filename, start)


def write_content_to_file(content, filename, num_threads):
    # 计算每个线程要处理的数据块大小
    chunk_size = len(content) // num_threads

    # 创建字节流分割点列表
    points = [i * chunk_size for i in range(num_threads)]
    points.append(len(content))

    # 定义线程任务
    def worker(start, end):
        write_file_thread(content, filename, start, end)

    # 启动多个线程下载和写入数据块
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_tasks = []
        for i in range(num_threads):
            start, end = points[i], points[i + 1]
            future = executor.submit(worker, start, end)
            future_tasks.append(future)

        for future in future_tasks:
            future.result()


def setRandomValueChosen(key1, key2):
    redis_dict = redis_get_map(key1)
    if redis_dict and len(redis_dict.items()) > 0:
        for key, value in redis_dict.items():
            dict = {}
            dict[key2] = value
            redis_add_map(key2, dict)
            return
    else:
        if key1 == REDIS_KEY_PROXIES_SERVER:
            initProxyServer()
        elif key1 == REDIS_KEY_PROXIES_MODEL:
            initProxyModel()


# 黑白名单线程数获取
def init_threads_num():
    global threadsNum
    data = threadsNum.get(REDIS_KEY_THREADS)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_THREADS)
    if num:
        try:
            num = int(num)
        except:
            num = 1000
        if num == 0:
            num = 1000
            redis_add(REDIS_KEY_THREADS, num)
            threadsNum[REDIS_KEY_THREADS] = num
            redis_public_message(f'{REDIS_KEY_UPDATE_THREAD_NUM_FLAG}_{num}')
        else:
            threadsNum[REDIS_KEY_THREADS] = num
    else:
        num = 1000
        redis_add(REDIS_KEY_THREADS, num)
        threadsNum[REDIS_KEY_THREADS] = num
        redis_public_message(f'{REDIS_KEY_UPDATE_THREAD_NUM_FLAG}_{num}')
    return num


# dns并发查询数获取
def init_dns_timeout():
    global dnstimeout
    data = dnstimeout.get(REDIS_KEY_DNS_TIMEOUT)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_DNS_TIMEOUT)
    if num:
        try:
            num = int(num)
        except:
            num = 30
        if num == 0:
            num = 30
            redis_add(REDIS_KEY_DNS_TIMEOUT, num)
            dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
        else:
            dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
    else:
        num = 30
        redis_add(REDIS_KEY_DNS_TIMEOUT, num)
        dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
    return num


# dns并发查询数获取
def init_dns_query_num():
    global dnsquerynum
    data = dnsquerynum.get(REDIS_KEY_DNS_QUERY_NUM)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_DNS_QUERY_NUM)
    if num:
        try:
            num = int(num)
        except:
            num = 1000
        if num == 0:
            num = 1000
            redis_add(REDIS_KEY_DNS_QUERY_NUM, num)
            dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
        else:
            dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
    else:
        num = 1000
        redis_add(REDIS_KEY_DNS_QUERY_NUM, num)
        dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
    return num


# 中国DNS端口获取
def init_china_dns_port():
    global chinadnsport
    data = chinadnsport.get(REDIS_KEY_CHINA_DNS_PORT)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_CHINA_DNS_PORT)
    if num:
        try:
            num = int(num)
        except:
            num = 5336
        if num == 0:
            num = 5336
            redis_add(REDIS_KEY_CHINA_DNS_PORT, num)
            chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
            redis_public_message(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG)
        else:
            chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
    else:
        num = 5336
        redis_add(REDIS_KEY_CHINA_DNS_PORT, num)
        chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
        redis_public_message(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG)
    return num


# 外国DNS端口获取
def init_extra_dns_port():
    global extradnsport
    data = extradnsport.get(REDIS_KEY_EXTRA_DNS_PORT)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_EXTRA_DNS_PORT)
    if num:
        try:
            num = int(num)
        except:
            num = 7874
        if num == 0:
            num = 7874
            redis_add(REDIS_KEY_EXTRA_DNS_PORT, num)
            extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
            redis_public_message(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG)
        else:
            extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
    else:
        num = 7874
        redis_add(REDIS_KEY_EXTRA_DNS_PORT, num)
        extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
        redis_public_message(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG)
    return num


# 中国DNS服务器获取
def init_china_dns_server():
    global chinadnsserver
    data = chinadnsserver.get(REDIS_KEY_CHINA_DNS_SERVER)
    if data and data != '':
        return data
    num = redis_get(REDIS_KEY_CHINA_DNS_SERVER)
    if num:
        num = num
        if num == "":
            num = "127.0.0.1"
            redis_add(REDIS_KEY_CHINA_DNS_SERVER, num)
            chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
            redis_public_message(REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG)
        else:
            chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
    else:
        num = "127.0.0.1"
        redis_add(REDIS_KEY_CHINA_DNS_SERVER, num)
        chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
        redis_public_message(REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG)
    return num


# 外国DNS服务器获取
def init_extra_dns_server():
    global extradnsserver
    data = extradnsserver.get(REDIS_KEY_EXTRA_DNS_SERVER)
    if data and data != '':
        return data
    num = redis_get(REDIS_KEY_EXTRA_DNS_SERVER)
    if num:
        num = num
        if num == "":
            num = "127.0.0.1"
            redis_add(REDIS_KEY_EXTRA_DNS_SERVER, num)
            extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
            redis_public_message(REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG)
        else:
            extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
    else:
        num = "127.0.0.1"
        redis_add(REDIS_KEY_EXTRA_DNS_SERVER, num)
        extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
        redis_public_message(REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG)
    return num


def initReloadCacheForNormal():
    for redisKey in allListArr:
        if redisKey == REDIS_KEY_FUNCTION_DICT:
            init_function_dict()
        elif redisKey == REDIS_KEY_FILE_NAME:
            init_file_name()
    for redisKey in hugeDataList:
        if redisKey in REDIS_KEY_YOUTUBE:
            try:
                global redisKeyYoutube
                redisKeyYoutube.clear()
                dict = redis_get_map(REDIS_KEY_YOUTUBE)
                if dict and len(dict.keys()) > 0:
                    redisKeyYoutube.update(dict)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_BILIBILI:
            try:
                global redisKeyBilili
                redisKeyBilili.clear()
                dict = redis_get_map(REDIS_KEY_BILIBILI)
                if dict and len(dict.keys()) > 0:
                    redisKeyBilili.update(dict)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_HUYA:
            try:
                global redisKeyHuya
                redisKeyHuya.clear()
                dict = redis_get_map(REDIS_KEY_HUYA)
                if dict and len(dict.keys()) > 0:
                    redisKeyHuya.update(dict)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_YY:
            try:
                global redisKeyYY
                redisKeyYY.clear()
                dict = redis_get_map(REDIS_KEY_YY)
                if dict and len(dict.keys()) > 0:
                    redisKeyYY.update(dict)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_DOUYIN:
            try:
                global redisKeyDOUYIN
                redisKeyDOUYIN.clear()
                dict = redis_get_map(REDIS_KEY_DOUYIN)
                if dict and len(dict.keys()) > 0:
                    redisKeyDOUYIN.update(dict)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_ALIST:
            try:
                global redisKeyAlist
                global redisKeyAlistM3u
                global redisKeyAlistM3uTsPath
                redisKeyAlist.clear()
                dict = redis_get_map(REDIS_KEY_ALIST)
                if dict and len(dict.keys()) > 0:
                    redisKeyAlist.update(dict)
                dict3 = redis_get_map(REDIS_KEY_Alist_M3U)
                if dict3 and len(dict3.keys()) > 0:
                    redisKeyAlistM3u.update(dict3)
                dict4 = redis_get_map(REDIS_KEY_Alist_M3U_TS_PATH)
                if dict4 and len(dict4.keys()) > 0:
                    redisKeyAlistM3uTsPath.update(dict4)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_TWITCH:
            try:
                global redisKeyTWITCH
                redisKeyTWITCH.clear()
                dict = redis_get_map(REDIS_KEY_TWITCH)
                if dict and len(dict.keys()) > 0:
                    redisKeyTWITCH.update(dict)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_NORMAL:
            try:
                global redisKeyNormal
                global redisKeyNormalM3U
                redisKeyNormal.clear()
                dict = redis_get_map(REDIS_KEY_NORMAL)
                if dict and len(dict.keys()) > 0:
                    redisKeyNormal.update(dict)
                dict3 = redis_get_map(REDIS_KEY_NORMAL_M3U)
                if dict3 and len(dict3.keys()) > 0:
                    redisKeyNormalM3U.update(dict3)
            except Exception as e:
                pass


def initReloadCacheForSpecial():
    for redisKey in specialRedisKey:
        if redisKey in REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME:
            try:
                # 从Redis中读取JSON字符串
                json_string_redis = redis_get(redisKey)
                # 反序列化成Python对象
                my_dict_redis = json.loads(json_string_redis)
                global downAndSecUploadUrlPassAndName
                downAndSecUploadUrlPassAndName.clear()
                downAndSecUploadUrlPassAndName = my_dict_redis.copy()
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME:
            try:
                # 从Redis中读取JSON字符串
                json_string_redis = redis_get(redisKey)
                # 反序列化成Python对象
                my_dict_redis = json.loads(json_string_redis)
                global downAndDeSecUrlPassAndName
                downAndDeSecUrlPassAndName.clear()
                downAndDeSecUrlPassAndName = my_dict_redis.copy()
            except Exception as e:
                pass


def init_pass(cacheKey):
    global redisKeySecretPassNow
    data = redisKeySecretPassNow.get(cacheKey)
    if data and data != '':
        return data
    dict = redis_get_map(REDIS_KEY_SECRET_PASS_NOW)
    if dict and len(dict.keys()) > 0:
        value = dict.get(cacheKey)
        if value:
            redisKeySecretPassNow[cacheKey] = value
            return value
        else:
            value = generateEncryptPassword()
            redisKeySecretPassNow[cacheKey] = value
            tmp_dict = {}
            tmp_dict[cacheKey] = value
            redis_add_map(REDIS_KEY_SECRET_PASS_NOW, tmp_dict)
            return value
    else:
        value = generateEncryptPassword()
        redisKeySecretPassNow[cacheKey] = value
        tmp_dict = {}
        tmp_dict[cacheKey] = value
        redis_add_map(REDIS_KEY_SECRET_PASS_NOW, tmp_dict)
        return value


# 获取gitee数据
def init_gitee(cachekey, redisKey, cache):
    data = cache.get(cachekey)
    if data:
        return data
    allDict = redis_get_map(redisKey)
    if allDict and len(allDict.keys()) > 0:
        cacheValue = allDict.get(cachekey)
        if cacheValue:
            cacheValue = cacheValue
            cache[cachekey] = cacheValue
        else:
            cacheValue = ''
            cache[cachekey] = cacheValue
            tmp_dict = {cachekey: cacheValue}
            redis_add_map(redisKey, tmp_dict)
        return cacheValue
    else:
        cacheValue = ''
        cache[cachekey] = cacheValue
        tmp_dict = {cachekey: cacheValue}
        redis_add_map(redisKey, tmp_dict)
        return cacheValue


# gitee-修改数据
def update_gitee(cachekey, value, redisKey, cache):
    tmp_dict = {cachekey: value}
    # 设定默认选择的模板
    redis_add_map(redisKey, tmp_dict)
    cache[cachekey] = value


def changeFileName2(cachekey, newFileName):
    global file_name_dict
    tmp_dict = {}
    tmp_dict[cachekey] = newFileName
    redis_add_map(REDIS_KEY_FILE_NAME, tmp_dict)
    file_name_dict[cachekey] = newFileName
    if cachekey == 'chinaTopDomain':
        # 通知dns服务器更新内存
        redis_public_message(f'{REDIS_KEY_UPDATE_CHINA_DOMAIN_FLAG}_{newFileName}')
    elif cachekey == 'foreignTopDomain':
        # 通知dns服务器更新内存
        redis_public_message(f'{REDIS_KEY_UPDATE_FOREIGN_DOMAIN_FLAG}_{newFileName}')
    elif cachekey == 'dnsMode':
        # 通知dns服务器更新内存
        redis_public_message(f'{REDIS_KEY_UPDATE_DNS_MODE_FLAG}_{newFileName}')
    elif cachekey == 'dnsLimitRecordSecondDomain':
        # 通知dns服务器更新内存
        redis_public_message(f'{REDIS_KEY_UPDATE_DNS_LIMIT_SECOND_DOMAIN_FLAG}_{newFileName}')
    elif cachekey == 'dnsLimitRecordSecondLenDomain':
        # 通知dns服务器更新内存
        redis_public_message(f'{REDIS_KEY_UPDATE_DNS_LIMIT_SECOND_DOMAIN_LEN_FLAG}_{newFileName}')
    elif cachekey == 'switch24':
        # 通知dns服务器更新内存
        redis_public_message(f'{REDIS_KEY_OPEN_AUTO_UPDATE_SIMPLE_WHITE_AND_BLACK_LIST_FLAG}_{newFileName}')
    return newFileName


# 直播源订阅密码刷新
def update_m3u_subscribe_pass_by_hand(cachekey, password):
    tagname = ''
    if cachekey == 'm3u':
        tagname = '直播源订阅'
    elif cachekey == 'proxy':
        tagname = '节点订阅'
    elif cachekey == 'ipv6':
        tagname = 'ipv6订阅'
    elif cachekey == 'ipv4':
        tagname = 'ipv4订阅'
    elif cachekey == 'blacklist':
        tagname = '域名黑名单订阅'
    elif cachekey == 'whitelist':
        tagname = '域名白名单订阅'
    global redisKeySecretPassNow
    oldpass = redisKeySecretPassNow.get(cachekey)
    if oldpass:
        addHistorySubscribePass(oldpass, tagname)
    else:
        oldpassDict = redis_get_map(REDIS_KEY_SECRET_PASS_NOW)
        if oldpassDict and len(oldpassDict.keys()) > 0:
            oldpass = oldpassDict.get(cachekey)
            addHistorySubscribePass(oldpass.decode(), tagname)
    tmp_dict = {}
    tmp_dict[cachekey] = password
    redis_add_map(REDIS_KEY_SECRET_PASS_NOW, tmp_dict)
    redisKeySecretPassNow[cachekey] = password
    return password


# 直播源订阅密码刷新
def update_m3u_subscribe_pass(cachekey):
    tagname = ''
    if cachekey == 'm3u':
        tagname = '直播源订阅'
    elif cachekey == 'proxy':
        tagname = '节点订阅'
    elif cachekey == 'ipv6':
        tagname = 'ipv6订阅'
    elif cachekey == 'ipv4':
        tagname = 'ipv4订阅'
    elif cachekey == 'blacklist':
        tagname = '域名黑名单订阅'
    elif cachekey == 'whitelist':
        tagname = '域名白名单订阅'
    # redisKeySecretPassNow = {'m3u': '', 'whitelist': '', 'blacklist': '', 'ipv4': '', 'ipv6': '', 'proxy': ''}
    global redisKeySecretPassNow
    oldpass = redisKeySecretPassNow.get(cachekey)
    if oldpass:
        addHistorySubscribePass(oldpass, tagname)
    else:
        oldpassDict = redis_get_map(REDIS_KEY_SECRET_PASS_NOW)
        if oldpassDict and len(oldpassDict.keys()) > 0:
            oldpass = oldpassDict.get(cachekey)
            addHistorySubscribePass(oldpass.decode(), tagname)
    password = generateEncryptPassword()
    tmp_dict = {}
    tmp_dict[cachekey] = password
    redis_add_map(REDIS_KEY_SECRET_PASS_NOW, tmp_dict)
    redisKeySecretPassNow[cachekey] = password
    return password


def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


# 生成订阅链接加密密码
def generateEncryptPassword():
    return generate_password() + "paperbluster" + base64.b64encode(os.urandom(16)).decode('utf-8')


# 返回字符串密码和比特流iv
def getIV(passwordStr):
    arr = passwordStr.split("paperbluster")
    iv_decoded = base64.b64decode(arr[1])
    return arr[0].encode('utf-8'), iv_decoded


# 加密函数   # bytes ciphertext
def encrypt(plaintext, cachekey):
    password = init_pass(cachekey)
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


# 关键字，分组
m3u_whitlist = {}
# 分组,排名
m3u_whitlist_rank = {}
m3u_blacklist = {}


# 初始化m3u黑名单
def init_m3u_blacklist():
    global m3u_blacklist
    dict = redis_get_map(REDIS_KEY_M3U_BLACKLIST)
    if not dict or len(dict) == 0:
        dict = {"DJ音乐": ''}
        redis_add_map(REDIS_KEY_M3U_BLACKLIST, dict)
        m3u_blacklist = dict.copy()
    m3u_blacklist = dict.copy()


# 初始化m3u白名单
def init_m3u_whitelist():
    global m3u_whitlist
    global m3u_whitlist_rank
    dict = redis_get_map(REDIS_KEY_M3U_WHITELIST)
    dictRank = redis_get_map(REDIS_KEY_M3U_WHITELIST_RANK)
    if not dict or len(dict) == 0:
        dict = {"央視": "央视", "央视": "央视", "中央": "央视", "CCTV": "央视", "cctv": "央视",
                "衛視": "卫视", "卫视": "卫视", "CGTN": "央视", "環球電視": "央视", "环球电视": "央视",
                }
        redis_add_map(REDIS_KEY_M3U_WHITELIST, dict)
        m3u_whitlist = dict.copy()
    else:
        m3u_whitlist = dict.copy()
    if not dictRank or len(dictRank) == 0:
        dictRank = {'央视': '1', '卫视': '2'
                    }
        redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, dictRank)
        m3u_whitlist_rank = dictRank.copy()
    else:
        m3u_whitlist_rank = dictRank.copy()
    getRankWhiteList()


# 获取软路由主路由ip
def getMasterIp():
    # 获取宿主机IP地址
    host_ip = '192.168.5.1'
    return host_ip


# 外国DNS服务器获取
def init_IP():
    data = ip.get(REDIS_KEY_IP)
    if data and data != '':
        return data
    num = redis_get(REDIS_KEY_IP)
    if num:
        num = num
        if num == "":
            num = getMasterIp()
            redis_add(REDIS_KEY_IP, num)
            ip[REDIS_KEY_IP] = num
        ip[REDIS_KEY_IP] = num
    else:
        num = getMasterIp()
        redis_add(REDIS_KEY_IP, num)
        ip[REDIS_KEY_IP] = num
    return num


ignore_domain = ['com.', 'cn.', 'org.', 'net.', 'edu.', 'gov.', 'mil.', 'int.', 'biz.', 'info.', 'name.', 'pro.',
                 'asia.', 'us.', 'uk.', 'jp.']



# 提取二级、一级级域名
def stupidThink(domain_name):
    try:
        sub_domains = ['.'.join(domain_name.split('.')[i:]) for i in range(len(domain_name.split('.')) - 1)]
    except Exception as e:
        return ''
    # 一级域名,不是顶级域名那种
    domain_first = sub_domains[-1]
    domain_second = None
    try:
        # 二级域名
        domain_second = sub_domains[-2]
    except Exception as e:
        pass
    try:
        # 尽可能争取存储到二级域名，但是要避免垃圾域名和测试域名
        if domain_second:
            for key in ignore_domain:
                # 一级域名有顶级域名，找二级域名,没有还是用一级域名
                if domain_first.startswith(key):
                    return domain_second
            # 怀疑是垃圾二级域名，只记录一级域名
            if len(domain_second.split('.')[0]) >= 20:
                return domain_first
            return domain_second
        return domain_first
    except Exception as e:
        return domain_first


def addHistorySubscribePass(password, name):
    my_dict = {password: name}
    redis_add_map(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS, my_dict)


file_name_dict_default = {'allM3u': 'allM3u', 'allM3uSecret': 'allM3uSecret', 'aliveM3u': 'aliveM3u',
                          'healthM3u': 'healthM3u',
                          'tvDomainForAdguardhome': 'tvDomainForAdguardhome',
                          'tvDomainForAdguardhomeSecret': 'tvDomainForAdguardhomeSecret',
                          'whiteListDnsmasq': 'whiteListDnsmasq', 'whiteListDnsmasqSecret': 'whiteListDnsmasqSecret',
                          'whiteListDomian': 'whiteListDomian',
                          'whiteListDomianSecret': 'whiteListDomianSecret',
                          'blackListDomain': 'blackListDomain',
                          'blackListDomainSecret': 'blackListDomainSecret', 'ipv4': 'ipv4', 'ipv4Secret': 'ipv4Secret',
                          'ipv6': 'ipv6',
                          'ipv6Secret': 'ipv6Secret', 'proxyConfig': 'proxyConfig',
                          'proxyConfigSecret': 'proxyConfigSecret',
                          'whitelistDirectRule': 'whitelistDirectRule', 'blacklistProxyRule': 'blacklistProxyRule',
                          'simpleOpenclashFallBackFilterDomain': 'simpleOpenclashFallBackFilterDomain',
                          'simpleblacklistProxyRule': 'simpleblacklistProxyRule', 'simpleDnsmasq': 'simpleDnsmasq',
                          'simplewhitelistProxyRule': 'simplewhitelistProxyRule', 'minTimeout': '5', 'maxTimeout': '30',
                          'usernameSys': 'admin', 'passwordSys': 'password', 'normalM3uClock': '7200',
                          'normalSubscriberClock': '10800',
                          'failTs': 'https://raw.githubusercontent.com/paperbluster/ppap/main/update.mp4',
                          'proxySubscriberClock': '3600', 'autoDnsSwitchClock': '600',
                          'reliveAlistTsTime': '600', 'recycle': '7200', 'chinaTopDomain': 'cn,中国',
                          'foreignTopDomain':
                              'xyz,club,online,site,top,win', 'dnsMode': '0', 'dnsLimitRecordSecondDomain': '15',
                          'dnsLimitRecordSecondLenDomain': '15', 'lastaliveport': '0'}


def init_file_name():
    count = 0
    success = False
    while count < 3:
        dict = redis_get_map(REDIS_KEY_FILE_NAME)
        if dict and len(dict.keys()) > 0:
            global file_name_dict
            file_name_dict.clear()
            file_name_dict.update(dict)
            success = True
            break
        else:
            count += 1
    if not success:
        redis_add_map(REDIS_KEY_FILE_NAME, file_name_dict_default)


def getFileNameByTagName(tagname):
    name = file_name_dict.get(tagname)
    if name and name != '':
        return name
    else:
        dict = redis_get_map(REDIS_KEY_FILE_NAME)
        if dict and len(dict.keys()) > 0:
            name = dict.get(tagname)
            if name and name != '':
                file_name_dict[tagname] = name
                return name
            else:
                name = file_name_dict_default.get(tagname)
                file_name_dict[tagname] = name
                redis_add_map(REDIS_KEY_FILE_NAME, {tagname: name})
                return name
        else:
            name = file_name_dict_default.get(tagname)
            file_name_dict[tagname] = name
            redis_add_map(REDIS_KEY_FILE_NAME, {tagname: name})
            return name


############################################################协议区####################################################


# 需要额外操作的
clockArr = ['switch25', 'switch26', 'switch27', 'switch28', 'switch13', 'switch25', 'switch33', 'switch34']


def switchSingleFunction(id, state):
    if id in clockArr:
        toggle_m3u(id, state)
    else:
        global function_dict
        function_dict[id] = str(state)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)


def returnDictCache(redisKey, cacheDict):
    if len(cacheDict.keys()) > 0:
        return jsonify(cacheDict)
    dict = redis_get_map(redisKey)
    if dict and len(dict.keys()) > 0:
        cacheDict.update(dict)
    return jsonify(cacheDict)


def dealRemoveRankGroup(rank):
    rankNum = int(rank)
    updateDict = {}
    for key, value in m3u_whitlist_rank.items():
        num = int(value)
        if num <= rankNum:
            continue
        finalRank = str(num - 1)
        updateDict[key] = finalRank
        m3u_whitlist_rank[key] = finalRank
    if len(updateDict) > 0:
        redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
    getRankWhiteList()


def checkAndRemoveM3uRank(group):
    global m3u_whitlist_rank
    global m3u_whitlist
    if group not in m3u_whitlist.values():
        if group in m3u_whitlist_rank:
            rank = m3u_whitlist_rank.get(group)
            del m3u_whitlist_rank[group]
            redis_del_map_key(REDIS_KEY_M3U_WHITELIST_RANK, group)
            rankNum = int(rank)
            updateDict = {}
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                if num <= rankNum:
                    continue
                finalRank = str(num - 1)
                updateDict[key] = finalRank
                m3u_whitlist_rank[key] = finalRank
            if len(updateDict) > 0:
                redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
    getRankWhiteList()


def checkAndUpdateM3uRank(group, rank):
    if group == '':
        return
    global m3u_whitlist_rank
    global m3u_whitlist
    rankNum = int(rank)
    updateDict = {}
    updateDict[group] = rank
    # 新分组
    if group not in m3u_whitlist_rank:
        if rankNum == -99:
            maxnow = rankNum
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                maxnow = max(num, maxnow)
            maxnow = maxnow + 1
            updateDict[group] = str(maxnow)
            redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
            m3u_whitlist_rank[group] = str(maxnow)
        else:
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                if num < rankNum:
                    continue
                finalRank = str(num + 1)
                updateDict[key] = finalRank
                m3u_whitlist_rank[key] = finalRank
            redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
            m3u_whitlist_rank[group] = rank
    else:
        oldRank = int(m3u_whitlist_rank.get(group))
        # 排名后退，中间排名向前
        if oldRank < rankNum:
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                if num <= oldRank:
                    continue
                if num > rankNum:
                    continue
                finalRank = str(num - 1)
                updateDict[key] = finalRank
                m3u_whitlist_rank[key] = finalRank
        # 排名前进，中间排名向后
        elif oldRank > rankNum:
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                if num < rankNum:
                    continue
                if num >= oldRank:
                    continue
                finalRank = str(num + 1)
                updateDict[key] = finalRank
                m3u_whitlist_rank[key] = finalRank
        redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
        m3u_whitlist_rank[group] = rank
    getRankWhiteList()


def chaoronghe6():
    try:
        return chaorongheProxies(f"{secret_path}{getFileNameByTagName('proxyConfig')}.yaml")
    except:
        return "empty"


def chaoronghe7():
    path1 = f"{secret_path}{getFileNameByTagName('simpleOpenclashFallBackFilterDomain')}.txt"
    path2 = f"{secret_path}{getFileNameByTagName('simpleblacklistProxyRule')}.txt"
    try:
        return chaoronghebase2(REDIS_KEY_DNS_SIMPLE_BLACKLIST,
                               path1,
                               OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT,
                               OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT,
                               path2,
                               PROXY_RULE_LEFT)
    except Exception as e:
        return "empty"


def chaoronghe8():
    path1 = f"{secret_path}{getFileNameByTagName('simpleDnsmasq')}.conf"
    path2 = f"{secret_path}{getFileNameByTagName('simplewhitelistProxyRule')}.txt"
    try:
        return chaoronghebase2(REDIS_KEY_DNS_SIMPLE_WHITELIST, path1
                               ,
                               BLACKLIST_DNSMASQ_FORMATION_LEFT,
                               BLACKLIST_DNSMASQ_FORMATION_right,
                               path2,
                               DIRECT_RULE_LEFT)
    except Exception as e:
        return "empty"


def getUrlFileName(url):
    arr = url.split('/')
    return arr[len(arr) - 1]


def chaoronghe9():
    global downAndSecUploadUrlPassAndName
    urls = []
    passwordDict = {}
    filenameDict = {}
    secretNameDict = {}
    try:
        for url, urlDict in downAndSecUploadUrlPassAndName.items():
            password = urlDict['password']
            secretName = urlDict['secretName']
            filename = getUrlFileName(url)
            filenameDict[url] = f"{secret_path}{filename}"
            secretNameDict[url] = f"{public_path}{secretName}"
            urls.append(url)
            passwordDict[url] = password
        download_files2(urls, passwordDict, filenameDict, secretNameDict,
                        isOpenFunction('switch30'),
                        isOpenFunction('switch31'), isOpenFunction('switch32'))
        return "result"
    except Exception as e:
        return "empty"


def chaoronghe10():
    global downAndDeSecUrlPassAndName
    urls = []
    passwordDict = {}
    filenameDict = {}
    try:
        for url, urlDict in downAndDeSecUrlPassAndName.items():
            password = urlDict['password']
            secretName = urlDict['secretName']
            filenameDict[url] = f"{secret_path}{secretName}"
            urls.append(url)
            passwordDict[url] = password
        download_files3(urls, passwordDict, filenameDict)
        return "result"
    except Exception as e:
        return "empty"


async def download_file5_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                task = asyncio.ensure_future(grab2(session, id, m3u_dict, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"bilibili Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files5():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    global time_clock_update_dict
    nowId = time_clock_update_dict.get('bilibiliId')
    m3u_dict = await download_file5_single([nowId], mintimeout, maxTimeout)
    return m3u_dict


async def download_files6_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                if id == 'huya':
                    continue
                task = asyncio.ensure_future(grab3(session, id, m3u_dict, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files6():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    global time_clock_update_dict
    nowId = time_clock_update_dict.get('huyaId')
    m3u_dict = await download_files6_single([nowId], mintimeout, maxTimeout)
    return m3u_dict


async def download_files7_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                if id == 'YY':
                    continue
                task = asyncio.ensure_future(grab4(session, id, m3u_dict, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files_douyin_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                if id == 'Douyin':
                    continue
                task = asyncio.ensure_future(grab_douyin(session, id, m3u_dict, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files8_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                if id == 'Twitch':
                    continue
                task = asyncio.ensure_future(grab5(session, id, m3u_dict, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"twitch Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files_normal_single():
    global redisKeyNormal
    ids = redisKeyNormal.keys()
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = {}
    chongqing_ids = []
    migu_ids = {}
    ipanda_ids = {}
    for key in ids:
        id_arr = key.split(',')
        if id_arr[0] == 'cq':
            try:
                chongqing_ids.append(id_arr[1])
            except:
                pass
        elif id_arr[0] == 'migu':
            try:
                migu_ids[id_arr[1]] = [id_arr[2], id_arr[3]]
            except:
                pass
        elif id_arr[0] == 'ipanda':
            # channel,channel_id
            ipanda_ids[id_arr[1]] = id_arr[2]
    async with aiohttp.ClientSession() as session:
        try:
            for id in chongqing_ids:
                m3u_dict[f'cq,{id}'] = ''
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"normal Failed to fetch files. Error: {e}")
        try:
            for id in migu_ids.keys():
                arr = migu_ids.get(id)
                m3u_dict[f'migu,{id},{arr[0]},{arr[1]}'] = ''
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"migu Failed to fetch files. Error: {e}")
        try:
            await deal_qiumihui(session, m3u_dict, mintimeout, maxTimeout)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"qiumihui Failed to fetch files. Error: {e}")
        try:
            await deal_skylinewebcams(session, m3u_dict, mintimeout, maxTimeout)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"skylinewebcams Failed to fetch files. Error: {e}")
        try:
            tasks = []
            for id, value in ipanda_ids.items():
                task = asyncio.ensure_future(
                    grab_normal_ipanda(session, id, m3u_dict, mintimeout, maxTimeout, 'ipanda', value))
                tasks.append(task)
            await asyncio.gather(*tasks)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"ipanda Failed to fetch files. Error: {e}")
        try:
            await  grab_normal_longzhu(session, m3u_dict, mintimeout, maxTimeout, 'longzhu')
        except Exception as e:
            print(f"longzhu Failed to fetch files. Error: {e}")
        try:
            await  grab_normal_857(session, m3u_dict, mintimeout, maxTimeout, '857')
        except Exception as e:
            print(f"857 Failed to fetch files. Error: {e}")
    return m3u_dict


async def deal_skylinewebcams(session, m3u_dict, mintimeout, maxTimeout):
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Cookie": "PHPSESSID=3fbcaedr3jdolljejra92ouag0",
        "Referer": "https://www.skylinewebcams.com/",
        "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Microsoft Edge\";v=\"114\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67"
    }

    url = "https://www.skylinewebcams.com/zh/webcam.html"
    pref = 'https://www.skylinewebcams.com/'
    try:
        try:
            async with session.get(url, headers=headers, timeout=mintimeout) as response:
                data = await response.read()

        except asyncio.TimeoutError:
            async with session.get(url, headers=headers, timeout=maxTimeout) as response:
                data = await response.read()
        if data:
            redisKeyNormal1 = {key: value for key, value in redisKeyNormal.items() if
                               not key.startswith('skylinewebcams,')}
            redisKeyNormal.clear()
            redisKeyNormal.update(redisKeyNormal1)
            html = data.decode()
            soup = BeautifulSoup(html, 'html.parser')
            for element in soup.find_all('a', class_='col-xs-12 col-sm-6 col-md-4'):
                id = pref + element.get('href')
                img = element.find('img').get('src')
                name = element.find('p', class_='tcam').text + '_' + element.find('p', class_='subt').text
                redisKeyNormal[f'skylinewebcams,{id}'] = f'{name},{img}'
                m3u_dict[f'skylinewebcams,{id}'] = ''

    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"skylinewebcams Failed to fetch files. Error: {e}")


async def deal_qiumihui(session, m3u_dict, mintimeout, maxTimeout):
    try:
        check_url = f'https://aapi.qmh01.com/api/room/page?roomType=&navId=&roomId=&word=&page=1&pageSize=30&channelId=3&platform=1'
        try:
            async with session.get(check_url, timeout=mintimeout) as response:
                data = await response.read()
                m3u8_dict = json.loads(data.decode('utf-8'))['data']['list']

        except asyncio.TimeoutError:
            async with session.get(check_url, timeout=maxTimeout) as response:
                data = await response.read()
                m3u8_dict = json.loads(data.decode('utf-8'))['data']['list']
        if m3u8_dict:
            redisKeyNormal1 = {key: value for key, value in redisKeyNormal.items() if
                               not key.startswith('qiumihui,')}
            redisKeyNormal.clear()
            redisKeyNormal.update(redisKeyNormal1)
            tasks = []
            for dict_single in m3u8_dict:
                task = asyncio.ensure_future(
                    grab_normal_qiumihui(session, m3u_dict, mintimeout, maxTimeout, 'qiumihui', dict_single))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"qiumihui Failed to fetch files. Error: {e}")


async def download_files7():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    global time_clock_update_dict
    nowId = time_clock_update_dict.get('yyId')
    m3u_dict = await download_files7_single([nowId], mintimeout, maxTimeout)
    return m3u_dict


async def download_files_douyin():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    global time_clock_update_dict
    nowId = time_clock_update_dict.get('douyinId')
    m3u_dict = await download_files_douyin_single([nowId], mintimeout, maxTimeout)
    return m3u_dict


async def download_files8():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    global time_clock_update_dict
    nowId = time_clock_update_dict.get('twitchId')
    m3u_dict = await download_files8_single([nowId], mintimeout, maxTimeout)
    return m3u_dict


# 先获取直播状态和真实房间号
bilibili_real_url = 'https://api.live.bilibili.com/room/v1/Room/room_init'
bili_header = {
    'User-Agent': 'Mozilla/5.0 (iPod; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, '
                  'like Gecko) CriOS/87.0.4280.163 Mobile/15E148 Safari/604.1',
}

cim_headers = {
    'User-Agent': 'Mozilla/5.0 (iPod; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, '
                  'like Gecko) CriOS/87.0.4280.163 Mobile/15E148 Safari/604.1',
}

biliurl = 'https://api.live.bilibili.com/xlive/web-room/v2/index/getRoomPlayInfo'


async def grab2(session, id, m3u_dict, mintimeout, maxTimeout):
    now_uuid = time_clock_update_dict.get('bilibiliId')
    try:
        param = {
            'id': id
        }
        try:
            if not is_same_action_uuid(now_uuid, 'bilibililockuuid'):
                return
            async with  session.get(bilibili_real_url, headers=cim_headers, params=param,
                                    timeout=mintimeout) as response:
                res = await response.json()
        except asyncio.TimeoutError:
            if not is_same_action_uuid(now_uuid, 'bilibililockuuid'):
                return
            async with  session.get(bilibili_real_url, headers=cim_headers, params=param,
                                    timeout=maxTimeout) as response:
                res = await response.json()
        if '不存在' in res['msg']:
            return
        live_status = res['data']['live_status']
        if live_status != 1:
            return
        real_room_id = res['data']['room_id']
        param2 = {
            'room_id': real_room_id,
            'protocol': '0,1',
            'format': '0,1,2',
            'codec': '0,1',
            'qn': 10000,
            'platform': 'web',
            'ptype': 8,
        }
        try:
            if not is_same_action_uuid(now_uuid, 'bilibililockuuid'):
                return
            async with  session.get(biliurl, headers=cim_headers, params=param2,
                                    timeout=mintimeout) as response2:
                res = await response2.json()
        except asyncio.TimeoutError:
            if not is_same_action_uuid(now_uuid, 'bilibililockuuid'):
                return
            async with  session.get(biliurl, headers=cim_headers, params=param2,
                                    timeout=maxTimeout) as response2:
                res = await response2.json()
        stream_info = res['data']['playurl_info']['playurl']['stream']
        accept_qn = stream_info[0]['format'][0]['codec'][0]['accept_qn']
        real_lists = []
        real_dict = {}
        nameArr = []
        for data in stream_info:
            format_name = data['format'][0]['format_name']
            if format_name == 'ts':
                base_url = data['format'][-1]['codec'][0]['base_url']
                url_info = data['format'][-1]['codec'][0]['url_info']
                for i, info in enumerate(url_info):
                    for qn in accept_qn:
                        url_ = base_url
                        host = info['host']
                        extra = info['extra']
                        if qn < 10000:
                            qn = qn * 10
                            url_ = re.sub('bluray/index', f'{qn}/index', base_url)
                        elif qn > 10000:
                            continue
                        extra = re.sub('qn=(\d+)', f'qn={qn}', extra)
                        if qn == 10000:
                            namestr = f'线路{i + 1}_{qn}'
                            nameArr.append(namestr)
                            real_lists.append({namestr: f'{host}{url_}{extra}'})
                break
        if real_lists:
            tasks = []
            for real_ in real_lists:
                for key, value in real_.items():
                    task = asyncio.ensure_future(
                        pingM3u(session, value, real_dict, key, mintimeout, maxTimeout, now_uuid, 'bilibililockuuid'))
                    tasks.append(task)
            await asyncio.gather(*tasks)
            if real_dict:
                isOne = len(nameArr) == 1
                if isOne:
                    for key, value in real_dict.items():
                        if nameArr[0] == key:
                            m3u_dict[id] = value
                            return
                else:
                    for i in range(len(nameArr) - 1):
                        for key, value in real_dict.items():
                            if nameArr[i] == key:
                                m3u_dict[id] = value
                                return
                return
        return
    except Exception as e:
        print(f"bilibili An error occurred while processing {id}. Error: {e}")


def huya_live(e):
    i, b = e.split('?')
    r = i.split('/')
    s = re.sub(r'.(flv|m3u8)', '', r[-1])
    c = b.split('&', 3)
    c = [i for i in c if i != '']
    n = {i.split('=')[0]: i.split('=')[1] for i in c}
    fm = urllib.parse.unquote(n['fm'])
    u = base64.b64decode(fm).decode('utf-8')
    p = u.split('_')[0]
    f = str(int(time.time() * 1e7))
    l = n['wsTime']
    t = '0'
    h = '_'.join([p, t, s, f, l])
    m = hashlib.md5(h.encode('utf-8')).hexdigest()
    y = c[-1]
    url = "{}?wsSecret={}&wsTime={}&u={}&seqid={}&{}".format(i, m, l, t, f, y)
    return url


cim_headers_huya = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/75.0.3770.100 Mobile Safari/537.36 '
}

headers_web_YY = {
    'referer': f'https://www.yy.com/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36 '
}

headers_YY = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/95.0.4638.69 Safari/537.36 '
}


async def room_id_(session, id, mintimeout, maxTimeout, now_uuid):
    url = 'https://www.yy.com/{}'.format(id)
    try:
        if not is_same_action_uuid(now_uuid, 'yylockuuid'):
            return
        async with session.get(url, headers=headers_web_YY,
                               timeout=mintimeout) as response:
            if response.status == 200:
                room_id = re.findall('ssid : "(\d+)', response.text)[0]
                return room_id
    except asyncio.TimeoutError:
        if not is_same_action_uuid(now_uuid, 'yylockuuid'):
            return
        async with session.get(url, headers=headers_web_YY,
                               timeout=maxTimeout) as response:
            if response.status == 200:
                room_id = re.findall('ssid : "(\d+)', response.text)[0]
                return room_id


async def fetch_room_url(session, room_url, headers, mintimeout, maxTimeout, now_uuid):
    try:
        if not is_same_action_uuid(now_uuid, 'yylockuuid'):
            return
        async with  session.get(room_url, headers=headers,
                                timeout=mintimeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                return None
    except asyncio.TimeoutError:
        if not is_same_action_uuid(now_uuid, 'yylockuuid'):
            return
        async with  session.get(room_url, headers=headers,
                                timeout=maxTimeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                return None


async def fetch_real_url(session, url, headers, mintimeout, maxTimeout, now_uuid):
    try:
        if not is_same_action_uuid(now_uuid, 'yylockuuid'):
            return
        async with  session.get(url, headers=headers, timeout=mintimeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                return None
    except asyncio.TimeoutError:
        if not is_same_action_uuid(now_uuid, 'yylockuuid'):
            return
        async with  session.get(url, headers=headers, timeout=maxTimeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                return None


async def get_client_id(rid, session, mintimeout, maxTimeout, now_uuid):
    try:
        twitch_room_url = f'https://www.twitch.tv/{rid}'
        try:
            if not is_same_action_uuid(now_uuid, 'twitchlockuuid'):
                return
            async with session.get(twitch_room_url, timeout=mintimeout) as response:
                res = await response.text()
        except asyncio.TimeoutError:
            if not is_same_action_uuid(now_uuid, 'twitchlockuuid'):
                return
            async with session.get(twitch_room_url, timeout=maxTimeout) as response:
                res = await response.text()
        client_id = re.search(r'clientId="(.*?)"', res).group(1)
        return client_id
    except requests.exceptions.ConnectionError:
        raise Exception('ConnectionError')


async def get_sig_token(rid, session, mintimeout, maxTimeout, now_uuid):
    data = {
        "operationName": "PlaybackAccessToken_Template",
        "query": "query PlaybackAccessToken_Template($login: String!, $isLive: Boolean!, $vodID: ID!, "
                 "$isVod: Boolean!, $playerType: String!) {  streamPlaybackAccessToken(channelName: $login, "
                 "params: {platform: \"web\", playerBackend: \"mediaplayer\", playerType: $playerType}) @include("
                 "if: $isLive) {    value    signature    __typename  }  videoPlaybackAccessToken(id: $vodID, "
                 "params: {platform: \"web\", playerBackend: \"mediaplayer\", playerType: $playerType}) @include("
                 "if: $isVod) {    value    signature    __typename  }}",
        "variables": {
            "isLive": True,
            "login": rid,
            "isVod": False,
            "vodID": "",
            "playerType": "site"
        }
    }

    headers = {
        'Client-ID': await get_client_id(rid, session, mintimeout, maxTimeout, now_uuid),
        'Referer': 'https://www.twitch.tv/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/90.0.4430.93 Safari/537.36',
    }
    posturl = 'https://gql.twitch.tv/gql'
    json_data = json.dumps(data)
    try:
        if not is_same_action_uuid(now_uuid, 'twitchlockuuid'):
            return
        async with session.post(posturl, headers=headers, data=json_data,
                                timeout=mintimeout) as response:
            res = await response.json()
    except asyncio.TimeoutError:
        if not is_same_action_uuid(now_uuid, 'twitchlockuuid'):
            return
        async with session.post(posturl, headers=headers, data=json_data,
                                timeout=maxTimeout) as response:
            res = await response.json()
    try:
        token, signature, _ = res['data']['streamPlaybackAccessToken'].values()
    except AttributeError:
        raise Exception("Channel does not exist")
    return signature, token


async def grab5(session, rid, m3u_dict, mintimeout, maxTimeout):
    now_uuid = time_clock_update_dict.get('twitchId')
    try:
        signature, token = await get_sig_token(rid, session, mintimeout, maxTimeout, now_uuid)
        params = {
            'allow_source': 'true',
            'dt': 2,
            'fast_bread': 'true',
            'player_backend': 'mediaplayer',
            'playlist_include_framerate': 'true',
            'reassignments_supported': 'true',
            'sig': signature,
            'supported_codecs': 'vp09,avc1',
            'token': token,
            'cdm': 'wv',
            'player_version': '1.4.0',
        }
        url = f'https://usher.ttvnw.net/api/channel/hls/{rid}.m3u8?{urlencode(params)}'
        final_url = await get_resolution(session, url, mintimeout, maxTimeout, now_uuid, 'twitchlockuuid')
        if final_url:
            m3u_dict[rid] = final_url
        else:
            m3u_dict[rid] = url

    except Exception as e:
        print(f"twitch An error occurred while processing {rid}. Error: {e}")


async def authenticate2(port, session, mintimeout, maxTimeout):
    post_data = '{"terminalType":"AndroidPhone","loginType":"3"}'
    url = f"http://vsc.aikan.miguvideo.com:{port}/EPG/VPE/PHONE/Authenticate"
    headers = {'Content-Type': 'application/json'}
    try:
        async with session.post(url, headers=headers, data=post_data, timeout=mintimeout) as response:
            if response.status == 200:
                return await response.json()
    except Exception as e:
        async with session.post(url, headers=headers, data=post_data, timeout=maxTimeout) as response:
            if response.status == 200:
                return await response.json()


async def fetch_play_url(port, session_id, channel_id, media_id, session, mintimeout, maxTimeout, m3u_dict, source_type,
                         rid):
    pdata = f'{{"businessType":"BTV","channelID":"{channel_id}","mediaID":"{media_id}"}}'
    uri = f"http://vsc.aikan.miguvideo.com:{port}/VSP/V3/PlayChannel"
    headers = {'Cookie': f'JSESSIONID={session_id}'}
    name = f'{source_type},{rid},{channel_id},{media_id}'
    try:
        if name in m3u_dict.keys():
            return
        async with session.post(uri, headers=headers, data=pdata, timeout=mintimeout) as response:
            if response.status == 200:
                play_url = (await response.json()).get('playURL')
                if play_url is not None:
                    m3u_dict[f'{source_type},{rid},{channel_id},{media_id}'] = play_url
                    changeFileName2('lastaliveport', str(port))
    except asyncio.TimeoutError:
        if name in m3u_dict.keys():
            return
        async with session.post(uri, headers=headers, data=pdata, timeout=maxTimeout) as response:
            if response.status == 200:
                play_url = (await response.json()).get('playURL')
                if play_url is not None:
                    m3u_dict[f'{source_type},{rid},{channel_id},{media_id}'] = play_url
                    changeFileName2('lastaliveport', str(port))
    except Exception as e:
        pass


async def grab_normal_migu(session, rid, m3u_dict, mintimeout, maxTimeout, source_type, rid_arr):
    try:
        tasks = []
        lastaliveport = int(getFileNameByTagName('lastaliveport'))
        if lastaliveport != 0:
            auth_task = asyncio.create_task(authenticate2(lastaliveport, session, mintimeout, maxTimeout))
            auth_result = await auth_task
            if auth_result is not None:
                session_id = auth_result.get('sessionID')
                await  fetch_play_url(lastaliveport, session_id, rid_arr[0], rid_arr[1], session, mintimeout,
                                      maxTimeout,
                                      m3u_dict,
                                      source_type, rid)
        name = f'{source_type},{rid},{rid_arr[0]},{rid_arr[1]}'
        if name not in m3u_dict.keys():
            for port in range(7100, 7151):
                auth_task = asyncio.create_task(authenticate2(port, session, mintimeout, maxTimeout))
                auth_result = await auth_task
                if auth_result is None:
                    continue
                session_id = auth_result.get('sessionID')
                play_url_task = asyncio.create_task(
                    fetch_play_url(port, session_id, rid_arr[0], rid_arr[1], session, mintimeout, maxTimeout, m3u_dict,
                                   source_type, rid))
                tasks.append(play_url_task)
            await asyncio.gather(*tasks)
    except Exception as e:
        print(f"migu An error occurred while processing {rid}. Error: {e}")


async def grab_normal_ipanda(session, rid, m3u_dict, mintimeout, maxTimeout, source_type, value):
    url = f'https://vdn.live.cntv.cn/api2/liveHtml5.do?channel=pc://{rid}&channel_id={value}&video_player=1&im=0&client=flash&tsp=1687495941&vn=1537&vc=1&uid=5A9A2532F878A0DB8EFE2BC8B2B191FC&wlan='
    try:
        async with session.get(url, headers=bili_header, timeout=mintimeout) as response:
            data = await response.read()
            # 将bytes转换成字符串并去掉前缀和后缀
            html5VideoDataStr = data.decode('utf-8').replace("var html5VideoData = '", '').replace(
                "';getHtml5VideoData(html5VideoData);", '')
            # 将字符串转换成字典
            dict = json.loads(html5VideoDataStr)['hls_url']
            if dict:
                for key, url in dict.items():
                    if '.m3u8' in url:
                        m3u_dict[f'{source_type},{rid},{value}'] = url
                        break
                    elif '.fly' in url:
                        m3u_dict[f'{source_type},{rid},{value}'] = url
                        break
    except asyncio.TimeoutError:
        async with session.get(url, headers=bili_header, timeout=maxTimeout) as response:
            data = await response.read()
            # 将bytes转换成字符串并去掉前缀和后缀
            html5VideoDataStr = data.decode('utf-8').replace("var html5VideoData = '", '').replace(
                "';getHtml5VideoData(html5VideoData);", '')
            # 将字符串转换成字典
            dict = json.loads(html5VideoDataStr)['hls_url']
            if dict:
                for key, url in dict.items():
                    if '.m3u8' in url:
                        m3u_dict[f'{source_type},{rid},{value}'] = url
                        break
                    elif '.fly' in url:
                        m3u_dict[f'{source_type},{rid},{value}'] = url
                        break
    except Exception as e:
        print(f"cetv An error occurred while processing {rid}. Error: {e}")


async def grab_normal_qiumihui(session, m3u_dict, mintimeout, maxTimeout, source_type, dict_single):
    global redisKeyNormal
    rid = dict_single['roomId']
    title = dict_single['title']
    cover = dict_single['cover']
    m3u8_url = f'https://aapi.qmh01.com/api/room/detail?roomId={rid}&channelId=3&platform=1'
    try:
        async with session.get(m3u8_url, headers=bili_header, timeout=mintimeout) as response:
            data = await response.read()
            m3u8 = json.loads(data.decode('utf-8'))['data']['pushUrl']
            m3u_dict[f'{source_type},{rid}'] = m3u8
            redisKeyNormal[f'{source_type},{rid}'] = f'{title},{cover}'
    except asyncio.TimeoutError:
        async with session.get(m3u8_url, headers=bili_header, timeout=maxTimeout) as response:
            data = await response.read()
            m3u8 = json.loads(data.decode('utf-8'))['data']['pushUrl']
            m3u_dict[f'{source_type},{rid}'] = m3u8
            redisKeyNormal[f'{source_type},{rid}'] = f'{title},{cover}'
    except Exception as e:
        print(f"qiumihui An error occurred while processing {rid}. Error: {e}")


def update_longzhu(dict_url, m3u_dict, rid, source_type, pic, name):
    global redisKeyNormal
    update_dict = {}
    if dict_url:
        url = None
        if 'ud' in dict_url.keys():
            data_dict = dict_url['ud']
            try:
                url = data_dict['m3u8']
            except:
                pass
            if url is None or url == '':
                try:
                    url = data_dict['rtmp']
                except:
                    pass
            if url is None or url == '':
                try:
                    url = data_dict['fly']
                except:
                    pass
        if url is None or url == '':
            if 'hd' in dict_url.keys():
                data_dict = dict_url['hd']
                try:
                    url = data_dict['m3u8']
                except:
                    pass
                if url is None or url == '':
                    try:
                        url = data_dict['rtmp']
                    except:
                        pass
                if url is None or url == '':
                    try:
                        url = data_dict['fly']
                    except:
                        pass
        if url is None or url == '':
            if 'playStreamInfo' in dict_url.keys():
                data_dict = dict_url['playStreamInfo']
                try:
                    url = data_dict['m3u8']
                except:
                    pass
                if url is None or url == '':
                    try:
                        url = data_dict['rtmp']
                    except:
                        pass
                if url is None or url == '':
                    try:
                        url = data_dict['fly']
                    except:
                        pass
        if url is None or url == '':
            if 'sd' in dict_url.keys():
                data_dict = dict_url['sd']
                try:
                    url = data_dict['m3u8']
                except:
                    pass
                if url is None or url == '':
                    try:
                        url = data_dict['rtmp']
                    except:
                        pass
                if url is None or url == '':
                    try:
                        url = data_dict['fly']
                    except:
                        pass
        if url is None or url == '':
            if 'ld' in dict_url.keys():
                data_dict = dict_url['ld']
                try:
                    url = data_dict['m3u8']
                except:
                    pass
                if url is None or url == '':
                    try:
                        url = data_dict['rtmp']
                    except:
                        pass
                if url is None or url == '':
                    try:
                        url = data_dict['fly']
                    except:
                        pass
        if url is None or url == '':
            if 'stream' in dict_url.keys():
                data_dict = dict_url['stream']
                try:
                    url = data_dict['m3u8']
                except:
                    pass
                if url is None or url == '':
                    try:
                        url = data_dict['rtmp']
                    except:
                        pass
                if url is None or url == '':
                    try:
                        url = data_dict['fly']
                    except:
                        pass
        if url is not None and url != '':
            m3u_dict[f'{source_type},{rid}'] = url
            update_dict[f'{source_type},{rid}'] = f'{name},{pic}'
    if len(update_dict) > 0:
        redisKeyNormal.update(update_dict)


# 857直播
def get_hd_url_857(id):
    room = id.split(',')[1]
    url = f'https://json.yyres.co/room/{room}/detail.json?v=1'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.content.decode()
        # 截取JSON字符串，去掉外部的无意义字符串和括号
        json_data = data[data.find("(") + 1:data.rfind(")")]
        # 解析JSON数据并转换为Python对象
        python_data = json.loads(json_data)
        # 访问JSON对象的属性
        try:
            liveUrl = python_data["data"]['stream']['hdM3u8']
        except:
            try:
                liveUrl = python_data["data"]['stream']['hdFlv']
            except:
                try:
                    liveUrl = python_data["data"]['stream']['m3u8']
                except:
                    liveUrl = python_data["data"]['stream']['fly']
        return liveUrl


# migu直播
def get_hd_url_migu(id):
    global time_clock_update_dict
    time_clock_update_dict['miguId'] = id
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 有效直播源,名字/id
    m3u_dict = loop.run_until_complete(download_files_normal_single_migu())
    return m3u_dict[id]


# youtube直播
def get_hd_url_youtube(id):
    global time_clock_update_dict
    # 持有锁的id
    time_clock_update_dict['youtubeId'] = id
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 有效直播源,名字/id
    m3u_dict = loop.run_until_complete(download_files4())
    time_clock_update_dict['youtubeId'] = '0'
    return m3u_dict[id]


# bilibili直播
def get_hd_url_bilibili(id):
    global time_clock_update_dict
    time_clock_update_dict['bilibiliId'] = id
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 有效直播源,名字/id
    m3u_dict = loop.run_until_complete(download_files5())
    time_clock_update_dict['bilibiliId'] = '0'
    return m3u_dict[id]


# huya直播
def get_hd_url_huya(id):
    global time_clock_update_dict
    time_clock_update_dict['huyaId'] = id
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 有效直播源,名字/id
    m3u_dict = loop.run_until_complete(download_files6())
    time_clock_update_dict['huyaId'] = '0'
    return m3u_dict[id]


# yy直播
def get_hd_url_yy(id):
    global time_clock_update_dict
    time_clock_update_dict['yyId'] = id
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 有效直播源,名字/id
    m3u_dict = loop.run_until_complete(download_files7())
    time_clock_update_dict['yyId'] = '0'
    return m3u_dict[id]


# douyin直播
def get_hd_url_douyin(id):
    global time_clock_update_dict
    time_clock_update_dict['douyinId'] = id
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 有效直播源,名字/id
    m3u_dict = loop.run_until_complete(download_files_douyin())
    time_clock_update_dict['douyinId'] = '0'
    return m3u_dict[id]


# twitch直播
def get_hd_url_twitch(id):
    global time_clock_update_dict
    time_clock_update_dict['twitchId'] = id
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 有效直播源,名字/id
    m3u_dict = loop.run_until_complete(download_files8())
    time_clock_update_dict['twitchId'] = '0'
    return m3u_dict[id]


# cq直播
def get_hd_url_cq(id):
    global time_clock_update_dict
    time_clock_update_dict['cqId'] = id
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 有效直播源,名字/id
    m3u_dict = loop.run_until_complete(download_files_normal_single_cq())
    return m3u_dict[id]


async def grab_normal_857(session, m3u_dict, mintimeout, maxTimeout, source_type):
    global redisKeyNormal
    timestr = str(int(time.time()) * 1000)
    m3u8_url = f'https://json.yyres.co/all_live_rooms.json?v={timestr}'
    update_dict = {}
    try:
        try:
            async with session.get(m3u8_url, timeout=mintimeout) as response:
                data = await response.read()
        except asyncio.TimeoutError:
            async with session.get(m3u8_url, timeout=maxTimeout) as response:
                data = await response.read()
        try:
            data = data.decode('utf-8')
            # 截取JSON字符串，去掉外部的无意义字符串和括号
            json_data = data[data.find("(") + 1:data.rfind(")")]
            # 解析JSON数据并转换为Python对象
            python_data = json.loads(json_data)
            # 访问JSON对象的属性
            pages = python_data["data"]
            for page, pageListDict in pages.items():
                try:
                    for pageDict in pageListDict:
                        try:
                            title = pageDict['title']
                            logo = pageDict['cover']
                            rid = pageDict['roomNum']
                            m3u_dict[f'{source_type},{rid}'] = ''
                            update_dict[f'{source_type},{rid}'] = f'{title},{logo}'
                        except:
                            pass
                except:
                    pass
            if len(update_dict) > 0:
                redisKeyNormal.update(update_dict)
        except Exception as e:
            pass
    except Exception as e:
        print(f"857live An error occurred while processing . Error: {e}")


async def grab_normal_longzhu(session, m3u_dict, mintimeout, maxTimeout, source_type):
    global redisKeyNormal
    m3u8_url = f'https://api.ansongqiubo.com/v3/list/streams/total?pcatId=1&pageIndex=0&dataLength=5000'
    try:
        async with session.get(m3u8_url, headers=bili_header, timeout=mintimeout) as response:
            data = await response.read()
            try:
                dict_urls = json.loads(data.decode('utf-8'))['data']['list']
                redisKeyNormal1 = {key: value for key, value in redisKeyNormal.items() if
                                   not key.startswith('longzhu,')}
                redisKeyNormal.clear()
                redisKeyNormal.update(redisKeyNormal1)
                for dict_item in dict_urls:
                    item = dict_item['item']
                    pic = item['cover']
                    name = item['title']
                    live_dict = dict_item['live']
                    rid = live_dict['roomId']
                    try:
                        source = live_dict['source'][0]
                    except:
                        source = live_dict['source']
                    update_longzhu(source, m3u_dict, rid, source_type, pic, name)
            except Exception as e:
                pass
    except asyncio.TimeoutError:
        async with session.get(m3u8_url, headers=bili_header, timeout=maxTimeout) as response:
            data = await response.read()
            try:
                dict_urls = json.loads(data.decode('utf-8'))['data']['list']
                redisKeyNormal1 = {key: value for key, value in redisKeyNormal.items() if
                                   not key.startswith('longzhu,')}
                redisKeyNormal.clear()
                redisKeyNormal.update(redisKeyNormal1)
                for dict_item in dict_urls:
                    item = dict_item['item']
                    pic = item['cover']
                    name = item['title']
                    live_dict = dict_item['live']
                    rid = live_dict['roomId']
                    try:
                        source = live_dict['source'][0]
                    except:
                        source = live_dict['source']
                    update_longzhu(source, m3u_dict, rid, source_type, pic, name)
            except Exception as e:
                pass
    except Exception as e:
        print(f"longzhu An error occurred while processing {rid}. Error: {e}")


async def grab_normal_chongqin(session, rid, m3u_dict, mintimeout, maxTimeout, source_type):
    try:
        cityId = '5A'
        playId = rid
        relativeId = playId
        type = '1'
        appId = "kdds-chongqingdemo"
        url = 'http://portal.centre.bo.cbnbn.cn/others/common/playUrlNoAuth?cityId=5A&playId=' + playId + '&relativeId=' + relativeId + '&type=1'
        timestamps = round(time.time() * 1000)
        sign = hashlib.md5(
            f"aIErXY1rYjSpjQs7pq2Gp5P8k2W7P^Y@appId{appId}cityId{cityId}playId{playId}relativeId{relativeId}timestamps{timestamps}type{type}".encode(
                'utf-8')).hexdigest()
        headers = {
            "appId": appId,
            "sign": sign,
            "timestamps": str(timestamps),
            "Content-Type": "application/json;charset=utf-8"
        }
        try:
            async with session.get(url, headers=headers, timeout=mintimeout) as response:
                data = await response.json()
                codes = data['data']['result']['protocol'][0]['transcode'][0]['url']
        except asyncio.TimeoutError:
            async with session.get(url, headers=headers, timeout=maxTimeout) as response:
                data = await response.json()
                codes = data['data']['result']['protocol'][0]['transcode'][0]['url']
        if codes is None:
            return
        m3u_dict[f'{source_type},{rid}'] = codes
    except Exception as e:
        print(f"chongqing An error occurred while processing {rid}. Error: {e}")


async def grab4(session, id, m3u_dict, mintimeout, maxTimeout):
    now_uuid = time_clock_update_dict.get('yyId')
    try:
        headers_YY['referer'] = f'https://wap.yy.com/mobileweb/{id}'
        real_lists = []
        real_dict = {}
        arr = []
        room_url = f'https://interface.yy.com/hls/new/get/{id}/{id}/1200?source=wapyy&callback='
        res_text = await fetch_room_url(session, room_url, headers_YY, mintimeout, maxTimeout, now_uuid)
        if not res_text:
            try:
                room_id = await room_id_(session, id, mintimeout, maxTimeout, now_uuid)
            except Exception as e:
                return
            room_url = f'https://interface.yy.com/hls/new/get/{room_id}/{room_id}/1200?source=wapyy&callback='
            res_text = await fetch_room_url(session, room_url, headers_YY, mintimeout, maxTimeout, now_uuid)
        if res_text:
            data = json.loads(res_text[1:-1])
            if data.get('hls', 0):
                xa = data['audio']
                xv = data['video']
                xv = re.sub(r'_0_\d+_0', '_0_0_0', xv)
                url = f'https://interface.yy.com/hls/get/stream/15013/{xv}/15013/{xa}?source=h5player&type=m3u8'
                res_json = await  fetch_real_url(session, url, headers_YY, mintimeout, maxTimeout, now_uuid)
                if not res_json:
                    return
                res_json = json.loads(res_json)
                # 取画质最高的
                if res_json and res_json.get('hls', 0):
                    real_url = res_json['hls']
                    real_lists.append({'hls': real_url})
                    arr.append(f'hls')
            if real_lists:
                tasks = []
                for real_ in real_lists:
                    for key, value in real_.items():
                        task = asyncio.ensure_future(
                            pingM3u(session, value, real_dict, key, mintimeout, maxTimeout, now_uuid, 'yylockuuid'))
                        tasks.append(task)
                await asyncio.gather(*tasks)
                if real_dict:
                    isOne = len(arr) == 1
                    if isOne:
                        for key, value in real_dict.items():
                            if arr[0] == key:
                                # 有效直播源,名字/id
                                m3u_dict[id] = value
                                return
                    else:
                        for i in range(len(arr) - 1):
                            for key, value in real_dict.items():
                                if arr[i] == key:
                                    m3u_dict[id] = value
                                    return
                    return
            return
    except Exception as e:
        print(f"YY An error occurred while processing {id}. Error: {e}")


async def get_room_id_douyin(url, session, mintimeout, maxTimeout, now_uuid):
    headers = {
        'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1',
    }
    url = re.search(r'(https.*)', url).group(1)

    try:
        if not is_same_action_uuid(now_uuid, 'douyinlockuuid'):
            return
        async with  session.get(url, headers=headers, timeout=mintimeout) as response:
            if response.status == 200:
                url = response.headers['location']
                room_id = re.search(r'\d{19}', url).group(0)
    except asyncio.TimeoutError:
        if not is_same_action_uuid(now_uuid, 'douyinlockuuid'):
            return
        async with  session.get(url, headers=headers, timeout=maxTimeout) as response:
            if response.status == 200:
                url = response.headers['location']
                room_id = re.search(r'\d{19}', url).group(0)
            else:
                return None

    headers.update({
        'cookie': '_tea_utm_cache_1128={%22utm_source%22:%22copy%22%2C%22utm_medium%22:%22android%22%2C%22utm_campaign%22:%22client_share%22}',
        'host': 'webcast.amemv.com',
    })
    params = (
        ('type_id', '0'),
        ('live_id', '1'),
        ('room_id', room_id),
        ('app_id', '1128'),
        ('X-Bogus', '1'),
    )

    try:
        if not is_same_action_uuid(now_uuid, 'douyinlockuuid'):
            return
        async with session.get('https://webcast.amemv.com/webcast/room/reflow/info/?', headers=headers,
                               params=params, timeout=mintimeout) as response:
            if response.status == 200:
                json_data = await response.json()
                return json_data['data']['room']['owner']['web_rid']
    except asyncio.TimeoutError:
        if not is_same_action_uuid(now_uuid, 'douyinlockuuid'):
            return
        async with session.get('https://webcast.amemv.com/webcast/room/reflow/info/?', headers=headers,
                               params=params, timeout=maxTimeout) as response:
            if response.status == 200:
                json_data = await response.json()
                return json_data['data']['room']['owner']['web_rid']
            else:
                return None


async def grab_douyin(session, id, m3u_dict, mintimeout, maxTimeout):
    now_uuid = time_clock_update_dict.get('douyinId')
    try:
        if 'v.douyin.com' in id:
            rid = await get_room_id_douyin(id, session, mintimeout, maxTimeout, now_uuid)
            if not rid:
                return
        else:
            rid = id
        url = 'https://live.douyin.com/{}'.format(rid)
        headers = {
            "cookie": "__ac_nonce=0;",
            "referer": "https://live.douyin.com/",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0(WindowsNT10.0;WOW64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/86.0.4240.198Safari/537.36",
        }
        try:
            if not is_same_action_uuid(now_uuid, 'douyinlockuuid'):
                return
            async with  session.get(url, headers=headers,
                                    timeout=mintimeout) as response:
                if response.status == 200:
                    result = await response.text()
        except asyncio.TimeoutError:
            if not is_same_action_uuid(now_uuid, 'douyinlockuuid'):
                return
            async with session.get(url, headers=headers,
                                   timeout=maxTimeout) as response:
                if response.status == 200:
                    result = await response.text()
                else:
                    return None
        text = urllib.parse.unquote(
            re.findall('<script id="RENDER_DATA" type="application/json">(.*?)</script>', result)[0])
        if not text:
            return
        json_ = json.loads(text)

        douyin_list = []
        try:
            flv_pull_url = json_['app']['initialState']['roomStore']['roomInfo']['room']['stream_url']['flv_pull_url']
            douyin_list.append(flv_pull_url)
        except:
            pass

        try:
            hls_pull_url_map = json_['app']['initialState']['roomStore']['roomInfo']['room']['stream_url'][
                'hls_pull_url_map']
            douyin_list.append(hls_pull_url_map)
        except:
            pass
        if len(douyin_list) == 0:
            return
        real_lists = []
        real_dict = {}
        arr = []

        for real_ in douyin_list:
            for name_ in real_:
                if '.flv' in real_[name_]:
                    real_lists.append({f'flv_{name_}': real_[name_]})
                    arr.append(f'flv_{name_}')
                elif '.m3u8' in real_[name_]:
                    real_lists.append({f'm3u8_{name_}': real_[name_]})
                    arr.append(f'm3u8_{name_}')
        if real_lists:
            tasks = []
            for real_ in real_lists:
                for key, value in real_.items():
                    task = asyncio.ensure_future(
                        pingM3u(session, value, real_dict, key, mintimeout, maxTimeout, now_uuid, 'douyinlockuuid'))
                    tasks.append(task)
            await asyncio.gather(*tasks)
            if real_dict:
                for key, value in real_dict.items():
                    if 'FULL_HD' in key:
                        m3u_dict[id] = value
                        return
                isOne = len(arr) == 1
                if isOne:
                    for key, value in real_dict.items():
                        if arr[0] == key:
                            # 有效直播源,名字/id
                            m3u_dict[id] = value
                            return
                else:
                    for i in range(len(arr) - 1):
                        for key, value in real_dict.items():
                            if arr[i] == key:
                                m3u_dict[id] = value
                                return
                return
        return
    except Exception as e:
        print(f"douyin An error occurred while processing {id}. Error: {e}")


async def grab3(session, id, m3u_dict, mintimeout, maxTimeout):
    now_uuid = time_clock_update_dict.get('huyaId')
    try:
        param = {
            'id': id
        }
        real_lists = []
        real_dict = {}
        arr = []
        huya_room_url = 'https://m.huya.com/{}'.format(id)
        try:
            if not is_same_action_uuid(now_uuid, 'huyalockuuid'):
                return
            async with session.get(huya_room_url, headers=cim_headers_huya, params=param,
                                   timeout=mintimeout) as response:
                res = await response.text()
        except asyncio.TimeoutError:
            if not is_same_action_uuid(now_uuid, 'huyalockuuid'):
                return
            async with session.get(huya_room_url, headers=cim_headers_huya, params=param,
                                   timeout=maxTimeout) as response:
                res = await response.text()
        liveLineUrl = re.findall(r'"liveLineUrl":"([\s\S]*?)",', res)[0]
        liveline = base64.b64decode(liveLineUrl).decode('utf-8')
        if liveline:
            if 'replay' in liveline:
                real_lists.append({'直播录像': f'https://{liveline}'})
            else:
                liveline = huya_live(liveline)
                real_url = ("https:" + liveline).replace("hls", "flv").replace("m3u8", "flv").replace(
                    '&ctype=tars_mobile', '')
                rate = [10000, 8000, 4000]
                # rate = [10000, 8000, 4000, 2000, 500]
                arr.append(f'flv_10000')
                arr.append(f'flv_8000')
                arr.append(f'flv_4000')
                # arr.append(f'flv_2000')
                # arr.append(f'flv_500')
                for ratio in range(len(rate) - 1, -1, -1):
                    ratio = rate[ratio]
                    if ratio != 10000:
                        real_url_flv = real_url.replace('.flv?', f'.flv?ratio={ratio}&')
                        name = f'flv_{ratio}'
                        real_lists.append({name: real_url_flv})
                    else:
                        name = f'flv_{ratio}'
                        real_lists.append({name: real_url})
            if real_lists:
                tasks = []
                for real_ in real_lists:
                    for key, value in real_.items():
                        task = asyncio.ensure_future(
                            pingM3u(session, value, real_dict, key, mintimeout, maxTimeout, now_uuid, 'huyalockuuid'))
                        tasks.append(task)
                await asyncio.gather(*tasks)
                if real_dict:
                    isOne = len(arr) == 1
                    if isOne:
                        for key, value in real_dict.items():
                            if arr[0] == key:
                                # 有效直播源,名字/id
                                m3u_dict[id] = value
                                return
                    else:
                        for i in range(len(arr) - 1):
                            for key, value in real_dict.items():
                                if arr[i] == key:
                                    m3u_dict[id] = value
                                    return
                    return
            return
    except Exception as e:
        print(f"huya An error occurred while processing {id}. Error: {e}")


async def download_files4():
    global redisKeyYoutube
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    global time_clock_update_dict
    nowId = time_clock_update_dict.get('youtubeId')
    m3u_dict = {}
    async with aiohttp.ClientSession() as session:
        await grab(session, nowId, m3u_dict, mintimeout, maxTimeout)
    return m3u_dict


async def get_resolution(session, liveurl, mintimeout, maxTimeout, now_uuid, uuid_cache):
    try:
        if not is_same_action_uuid(now_uuid, uuid_cache):
            return
        async with session.get(liveurl, headers=bili_header, timeout=mintimeout * 2) as response:
            playlist_text = await response.text()
    except asyncio.TimeoutError:
        if not is_same_action_uuid(now_uuid, uuid_cache):
            return
        async with session.get(liveurl, headers=bili_header, timeout=maxTimeout * 2) as response:
            playlist_text = await response.text()
    playlist = m3u8.loads(playlist_text)
    playlists = playlist.playlists
    if len(playlists) < 1:
        return None
    highest_resolution = 0
    url = ''
    for item in playlists:
        resolution = item.stream_info.resolution[0] * item.stream_info.resolution[1]
        if resolution > highest_resolution:
            highest_resolution = resolution
            url = item.uri
    return url


async def grab(session, id, m3u_dict, mintimeout, maxTimeout):
    now_uuid = time_clock_update_dict.get('youtubeId')
    youtubeUrl = 'https://www.youtube.com/watch?v='
    try:
        url = youtubeUrl + id
        try:
            if not is_same_action_uuid(now_uuid, 'youtubelockuuid'):
                return
            async with session.get(url, headers=bili_header, timeout=mintimeout * 2) as response:
                content = await response.text()
                if '.m3u8' not in content:
                    async with session.get(url, headers=bili_header, timeout=maxTimeout * 2) as response2:
                        content = await response2.text()
                        if '.m3u8' not in content:
                            return
        except asyncio.TimeoutError:
            if not is_same_action_uuid(now_uuid, 'youtubelockuuid'):
                return
            async with session.get(url, headers=bili_header, timeout=maxTimeout * 2) as response:
                content = await response.text()
                if '.m3u8' not in content:
                    return
        end = content.find('.m3u8') + 5
        tuner = 100
        highest_quality_link = None
        while True:
            if 'https://' in content[end - tuner: end]:
                link = content[end - tuner: end]
                start = link.find('https://')
                end = link.find('.m3u8') + 5
                match = await get_resolution(session, link[start: end], mintimeout, maxTimeout, now_uuid,
                                             'youtubelockuuid')
                if match:
                    highest_quality_link = match
                break
            else:
                tuner += 5
        if highest_quality_link:
            m3u_dict[id] = highest_quality_link
        else:
            m3u_dict[id] = link[start: end]
    except Exception as e:
        print(f"youtube An error occurred while processing {id}. Error: {e}")


def chaoronghe25():
    try:
        global redisKeyBilili
        ids = redisKeyBilili.keys()
        m3u_dict = {}
        for id in ids:
            m3u_dict[id] = ''
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        redisKeyBililiM3uFake = {}
        # fakeurl = f'http://127.0.0.1:22771/bilibili/'
        fakeurl = f"http://{ip}:{port_live}/bilibili/"
        for id, url in m3u_dict.items():
            try:
                name = redisKeyBilili[id]
                link = f'#EXTINF:-1 group-title="哔哩哔哩"  tvg-name="{name}",{name}\n'
                redisKeyBililiM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyBililiM3uFake, f"{secret_path}bilibili.m3u", 10)
        fuck_m3u_to_txt(f"{secret_path}bilibili.m3u", f"{secret_path}bilibili.txt")
        return "result"
    except Exception as e:
        return "empty"


def chaoronghe26():
    try:
        global redisKeyHuya
        ids = redisKeyHuya.keys()
        m3u_dict = {}
        for id in ids:
            m3u_dict[id] = ''
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        redisKeyHuyaM3uFake = {}
        # fakeurl = 'http://127.0.0.1:22771/huya/'
        fakeurl = f"http://{ip}:{port_live}/huya/"
        for id, url in m3u_dict.items():
            try:
                name = redisKeyHuya[id]
                link = f'#EXTINF:-1 group-title="虎牙"  tvg-name="{name}",{name}\n'
                redisKeyHuyaM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyHuyaM3uFake, f"{secret_path}huya.m3u", 10)
        fuck_m3u_to_txt(f"{secret_path}huya.m3u", f"{secret_path}huya.txt")
        return "result"
    except Exception as e:
        return "empty"


def chaoronghe27():
    try:
        global redisKeyYY
        ids = redisKeyYY.keys()
        m3u_dict = {}
        for id in ids:
            m3u_dict[id] = ''
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        redisKeyYYM3uFake = {}
        # fakeurl='http://127.0.0.1:22771/YY/'
        fakeurl = f"http://{ip}:{port_live}/YY/"
        for id, url in m3u_dict.items():
            try:
                name = redisKeyYY[id]
                link = f'#EXTINF:-1 group-title="YY"  tvg-name="{name}",{name}\n'
                redisKeyYYM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyYYM3uFake, f"{secret_path}YY.m3u", 10)
        fuck_m3u_to_txt(f"{secret_path}YY.m3u", f"{secret_path}YY.txt")
        return "result"
    except Exception as e:
        return "empty"


def chaoronghe29():
    try:
        global redisKeyDOUYIN
        ids = redisKeyDOUYIN.keys()
        m3u_dict = {}
        for id in ids:
            m3u_dict[id] = ''
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        redisKeyDOUYINM3uFake = {}
        fakeurl = f"http://{ip}:{port_live}/DOUYIN/"
        # fakeurl = f"http://127.0.0.1:22771/DOUYIN/"
        for id, url in m3u_dict.items():
            try:
                name = redisKeyDOUYIN[id]
                link = f'#EXTINF:-1 group-title="抖音"  tvg-name="{name}",{name}\n'
                redisKeyDOUYINM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyDOUYINM3uFake, f"{secret_path}Douyin.m3u", 10)
        fuck_m3u_to_txt(f"{secret_path}Douyin.m3u", f"{secret_path}Douyin.txt")
        return "result"
    except Exception as e:
        return "empty"


def safe_del_alist_m3u8():
    # 新的切片产生，删除全部其他切片
    if os.path.exists(SLICES_ALIST_M3U8):
        # 目录下全部文件
        removePaths = os.listdir(SLICES_ALIST_M3U8)
        for filename in removePaths:
            removePath = os.path.join(SLICES_ALIST_M3U8, filename)
            try:
                os.remove(removePath)
            except Exception as e:
                pass


def chaoronghe30():
    try:
        global redisKeyAlist
        if len(redisKeyAlist) == 0:
            return "empty"
        global redisKeyAlistM3u
        global redisKeyAlistM3uTsPath
        redisKeyAlistM3uTsPath.clear()
        redisKeyAlistM3u.clear()
        try:
            redis_del_map(REDIS_KEY_Alist_M3U)
            redis_del_map(REDIS_KEY_Alist_M3U_TS_PATH)
        except:
            pass
        safe_del_alist_m3u8()
        ip = init_IP()
        fakeurl = f"http://{ip}:{port_live}/alist/"
        # fakeurl = f"http://127.0.0.1:5000/alist/"
        pathxxx = f"{secret_path}alist.m3u"
        thread2 = threading.Thread(target=check_alist_file,
                                   args=(redisKeyAlist, fakeurl, pathxxx))
        thread2.start()
        return "result"
    except Exception as e:
        return "empty"


def check_alist_file(alist_url_dict, fakeurl, pathxxx):
    asyncio.run(sluty_alist_hunter(alist_url_dict, fakeurl, pathxxx))


# 分割alist路径获取alist主站和path参数,path参数为空字符串说明url就是主站
def get_site_and_path(url):
    parsed_url = urlparse(url)
    domain = parsed_url.scheme + '://' + parsed_url.netloc
    path = parsed_url.path
    if not path or path == '':
        path = None
    return domain, path


async def sluty_alist_hunter(alist_url_dict, fakeurl, pathxxx):
    if os.path.exists(pathxxx):
        os.remove(pathxxx)
    # 获取路径下的文件和文件夹列表数据
    api_part = 'api/fs/list'
    # 可以解析出alist网站隐藏的基础路径
    api_me_base_path = 'api/me'
    async with aiohttp.ClientSession() as session:
        for site, password in alist_url_dict.items():
            all_filename_groupname = {}
            # 需要迭代访问的路径
            future_path_set = set()
            site, startPath = get_site_and_path(site)
            if not site.endswith('/'):
                site += '/'
            base_path_url = site + api_me_base_path
            async with  session.get(base_path_url) as response:
                json_data = await response.json()
                base_path = json_data['data']['base_path']
            full_url = site + api_part
            await getPathBase(site, full_url, startPath, future_path_set, session, fakeurl, pathxxx,
                              base_path, password, all_filename_groupname)

            async def process_path(pathbase):
                await getPathBase(site, full_url, pathbase, future_path_set, session, fakeurl,
                                  pathxxx, base_path, password, all_filename_groupname
                                  )

            while len(future_path_set) > 0:
                tasks = [process_path(pathbase) for pathbase in future_path_set]
                future_path_set.clear()
                await asyncio.gather(*tasks)


# target_file_name  和文件夹同名的文件
def has_found_target(content, target_file_name):
    for item in content:
        # 名字
        name = item['name']
        # false-不是文件夹 true-是文件夹
        is_dir = item['is_dir']
        # 是文件夹，计算下一级目录，等待再次访问
        # 签名
        sign = item['sign']
        if not is_dir:
            if name.startswith(target_file_name):
                if name == target_file_name:
                    return sign
                arr = name.split(target_file_name)[1]
                if not arr.startswith('_'):
                    return name, sign
    return None


def check_alist_fie_repeat(uuid_name, all_filename_groupname):
    for name in all_filename_groupname.keys():
        if name.startswith(uuid_name):
            return True
        if uuid_name.startswith(name):
            return True
    return False


# url-基础请求列表API地址(alist网站/alist/api/fs/list)
# path-迭代查询路径
# file_url_dict 已经捕获到的文件(只存储视频文件)
# 新的路径
async def getPathBase(site, full_url, path, future_path_set, session, fakeurl, pathxxx,
                      base_path, password, all_filename_groupname):
    global redisKeyAlistM3u
    global redisKeyAlistM3uTsPath
    if path:
        if not path.startswith('/'):
            path = '/' + path
        if path.endswith('/'):
            path = path[:-1]
        url = f'{full_url}?path={path}'
    else:
        url = full_url
    try:
        async with  session.get(url) as response:
            json_data = await response.json()
            if not json_data:
                return
            content = json_data['data']['content']
            for item in content:
                # 名字
                name = item['name']
                # 是文件夹，计算下一级目录，等待再次访问
                # 签名
                sign = item['sign']
                if name.endswith('.zip'):
                    if base_path != '/':
                        # 下载菜单文件需要的路径，此时的name其实是文件夹和菜单名字相同的
                        future_path = f'{site}d{base_path}{path}/{name}'
                    else:
                        future_path = f'{site}d{path}/{name}'
                    encoded_url = urllib.parse.quote(future_path, safe=':/')
                    if sign and sign != '':
                        encoded_url = f'{encoded_url}?sign={sign}'
                        filename_groupname = await get_zip_data(encoded_url, password, fakeurl, session)
                        if filename_groupname:
                            all_filename_groupname.update(filename_groupname)
                            for filename in filename_groupname.keys():
                                dict = filename_groupname[filename]
                                groupname = dict['groupname']
                                uuid_name = dict['uuid_name']
                                ts_uuid = dict['ts_uuid']
                                same_level_path = f'{path}/{ts_uuid}'
                                link = f'#EXTINF:-1 group-title={groupname}  tvg-name="{filename}",{filename}\n'
                                # uuid(视频序号),uuid下子目录url，结合这个可以逆推与之同一个目录的加密ts文件的url，主要检查是否有签名,由于数量巨大不予以存储
                                if base_path != '/':
                                    # 不完整ts路径，拼接上具体ts文件名就是完整的
                                    future_path_ts = f'{site}d{base_path}{path}/{ts_uuid}'
                                else:
                                    future_path_ts = f'{site}d{path}/{ts_uuid}'
                                uuid_same_level_path_url = f'{full_url}?path={same_level_path}'
                                redisKeyAlistM3u[ts_uuid] = uuid_same_level_path_url
                                redis_add_map(REDIS_KEY_Alist_M3U, {ts_uuid: uuid_same_level_path_url})
                                redisKeyAlistM3uTsPath[ts_uuid] = future_path_ts
                                redis_add_map(REDIS_KEY_Alist_M3U_TS_PATH, {ts_uuid: future_path_ts})
                                # 虚假IP+端口+唯一uuid(文件夹名字)
                                fake_m3u8 = f'{fakeurl}{uuid_name}.m3u8'
                                async with aiofiles.open(pathxxx, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
                                    await f.write(f'{link}{fake_m3u8}\n')
            for item in content:
                # 名字
                name = item['name']
                # false-不是文件夹 true-是文件夹
                is_dir = item['is_dir']
                # 是文件夹，计算下一级目录，等待再次访问
                # 签名
                sign = item['sign']
                if is_dir:
                    same_name_file, same_name_file_sign = has_found_target(content, name)
                    # 同级目录下找到了目标文件，不再向下检查
                    if same_name_file:
                        if path:
                            # 这是切片文件需要的路径，已经找到了菜单文件，不再寻找菜单目录下的内容，直接记录菜单目录，但是现在是菜单目录的父亲目录
                            same_level_path = f'{path}/{name}'
                            if base_path != '/':
                                # 下载菜单文件需要的路径，此时的name其实是文件夹和菜单名字相同的
                                future_path = f'{site}d{base_path}{path}/{same_name_file}'
                                # 不完整ts路径，拼接上具体ts文件名就是完整的
                                future_path_ts = f'{site}d{base_path}{path}/{name}'
                            else:
                                future_path = f'{site}d{path}/{same_name_file}'
                                future_path_ts = f'{site}d{path}/{name}'
                        else:
                            same_level_path = f'/{name}'
                            if base_path != '/':
                                future_path = f'{site}d{base_path}/{same_name_file}'
                                future_path_ts = f'{site}d{base_path}/{name}'
                            else:
                                future_path = f'{site}d/{same_name_file}'
                                future_path_ts = f'{site}d/{name}'
                        encoded_url = urllib.parse.quote(future_path, safe=':/')
                        if same_name_file_sign and same_name_file_sign != '':
                            encoded_url = f'{encoded_url}?sign={same_name_file_sign}'
                        uuid_name = name
                        try:
                            if check_alist_fie_repeat(uuid_name, all_filename_groupname):
                                tvg_name, groupname = await get_alist_uuid_file_data(encoded_url, password,
                                                                                     uuid_name,
                                                                                     fakeurl, session)
                        except Exception as e:
                            pass
                        if tvg_name:
                            if groupname and groupname != '':
                                groupname = groupname
                            else:
                                groupname = 'alist'
                            link = f'#EXTINF:-1 group-title={groupname}  tvg-name="{tvg_name}",{tvg_name}\n'
                            # uuid(视频序号),uuid下子目录url，结合这个可以逆推与之同一个目录的加密ts文件的url，主要检查是否有签名,由于数量巨大不予以存储
                            uuid_same_level_path_url = f'{full_url}?path={same_level_path}'
                            redisKeyAlistM3u[uuid_name] = uuid_same_level_path_url
                            redis_add_map(REDIS_KEY_Alist_M3U, {uuid_name: uuid_same_level_path_url})
                            redisKeyAlistM3uTsPath[uuid_name] = future_path_ts
                            redis_add_map(REDIS_KEY_Alist_M3U_TS_PATH, {uuid_name: future_path_ts})
                            # 虚假IP+端口+唯一uuid(文件夹名字)
                            fake_m3u8 = f'{fakeurl}{uuid_name}.m3u8'
                            async with aiofiles.open(pathxxx, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
                                await f.write(f'{link}{fake_m3u8}\n')
                    else:
                        # 设置接下来要检测的路径，但是如果在这一层路径找到想要的东西就pass
                        if path:
                            future_path_set.add(f'{path}/{name}')
                        else:
                            future_path_set.add(f'/{name}')
                else:
                    # 假定是加密m3u8文件
                    if url.endswith(name):
                        if path:
                            same_level_path = f'{path}'
                            if base_path != '/':
                                future_path = f'{site}d{base_path}{path}/{name}'
                                # 不完整ts路径，拼接上具体ts文件名就是完整的
                                future_path_ts = f'{site}d{base_path}{path}'
                            else:
                                future_path = f'{site}d{path}/{name}'
                                future_path_ts = f'{site}d{path}'
                        else:
                            same_level_path = f'/'
                            if base_path != '/':
                                future_path = f'{site}d{base_path}/{name}'
                                future_path_ts = f'{site}d{base_path}'
                            else:
                                future_path = f'{site}d/{name}'
                                future_path_ts = f'{site}d'
                        encoded_url = urllib.parse.quote(future_path, safe=':/')
                        if sign and sign != '':
                            encoded_url = f'{encoded_url}?sign={sign}'
                        uuid_name = name
                        try:
                            if check_alist_fie_repeat(uuid_name, all_filename_groupname):
                                tvg_name, groupname = await get_alist_uuid_file_data(encoded_url, password,
                                                                                     uuid_name,
                                                                                     fakeurl, session)
                        except Exception as e:
                            pass
                        if tvg_name:
                            if groupname and groupname != '':
                                groupname = groupname
                            else:
                                groupname = 'alist'
                            link = f'#EXTINF:-1 group-title={groupname}  tvg-name="{tvg_name}",{tvg_name}\n'
                            # uuid(视频序号),uuid下子目录url，结合这个可以逆推与之同一个目录的加密ts文件的url，主要检查是否有签名,由于数量巨大不予以存储
                            uuid_same_level_path_url = f'{full_url}?path={same_level_path}'
                            redisKeyAlistM3u[uuid_name] = uuid_same_level_path_url
                            redis_add_map(REDIS_KEY_Alist_M3U, {uuid_name: uuid_same_level_path_url})
                            redisKeyAlistM3uTsPath[uuid_name] = future_path_ts
                            redis_add_map(REDIS_KEY_Alist_M3U_TS_PATH, {uuid_name: future_path_ts})
                            # 虚假IP+端口+唯一uuid(文件夹名字)
                            fake_m3u8 = f'{fakeurl}{uuid_name}.m3u8'
                            async with aiofiles.open(pathxxx, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
                                await f.write(f'{link}{fake_m3u8}\n')
    except Exception as e:
        pass


def get_password(url):
    site, startPath = get_site_and_path(url)
    for key, password in redisKeyAlist.items():
        if key.startswith(site):
            return password
    return None


past_list_item = []
past_alist_ts_uuid = {'uuid': ''}


def get_content_by_uuid(uuid):
    old_uuid = past_alist_ts_uuid.get('uuid')
    if uuid == old_uuid:
        if len(past_list_item) > 0:
            return past_list_item
    return None


update_lock = threading.Lock()


def get_new_content_by_uuid(mintimeout, maxTimeout, same_level_path, uuid, headers):
    global past_list_item
    with update_lock:
        content_list = get_content_by_uuid(uuid)
        if content_list:
            return content_list
        try:
            response = requests.get(same_level_path, headers=headers, timeout=mintimeout, verify=False)
        except requests.exceptions.Timeout:
            # 处理请求超时异常
            response = requests.get(same_level_path, headers=headers, timeout=maxTimeout, verify=False)
        if response.status_code == 200:
            json_data = response.json()
            content = json_data['data']['content']
            past_list_item.clear()
            past_list_item = content.copy()
            past_alist_ts_uuid['uuid'] = uuid
            return content
        return None


# 获取加密ts文件的真实下载url   uuid_ts-加密ts文件名字
# same_level_path 加密m3u8文件路径,来源于redisKeyAlistM3u[uuid_name],ts_uuid_secret_name，来源于m3u8文件 加密ts文件名字，根据此二项获取真实有效的加密ts文件文件内容
def get_true_alist_ts_url(ts_uuid_secret_name):
    global redisKeyAlistM3u
    global redisKeyAlistM3uTsPath
    global redisKeyAlist
    global past_list_item
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    uuid = ts_uuid_secret_name.split('_')[0]
    # 绕过一些网站对下载工具的限制或检测
    user_agent = '-user_agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\"'
    headers = {'User-Agent': user_agent}
    content_list = get_content_by_uuid(uuid)
    same_level_path = redisKeyAlistM3u.get(uuid)
    if not same_level_path:
        return None
    if not content_list:
        content_list = get_new_content_by_uuid(mintimeout, maxTimeout, same_level_path, uuid, headers)
    if not content_list:
        return None
    for item in content_list:
        # 名字
        name = item['name']
        if ts_uuid_secret_name != name:
            continue
        # 签名
        sign = item['sign']
    future_path_ts = f'{redisKeyAlistM3uTsPath.get(uuid)}/{ts_uuid_secret_name}'
    encoded_url = urllib.parse.quote(future_path_ts, safe=':/')
    if sign and sign != '':
        encoded_url = f'{encoded_url}?sign={sign}'
    else:
        encoded_url = f'{encoded_url}?sign='''
    try:
        content = download_file(encoded_url, headers, mintimeout, 1024 * 64)
    except requests.exceptions.Timeout:
        content = download_file(encoded_url, headers, mintimeout, 1024 * 64)
        # 处理请求超时异常
    except requests.exceptions.HTTPError as e:
        # 签名异常，重新刷新content数据
        if e.response.status_code == 401:
            content_list = get_new_content_by_uuid(mintimeout, maxTimeout, same_level_path, uuid, headers)
            for item in content_list:
                # 名字
                name = item['name']
                if ts_uuid_secret_name != name:
                    continue
                # 签名
                sign = item['sign']
            future_path_ts = f'{redisKeyAlistM3uTsPath.get(uuid)}/{ts_uuid_secret_name}'
            encoded_url = urllib.parse.quote(future_path_ts, safe=':/')
            if sign and sign != '':
                encoded_url = f'{encoded_url}?sign={sign}'
            else:
                encoded_url = f'{encoded_url}?sign='''
            try:
                content = download_file(encoded_url, headers, mintimeout, 1024 * 64)
            except requests.exceptions.Timeout:
                content = download_file(encoded_url, headers, mintimeout, 1024 * 64)
            except Exception as e:
                return None
    if content:
        password = get_password(same_level_path)
        if not password:
            return None
        # 已经解密的高度加密的m3u8文件(只有uuid，没有格式)，bytes
        blankContent_alist_uuid_m3u8 = decrypt(password, content)
        return blankContent_alist_uuid_m3u8
    return None


def download_file(url, headers, timeout, size):
    response = requests.get(url, headers=headers, timeout=timeout, stream=True)
    bytes_data = b''
    for chunk in response.iter_content(chunk_size=size):
        if chunk:
            bytes_data += chunk
    return bytes_data


async def get_zip_data(zip_url, password, fakeurl, session):
    filename_groupname = {}
    user_agent = '-user_agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\"'
    headers = {'User-Agent': user_agent}
    count = 0
    while count < 20:
        try:
            async with  session.get(zip_url, headers=headers,
                                    timeout=30) as response:
                content = await response.read()
        except asyncio.TimeoutError:
            async with  session.get(zip_url, headers=headers,
                                    timeout=60) as response:
                content = await response.read()
        if content and len(content) > 0:
            break
        count += 1
    if content:
        with zipfile.ZipFile(io.BytesIO(content), 'r') as zip_ref:
            zip_ref.extractall(SLICES_ALIST_M3U8)
            extracted_files = zip_ref.namelist()
        # 输出解压缩后的文件名
        for file_name in extracted_files:
            secret_file_path = os.path.join(SLICES_ALIST_M3U8, file_name)
            count = 0
            while count < 3:
                try:
                    async with aiofiles.open(secret_file_path, 'rb') as f:
                        bytes = await f.read()  # 异步读取文件内容
                        if bytes:
                            break
                except:
                    count += 1
            if bytes:
                try:
                    # 已经解密的高度加密的m3u8文件(只有uuid，没有格式)，bytes
                    blankContent_alist_uuid_m3u8 = decrypt(password, bytes)
                except Exception as e:
                    blankContent_alist_uuid_m3u8 = None
                if blankContent_alist_uuid_m3u8:
                    bytes_array = blankContent_alist_uuid_m3u8.splitlines()
                    fix_m3u8_data = b''
                    encode_uuid = file_name.encode()
                    fakeurl_encode = fakeurl.encode()
                    filename = ''
                    groupname = ''
                    ts_uuid = ''
                    for line in bytes_array:
                        preline = line.split(b'_')[0]
                        if not preline.startswith(encode_uuid) and not encode_uuid.startswith(preline):
                            if line.startswith(b"#my_video_true_name_is="):
                                filename = line.split(b"#my_video_true_name_is=")[1].decode()
                            elif line.startswith(b"#my_video_group_name_is="):
                                groupname = line.split(b"#my_video_group_name_is=")[1].decode()
                            else:
                                fix_m3u8_data += line
                                fix_m3u8_data += b'\n'
                        else:
                            if preline == b'':
                                continue
                            ts_uuid = preline.decode()
                            fix_m3u8_data += fakeurl_encode
                            fix_m3u8_data += line
                            fix_m3u8_data += b'.ts\n'
                    if len(fix_m3u8_data) > 0:
                        # 把解密的m3u8文件落地保存，这样子就不需要定时器拉取m3u8列表文件
                        thread_write_bytes_to_file(f"{SLICES_ALIST_M3U8}/{ts_uuid}.m3u8", fix_m3u8_data)
                        filename_groupname[filename] = {'groupname': groupname, 'uuid_name': ts_uuid,
                                                        'ts_uuid': ts_uuid}
                        os.remove(secret_file_path)
    return filename_groupname


# 下载解密全部特殊加密直播文件
async def get_alist_uuid_file_data(secret_uuid_m3u8_file_url, password, uuid_name, fakeurl, session):
    user_agent = '-user_agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\"'
    headers = {'User-Agent': user_agent}
    count = 0
    while count < 3:
        try:
            async with  session.get(secret_uuid_m3u8_file_url, headers=headers,
                                    timeout=30) as response:
                content = await response.read()
        except asyncio.TimeoutError:
            async with  session.get(secret_uuid_m3u8_file_url, headers=headers,
                                    timeout=60) as response:
                content = await response.read()
        if content and len(content) > 0:
            break
        count += 1
    if content:
        # 已经解密的高度加密的m3u8文件(只有uuid，没有格式)，bytes
        blankContent_alist_uuid_m3u8 = decrypt(password, content)
    else:
        return None
    bytes_array = blankContent_alist_uuid_m3u8.splitlines()
    fix_m3u8_data = b''
    encode_uuid = uuid_name.encode()
    fakeurl_encode = fakeurl.encode()
    filename = ''
    groupname = ''
    for line in bytes_array:
        if not line.startswith(encode_uuid):
            if line.startswith(b"#my_video_true_name_is="):
                filename = line.split(b"#my_video_true_name_is=")[1].decode()
            elif line.startswith(b"#my_video_group_name_is="):
                groupname = line.split(b"#my_video_group_name_is=")[1].decode()
            else:
                fix_m3u8_data += line
                fix_m3u8_data += b'\n'
        else:
            fix_m3u8_data += fakeurl_encode
            fix_m3u8_data += line
            fix_m3u8_data += b'.ts\n'
    # 把解密的m3u8文件落地保存，这样子就不需要定时器拉取m3u8列表文件
    thread_write_bytes_to_file(f"{SLICES_ALIST_M3U8}/{uuid_name}.m3u8", fix_m3u8_data)
    if filename != '':
        return filename, groupname
    return None


headers_default = {'Content-type': 'application/vnd.apple.mpegurl',
                   'Expect': '100-continue',
                   'Connection': 'Keep-Alive',
                   'Cache-Control': 'no-cache'
                   }
headers_default2 = {'Content-type': 'application/vnd.apple.mpegurl',
                    'Expect': '100-continue',
                    'Connection': 'Keep-Alive',
                    }


# headers_default = {'Content-Type': 'application/vnd.apple.mpegurl'
#                    }


def chaoronghe28():
    try:
        global redisKeyTWITCH
        ids = redisKeyTWITCH.keys()
        m3u_dict = {}
        for id in ids:
            m3u_dict[id] = ''
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        redisKeyTWITCHM3uFake = {}
        # fakeurl = f"http://127.0.0.1:22771/TWITCH/"
        fakeurl = f"http://{ip}:{port_live}/TWITCH/"
        for id, url in m3u_dict.items():
            try:
                name = redisKeyTWITCH[id]
                link = f'#EXTINF:-1 group-title="Twitch"  tvg-name="{name}",{name}\n'
                redisKeyTWITCHM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyTWITCHM3uFake, f"{secret_path}TWITCH.m3u", 10)
        fuck_m3u_to_txt(f"{secret_path}TWITCH.m3u", f"{secret_path}TWITCH.txt")
        return "result"
    except Exception as e:
        return "empty"


def map_remove_keys(map, keys):
    if not keys:
        return
    for k in keys:
        map.pop(k, None)


def update_by_type_normal(type):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if type == 'qiumihui,':
        # 有效直播源,名字/id
        m3u_dict = loop.run_until_complete(download_files_normal_single_qiumihui())
    elif type == 'longzhu,':
        # 有效直播源,名字/id
        m3u_dict = loop.run_until_complete(download_files_normal_single_longzhu())
    elif type == '857,':
        # 有效直播源,名字/id
        m3u_dict = loop.run_until_complete(download_files_normal_single_857())
    return m3u_dict


async def download_files_normal_single_qiumihui():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = {}
    async with aiohttp.ClientSession() as session:
        try:
            await deal_qiumihui(session, m3u_dict, mintimeout, maxTimeout)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"qiumihui Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files_normal_single_longzhu():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = {}
    async with aiohttp.ClientSession() as session:
        try:
            await  grab_normal_longzhu(session, m3u_dict, mintimeout, maxTimeout, 'longzhu')
        except Exception as e:
            print(f"longzhu Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files_normal_single_857():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = {}
    async with aiohttp.ClientSession() as session:
        try:
            await  grab_normal_857(session, m3u_dict, mintimeout, maxTimeout, '857')
        except Exception as e:
            print(f"857 Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files_normal_single_migu():
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = {}
    global time_clock_update_dict
    nowId = time_clock_update_dict.get('miguId')
    source_type, rid, channel_id, media_id = nowId.split(',')
    async with aiohttp.ClientSession() as session:
        try:
            await   grab_normal_migu(session, rid, m3u_dict, mintimeout, maxTimeout, 'migu', [channel_id, media_id])
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"migu Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files_normal_single_cq():
    global redisKeyNormal
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = {}
    global time_clock_update_dict
    nowId = time_clock_update_dict.get('cqId')
    source_type, rid = nowId.split(',')
    async with aiohttp.ClientSession() as session:
        try:
            await grab_normal_chongqin(session, rid, m3u_dict, mintimeout, maxTimeout, 'cq')
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"normal Failed to fetch files. Error: {e}")
    return m3u_dict


def chaoronghe31_single(type):
    try:
        global redisKeyNormalM3U
        global redisKeyNormal
        removeKeys = []
        for key in redisKeyNormalM3U.keys():
            if key.startswith(type):
                removeKeys.append(key)
        map_remove_keys(redisKeyNormalM3U, removeKeys)
        redis_del_map_keys(REDIS_KEY_NORMAL_M3U, removeKeys)
        removeredisKeyNormalKeys = []
        for key in redisKeyNormal.keys():
            if key.startswith(type):
                if type != 'migu,' and type != 'cq,' and type != 'hkdtmb,':
                    removeredisKeyNormalKeys.append(key)
        map_remove_keys(redisKeyNormal, removeredisKeyNormalKeys)
        redis_del_map_keys(REDIS_KEY_NORMAL, removeredisKeyNormalKeys)
        m3u_dict = update_by_type_normal(type)
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        redisKeyM3uFake = {}
        # fakeurl = f"http://127.0.0.1:22771/normal/"
        fakeurl = f"http://{ip}:{port_live}/normal/"
        for id, name in redisKeyNormal.items():
            if not id.startswith('hkdtmb,'):
                continue
            try:
                name, logo = name.split(',')
            except Exception as e:
                logo = None
            if logo is None:
                link = f'#EXTINF:-1 group-title="香港地面波"  tvg-name="{name}",{name}\n'
            else:
                link = f'#EXTINF:-1 group-title="香港地面波" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
            redisKeyM3uFake[f'{fakeurl}{id}.m3u8'] = link
        for id, url in redisKeyNormalM3U.items():
            try:
                if id in m3u_dict.keys():
                    continue
                name = redisKeyNormal[id]
                try:
                    name, logo = name.split(',')
                except Exception as e:
                    logo = None
                if id.startswith('cq,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="国内源"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="国内源" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('migu,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="国内源2"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="国内源2" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('qiumihui,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播1"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播1" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('ipanda,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="iPanda熊猫频道"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="iPanda熊猫频道" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('longzhu,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播2"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播2" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('857,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播3"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播3" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('hkdtmb,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="香港地面波"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="香港地面波" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('skylinewebcams,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="世界遗迹"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="世界遗迹" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                else:
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="国内"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="国内" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                redisKeyM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except Exception as e:
                pass
        for id, url in m3u_dict.items():
            try:
                redisKeyNormalM3U[id] = url
                name = redisKeyNormal[id]
                try:
                    name, logo = name.split(',')
                except Exception as e:
                    logo = None
                link = None
                if id.startswith('qiumihui,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播1"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播1" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('longzhu,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播2"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播2" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('857,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播3"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播3" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('migu,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="国内源2"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="国内源2" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('cq,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="国内源"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="国内源" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('skylinewebcams,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="世界遗迹"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="世界遗迹" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                if link:
                    redisKeyM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except Exception as e:
                pass
        add_update_live('qiumihui,', '体育直播1', '更新体育直播1', redisKeyM3uFake, fakeurl)
        add_update_live('longzhu,', '体育直播2', '更新体育直播2', redisKeyM3uFake, fakeurl)
        add_update_live('857,', '体育直播3', '更新体育直播3', redisKeyM3uFake, fakeurl)
        # 同步方法写出全部配置
        distribute_data(redisKeyM3uFake, f"{secret_path}normal.m3u", 10)
        fuck_m3u_to_txt(f"{secret_path}normal.m3u", f"{secret_path}normal.txt")
        chaoronghe()
        update_clock('normalM3uClock')
        return "result"
    except Exception as e:
        return "empty"


def chaoronghe31():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # 有效直播源,名字/id
        m3u_dict = loop.run_until_complete(download_files_normal_single())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        global redisKeyNormalM3U
        global redisKeyNormal
        redisKeyM3uFake = {}
        redisKeyNormalM3U.clear()
        redis_del_map(REDIS_KEY_NORMAL_M3U)
        fakeurl = f"http://{ip}:{port_live}/normal/"
        # fakeurl = f"http://127.0.0.1:5000/normal/"
        for id, name in redisKeyNormal.items():
            if not id.startswith('hkdtmb,'):
                continue
            try:
                name, logo = name.split(',')
            except Exception as e:
                logo = None
            if logo is None:
                link = f'#EXTINF:-1 group-title="香港地面波"  tvg-name="{name}",{name}\n'
            else:
                link = f'#EXTINF:-1 group-title="香港地面波" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
            redisKeyM3uFake[f'{fakeurl}{id}.m3u8'] = link
        for id, url in m3u_dict.items():
            try:
                redisKeyNormalM3U[id] = url
                name = redisKeyNormal[id]
                try:
                    name, logo = name.split(',')
                except Exception as e:
                    logo = None
                if id.startswith('cq,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="国内源"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="国内源" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('migu,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="国内源2"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="国内源2" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('qiumihui,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播1"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播1" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('ipanda,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="iPanda熊猫频道"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="iPanda熊猫频道" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('longzhu,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播2"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播2" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('857,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="体育直播3"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="体育直播3" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                elif id.startswith('skylinewebcams,'):
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="世界遗迹"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="世界遗迹" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                else:
                    if logo is None:
                        link = f'#EXTINF:-1 group-title="国内"  tvg-name="{name}",{name}\n'
                    else:
                        link = f'#EXTINF:-1 group-title="国内" tvg-logo="{logo}"  tvg-name="{name}",{name}\n'
                redisKeyM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except Exception as e:
                pass
        add_update_live('qiumihui,', '体育直播1', '更新体育直播1', redisKeyM3uFake, fakeurl)
        add_update_live('longzhu,', '体育直播2', '更新体育直播2', redisKeyM3uFake, fakeurl)
        add_update_live('857,', '体育直播3', '更新体育直播3', redisKeyM3uFake, fakeurl)
        # 同步方法写出全部配置
        distribute_data(redisKeyM3uFake, f"{secret_path}normal.m3u", 10)
        redis_add_map(REDIS_KEY_NORMAL_M3U, redisKeyNormalM3U)
        fuck_m3u_to_txt(f"{secret_path}normal.m3u", f"{secret_path}normal.txt")
        return "result"
    except Exception as e:
        return "empty"


def add_update_live(type, group_name, tvg_name, redisKeyM3uFake, fakeurl):
    global redisKeyNormal
    redisKeyNormal[type] = tvg_name
    redis_add_map(REDIS_KEY_NORMAL, {type: tvg_name})
    link2 = f'#EXTINF:-1 group-title="{group_name}" tvg-logo="https://raw.githubusercontent.com/paperbluster/ppap/main/update.png"  tvg-name="{tvg_name}",{tvg_name}\n'
    redisKeyM3uFake[f'{fakeurl}{type}.m3u8'] = link2


def chaoronghe24():
    try:
        global redisKeyYoutube
        ids = redisKeyYoutube.keys()
        m3u_dict = {}
        for id in ids:
            m3u_dict[id] = ''
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        redisKeyYoutubeM3uFake = {}
        # fakeurl = 'http://127.0.0.1:22771/youtube/'
        fakeurl = f"http://{ip}:{port_live}/youtube/"
        for id, url in m3u_dict.items():
            try:
                name = redisKeyYoutube[id]
                pic = f'https://i.ytimg.com/vi/{id}/hqdefault.jpg'
                link = f'#EXTINF:-1 group-title="Youtube" tvg-logo="{pic}"  tvg-name="{name}",{name}\n'
                redisKeyYoutubeM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyYoutubeM3uFake, f"{secret_path}youtube.m3u", 10)
        fuck_m3u_to_txt(f"{secret_path}youtube.m3u", f"{secret_path}youtube.txt")
        return "result"
    except Exception as e:
        return "empty"


# 一键导出全部配置
def delete_all_items_in_db(file_paths):
    for path in file_paths:
        if os.path.exists(path):
            os.remove(path)


def getHugeDataList(file_paths):
    for redisKey in hugeDataList:
        try:
            # 生成JSON文件数据
            json_data = generate_json_string(redisKey)
            filename = f"{secret_path}{redisKey}.json"
            if os.path.exists(filename):
                os.remove(filename)
            # 保存JSON数据到临时文件
            with open(filename, 'w') as f:
                f.write(json_data)
            file_paths.append(filename)
        except Exception as e:
            pass


def send_multiple_files(file_paths):
    zip_path = os.path.join(secret_path, "allData.zip")
    # 将所有文件压缩成zip文件
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
        for file_path in file_paths:
            zip_file.write(file_path, arcname=os.path.basename(file_path))
    # 发送zip文件到前端
    return send_file(zip_path, as_attachment=True)


def chaoronghe5():
    try:
        return chaorongheBase(REDIS_KEY_WHITELIST_IPV6_LINK, 'process_data_abstract6',
                              REDIS_KEY_WHITELIST_IPV6_DATA, f"{secret_path}{getFileNameByTagName('ipv6')}.txt")
    except:
        return "empty"


def chaoronghe4():
    try:
        return chaorongheBase(REDIS_KEY_WHITELIST_IPV4_LINK, 'process_data_abstract5',
                              REDIS_KEY_WHITELIST_IPV4_DATA, f"{secret_path}{getFileNameByTagName('ipv4')}.txt")
    except:
        return "empty"


def chaoronghe3():
    try:
        return chaorongheBase(REDIS_KEY_BLACKLIST_LINK, 'process_data_abstract7',
                              REDIS_KEY_BLACKLIST_OPENCLASH_FALLBACK_FILTER_DOMAIN_DATA)
        # return chaorongheBase(REDIS_KEY_BLACKLIST_LINK, 'process_data_abstract2',
        #                       REDIS_KEY_BLACKLIST_DATA, "/C.txt")
    except:
        return "empty"


def chaoronghe2():
    try:
        # chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract4',
        #                REDIS_KEY_DOMAIN_DATA, "/WhiteDomain.txt")
        return chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract3',
                              REDIS_KEY_WHITELIST_DATA_DNSMASQ,
                              f"{secret_path}{getFileNameByTagName('whiteListDnsmasq')}.conf")
        # return chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract2',
        #                       REDIS_KEY_WHITELIST_DATA, "/B.txt")
    except:
        return "empty"


def chaoronghe():
    try:
        return chaorongheBase(REDIS_KEY_M3U_LINK, 'process_data_abstract', REDIS_KEY_M3U_DATA,
                              f"{secret_path}{getFileNameByTagName('allM3u')}.m3u")
    except:
        return "empty"


message_dict = {}


# 根据年月日、当前时间、输入的字符串生成的绝对唯一uuid
def generate_only_uuid(my_string):
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d%H%M%S%f")
    unique_str = f"{timestamp}-{my_string}"
    serial_number = uuid.uuid5(uuid.NAMESPACE_URL, unique_str)
    return str(serial_number)


# 存储字典{'url'}
ask_queu = queue.Queue(1000)
# uuid,response/content/text
response_dict = {}


async def download_chunk(session, url, start, end, timeout=None, verify=None, params=None, proxy=None,
                         proxy_auth=None,
                         header=None, data=None):
    headers = {'Range': f'bytes={start}-{end}'}
    if header:
        headers.update(header)
    async with session.get(url, headers=headers, params=params, timeout=timeout, ssl=verify, proxy=proxy,
                           proxy_auth=proxy_auth, data=data) as response:
        if response.status == 206:  # Partial Content
            chunk = await response.read()
            return chunk
        else:
            return None


async def download_file2(session, url, threadnum=4, timeout=None, verify=None, params=None, proxy=None,
                         proxy_auth=None,
                         header=None, data=None):
    async with session.head(url, headers=header, params=params, timeout=timeout, ssl=verify, proxy=proxy,
                            proxy_auth=proxy_auth, data=data) as response:
        total_size = int(response.headers.get('Content-Length', 0))
        if not threadnum:
            threadnum = 4
        chunk_size = total_size // threadnum
        tasks = []
        chunks = []

        for i in range(threadnum):
            start = i * chunk_size
            end = start + chunk_size - 1 if i < threadnum - 1 else total_size - 1
            task = asyncio.create_task(
                download_chunk(session, url, start, end, timeout=timeout, verify=verify, params=params, proxy=proxy,
                               proxy_auth=proxy_auth,
                               header=header, data=data))
            tasks.append(task)

        for task in tasks:
            chunk = await task
            if chunk is not None:
                chunks.append(chunk)

        return b''.join(chunks)


async def ask(session, url, action, timeout=None, verify=None, params=None, proxy=None, proxy_auth=None,
              header=None, stream=None, data=None, threadnum=None, json=None):
    if action == 'threaddownload':
        content = await download_file2(session, url, threadnum=threadnum, timeout=timeout, verify=verify, params=params,
                                       proxy=proxy, proxy_auth=proxy_auth,
                                       header=header, data=data)
        if content and len(content) > 0:
            return content
        return None
    elif action.startswith('post-'):
        async with  session.post(url, headers=header, params=params, timeout=timeout, ssl=verify, proxy=proxy,
                                 proxy_auth=proxy_auth, data=data, json=json) as response:
            if stream:
                content = b''
                async for chunk in response.content.iter_any():
                    content += chunk
                if len(content) == 0:
                    return None
                return content
            else:
                content = None
                if action == 'post-text':
                    content = await response.text()
                elif action == 'post-read':
                    content = await response.read()
                elif action == 'post-content':
                    content = await response.content.read()
                elif action == 'post-json':
                    content = await response.json()
                elif action == 'post-ping':
                    if response and response.status == 200:
                        content = '1'
                elif action == 'post-headers':
                    if response and response.status == 200:
                        content = await response.headers
                elif action == 'post-status':
                    content = response.status
                return content
    else:
        async with  session.get(url, headers=header, params=params, timeout=timeout, ssl=verify, proxy=proxy,
                                proxy_auth=proxy_auth, data=data) as response:
            if stream:
                content = b''
                async for chunk in response.content.iter_any():
                    content += chunk
                if len(content) == 0:
                    return None
                return content
            else:
                content = None
                if action == 'text':
                    content = await response.text()
                elif action == 'read':
                    content = await response.read()
                elif action == 'content':
                    content = await response.content.read()
                elif action == 'json':
                    content = await response.json()
                elif action == 'ping':
                    if response and response.status == 200:
                        content = '1'
                elif action == 'headers':
                    if response and response.status == 200:
                        content = await response.headers
                return content


def put_async_request_queue(url, action, header=None, timeout=None, verify=True, stream=False, params=None, proxy=None,
                            proxy_auth=None, data=None, threadnum=None, json=None):
    ask_dict = {}
    uuid = generate_only_uuid(random.randrange(0, int(time.time())))
    ask_dict['uuid'] = uuid
    ask_dict['url'] = url
    ask_dict['action'] = action
    if header:
        ask_dict['header'] = header
    if timeout:
        ask_dict['timeout'] = timeout
    if verify:
        ask_dict['verify'] = verify
    if stream:
        ask_dict['stream'] = stream
    if params:
        ask_dict['params'] = params
    if proxy:
        ask_dict['proxy'] = proxy
    if proxy_auth:
        ask_dict['proxy_auth'] = proxy_auth
    if stream:
        ask_dict['stream'] = stream
    if data:
        ask_dict['data'] = data
    if threadnum:
        ask_dict['threadnum'] = threadnum
    if json:
        ask_dict['json'] = json
    ask_queu.put(ask_dict)
    start = time.time()
    returnValue = None
    if timeout:
        newTimeout = timeout + 5
    else:
        newTimeout = 60
    while time.time() - start < newTimeout:
        try:
            if uuid not in response_dict.keys():
                continue
            response = response_dict.get(uuid)
            if response:
                returnValue = response
                break
        except Exception as e:
            pass
    try:
        del response_dict[uuid]
    except Exception as e:
        pass
    return returnValue


async def get_url(session, url_dict):
    url = url_dict['url']
    uuid = url_dict['uuid']
    action = url_dict['action']
    try:
        header = url_dict['header']
    except Exception as e:
        header = None
    try:
        timeout = url_dict['timeout']
    except Exception as e:
        timeout = None
    try:
        verify = url_dict['verify']
    except Exception as e:
        verify = None
    try:
        params = url_dict['params']
    except Exception as e:
        params = None
    try:
        proxy = url_dict['proxy']
    except Exception as e:
        proxy = None
    try:
        proxy_auth = url_dict['proxy_auth']
    except Exception as e:
        proxy_auth = None
    try:
        stream = url_dict['stream']
    except Exception as e:
        stream = None
    try:
        data = url_dict['data']
    except Exception as e:
        data = None
    try:
        threadnum = url_dict['threadnum']
    except Exception as e:
        threadnum = None
    try:
        json = url_dict['json']
    except Exception as e:
        json = None
    response = None
    try:
        response = await ask(session, url, action, timeout=timeout, verify=verify, params=params,
                             proxy=proxy, proxy_auth=proxy_auth,
                             header=header, stream=stream, data=data, threadnum=threadnum, json=json)
        response_dict[uuid] = response
    except Exception as e:
        print(e)
        response = None
        pass
    if response is None:
        response_dict[uuid] = None


async def download_session_queue():
    async with aiohttp.ClientSession() as session:
        while True:
            # 从任务队列中获取一个任务
            if not ask_queu.empty():
                try:
                    url_dict = ask_queu.get()
                except Exception as e:
                    print(e)
                    # continue
                await asyncio.create_task(get_url(session, url_dict))


def start_async_listener():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(download_session_queue())


# 自定义flask程序，使其启动时后挂一个程序
class FlaskApp(Flask):
    def __init__(self, *args, **kwargs):
        super(FlaskApp, self).__init__(*args, **kwargs)
        self._activate_background_job()

    def _activate_background_job(self):
        timer_thread1 = threading.Thread(target=clock_thread, daemon=True)
        timer_thread1.start()


app = FlaskApp(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True  # 实时更新模板文件
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 上传文件最大限制1000 MB
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # 静态文件缓存时间，默认值为 12 小时。可以通过将其设为 0 来禁止浏览器缓存静态文件
app.config['JSONIFY_TIMEOUT'] = 6000  # 设置响应超时时间为 6000 秒
app.config['PROXY_CONNECT_TIMEOUT'] = 6000
app.config['PROXY_SEND_TIMEOUT'] = 6000
app.config['PROXY_READ_TIMEOUT'] = 6000


# 针对已登录用户的受保护视图函数
@app.route('/')
@requires_auth
def index():
    return render_template('index.html')


# 路由隐藏真实路径-公共路径
@app.route('/url/<path:filename>')
def serve_files(filename):
    root_dir = public_path  # 根目录
    return send_from_directory(root_dir, filename, as_attachment=True)


# 路由隐藏真实路径-隐私路径
@app.route('/secret/<path:filename>')
def serve_files2(filename):
    root_dir = secret_path  # 根目录
    return send_from_directory(root_dir, filename, as_attachment=True)


youtube_lock = threading.Lock()


def get_live_url(tv_dict, id, liveType):
    url_json = tv_dict.get(id)
    url = getFileNameByTagName('failTs')
    if not url_json:
        try:
            if liveType == 'youtube':
                with youtube_lock:
                    url_json = tv_dict.get(id)
                    if url_json:
                        lastUpdateTime = float(url_json['updatetime'])
                        if (time.time() - lastUpdateTime) < 300:
                            url = tv_dict[id]['url']
                            return url
                    url = get_hd_url_youtube(id)
                    if url:
                        tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
            elif liveType == 'bilibili':
                with bilibili_lock:
                    url_json = tv_dict.get(id)
                    if url_json:
                        lastUpdateTime = float(url_json['updatetime'])
                        if (time.time() - lastUpdateTime) < 300:
                            url = tv_dict[id]['url']
                            return url
                    url = get_hd_url_bilibili(id)
                    if url:
                        tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
            elif liveType == 'huya':
                with huya_lock:
                    url_json = tv_dict.get(id)
                    if url_json:
                        lastUpdateTime = float(url_json['updatetime'])
                        if (time.time() - lastUpdateTime) < 300:
                            url = tv_dict[id]['url']
                            return url
                    url = get_hd_url_huya(id)
                    if url:
                        tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
            elif liveType == 'yy':
                with yy_lock:
                    url_json = tv_dict.get(id)
                    if url_json:
                        lastUpdateTime = float(url_json['updatetime'])
                        if (time.time() - lastUpdateTime) < 300:
                            url = tv_dict[id]['url']
                            return url
                    url = get_hd_url_yy(id)
                    if url:
                        tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
            elif liveType == 'twitch':
                with twitch_lock:
                    url_json = tv_dict.get(id)
                    if url_json:
                        lastUpdateTime = float(url_json['updatetime'])
                        if (time.time() - lastUpdateTime) < 300:
                            url = tv_dict[id]['url']
                            return url
                    url = get_hd_url_twitch(id)
                    if url:
                        tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
            elif liveType == 'douyin':
                with douyin_lock:
                    url_json = tv_dict.get(id)
                    if url_json:
                        lastUpdateTime = float(url_json['updatetime'])
                        if (time.time() - lastUpdateTime) < 300:
                            url = tv_dict[id]['url']
                            return url
                    url = get_hd_url_douyin(id)
                    if url:
                        tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
        except:
            pass
    else:
        lastUpdateTime = float(url_json['updatetime'])
        if (time.time() - lastUpdateTime) >= 600:
            try:
                if liveType == 'youtube':
                    with youtube_lock:
                        url_json = tv_dict.get(id)
                        if url_json:
                            lastUpdateTime = float(url_json['updatetime'])
                            if (time.time() - lastUpdateTime) < 300:
                                url = tv_dict[id]['url']
                                return url
                        url = get_hd_url_youtube(id)
                        if url:
                            tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
                elif liveType == 'bilibili':
                    with bilibili_lock:
                        url_json = tv_dict.get(id)
                        if url_json:
                            lastUpdateTime = float(url_json['updatetime'])
                            if (time.time() - lastUpdateTime) < 300:
                                url = tv_dict[id]['url']
                                return url
                        url = get_hd_url_bilibili(id)
                        if url:
                            tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
                elif liveType == 'huya':
                    with huya_lock:
                        url_json = tv_dict.get(id)
                        if url_json:
                            lastUpdateTime = float(url_json['updatetime'])
                            if (time.time() - lastUpdateTime) < 300:
                                url = tv_dict[id]['url']
                                return url
                        url = get_hd_url_huya(id)
                        if url:
                            tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
                elif liveType == 'yy':
                    with yy_lock:
                        url_json = tv_dict.get(id)
                        if url_json:
                            lastUpdateTime = float(url_json['updatetime'])
                            if (time.time() - lastUpdateTime) < 300:
                                url = tv_dict[id]['url']
                                return url
                        url = get_hd_url_yy(id)
                        if url:
                            tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
                elif liveType == 'twitch':
                    with twitch_lock:
                        url_json = tv_dict.get(id)
                        if url_json:
                            lastUpdateTime = float(url_json['updatetime'])
                            if (time.time() - lastUpdateTime) < 300:
                                url = tv_dict[id]['url']
                                return url
                        url = get_hd_url_twitch(id)
                        if url:
                            tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
                elif liveType == 'douyin':
                    with douyin_lock:
                        url_json = tv_dict.get(id)
                        if url_json:
                            lastUpdateTime = float(url_json['updatetime'])
                            if (time.time() - lastUpdateTime) < 300:
                                url = tv_dict[id]['url']
                                return url
                        url = get_hd_url_douyin(id)
                        if url:
                            tv_dict[id] = {'url': url, 'updatetime': str(time.time())}
            except:
                pass
        else:
            url = tv_dict[id]['url']
    return url


# 路由youtube
@app.route('/youtube/<path:filename>')
def serve_youtube(filename):
    id = filename.split('.')[0]
    time_clock_update_dict['youtubelockuuid'] = id
    url = get_live_url(tv_dict_youtube, id, 'youtube')

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    return redirect(url)


bilibili_lock = threading.Lock()


# 路由bilibili
@app.route('/bilibili/<path:filename>')
def serve_files4(filename):
    id = filename.split('.')[0]
    time_clock_update_dict['bilibililockuuid'] = id
    url = get_live_url(tv_dict_bilibili, id, 'bilibili')

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    return redirect(url)


huya_lock = threading.Lock()


# 路由huya
@app.route('/huya/<path:filename>')
def serve_files5(filename):
    id = filename.split('.')[0]
    time_clock_update_dict['huyalockuuid'] = id
    url = get_live_url(tv_dict_huya, id, 'huya')

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    return redirect(url)


yy_lock = threading.Lock()


# 路由YY
@app.route('/YY/<path:filename>')
def serve_files6(filename):
    id = filename.split('.')[0]
    time_clock_update_dict['yylockuuid'] = id
    url = get_live_url(tv_dict_yy, id, 'yy')

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    return redirect(url)


douyin_lock = threading.Lock()


# 路由DOUYIN
@app.route('/DOUYIN/<path:filename>')
def serve_files_DOUYIN(filename):
    id = filename.split('.')[0]
    time_clock_update_dict['douyinlockuuid'] = id
    url = get_live_url(tv_dict_douyin, id, 'douyin')

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    return redirect(url)


twitch_lock = threading.Lock()


# 路由twitch
@app.route('/TWITCH/<path:filename>')
def serve_files7(filename):
    id = filename.split('.')[0]
    time_clock_update_dict['twitchlockuuid'] = id
    url = get_live_url(tv_dict_twitch, id, 'twitch')

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    return redirect(url)


def reset_clock(key):
    global time_clock_update_dict
    time_clock_update_dict[key] = '0'


def get_m3u8_link(id):
    url = f"https://hklive.tv/{id}"

    headers = {
        "Authority": "https://hklive.tv/",
        "Path": f"/{id}",
        'Accept-Encoding': 'gzip, deflate, br',
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        "Referer": f"https://hklive.tv/{id}",
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67'
    }
    try:
        response = requests.get(url, headers=headers)
        if response and response.status_code == 200:
            content = response.text  # 解码为字符串
            # 使用正则表达式提取file对应的字符串
            pattern = r'file:\s*"(.*?)"'
            match = re.search(pattern, content)
            if match:
                file_url = match.group(1)
                return file_url
            else:
                return None
        else:
            return None
    except:
        return None


async def download_chunk(session, url, headers, start_byte, end_byte):
    headers['Range'] = f'bytes={start_byte}-{end_byte}'
    async with session.get(url, headers=headers) as response:
        if response.status == 206:
            return await response.content.read()
        return b''


def get_hd_m3u8_url_sky(href_url):
    href_url = href_url.split('skylinewebcams,')[1]
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    count = 0
    while count < 3:
        try:
            bytesdata = loop.run_until_complete(get_sky_url(href_url))
            if bytesdata is None:
                count += 1
                continue
            return bytesdata
        except:
            count += 1
            pass
    return None


async def get_sky_url(href_url):
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Cache-Control": "max-age=0",
        "Cookie": "PHPSESSID=3fbcaedr3jdolljejra92ouag0",
        "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Microsoft Edge\";v=\"114\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67"
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(href_url, headers=headers) as response:
                if response.status == 200:
                    cotent = await response.read()
                    source_parameter = re.search(r"source:'([^']+)'", cotent.decode())

                    if source_parameter:
                        source = 'https://hd-auth.skylinewebcams.com/' + source_parameter.group(1).replace('livee.',
                                                                                                           'live.')
                        return source
                    else:
                        return None
    except:
        return None
    return None


def async_to_sync(funtionName, id, number):
    # loop = asyncio.new_event_loop()
    # asyncio.set_event_loop(loop)
    timesec = time.time()
    while time.time() - timesec < 60:
        if funtionName == 'get_ts_data2':
            # 有效直播源,名字/id
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            bytesdata = loop.run_until_complete(get_ts_data2(id, number))
            # if bytesdata is None:
            #bytesdata = get_ts_data(id, number)
            if bytesdata is None:
                continue
            return bytesdata
        if funtionName == 'get_m3u8_raw_content2':
            # 有效直播源,名字/id
            # bytesdata = loop.run_until_complete(get_m3u8_raw_content2(id, number))
            # if bytesdata is None:
            bytesdata = get_m3u8_raw_content(id, number)
            if bytesdata is None:
                continue
            return bytesdata
        if funtionName == 'get_m3u8_link2':
            # 有效直播源,名字/id
            # bytesdata = loop.run_until_complete(get_m3u8_link2(id))
            # if bytesdata is None:
            bytesdata = get_m3u8_link(id)
            if bytesdata is None:
                continue
            return bytesdata


async def get_m3u8_link2(id):
    url = f"https://hklive.tv/{id}"

    headers = {
        "Authority": "https://hklive.tv/",
        "Method": "GET",
        "Path": f"/{id}",
        "Scheme": "https",
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        "Referer": f"https://hklive.tv/{id}",
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67'
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(url, ssl=False) as response:
            if response and response.status == 200:
                content = await response.text()  # 解码为字符串
                # 使用正则表达式提取file对应的字符串
                pattern = r'file:\s*"(.*?)"'
                match = re.search(pattern, content)
                if match:
                    file_url = match.group(1)
                    return file_url
                else:
                    return None
            else:
                return None


async def get_m3u8_raw_content2(url, id):
    if not url:
        return None
    path = url.split('https://hklive.tv')[1].split('?')[0]
    headers = {
        "Authority": "https://hklive.tv/",
        'Accept': '*/*',
        'If-Modified-Since': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
        "Referer": f"https://hklive.tv/{id}",
        "Sec-Ch-Ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Path": path,
        'User-Agent': '-user_agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67\"'
    }
    # url = f"https://hklive.tv/dtmb/{id}/"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, ssl=False) as response:
            if response.status == 200:
                content = await response.content.read()
                new_m3u8_data = []
                ip = init_IP()
                fakeurl = f"http://127.0.0.1:5000/normal/"
                # fakeurl = f"http://{ip}:{port_live}/normal/"
                for line in content.splitlines():
                    if line.startswith(
                            (b'#EXTM3U', b'#EXT-X', b'#EXTINF')):
                        new_m3u8_data.append(line)
                    else:
                        if line.startswith(b'web_error'):
                            return None
                        try:
                            num = int(line.split(b'.')[0]) / 1000
                        except:
                            return None
                        new_m3u8_data.append(f'{fakeurl}hkdtmb,{id},{line.decode()}'.encode())
                        # new_m3u8_data.append(f'{url}{line.decode()}'.encode())
                return b'\n'.join(new_m3u8_data)
            else:
                return None


async def get_ts_data2(id, number):
    url = f"https://hklive.tv/dtmb/{id}/{number}.ts"
    headers = {
        'Accept': '*/*',
        'Authority': 'https://hklive.tv/',
        'If-Modified-Since': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
        "Referer": f"https://hklive.tv/{id}",
        "Sec-Ch-Ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Path": url.split('https://hklive.tv')[1],
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67'}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.read()
    return None


def get_ts_data(id, number):
    url = f"https://hklive.tv/dtmb/{id}/{number}.ts"
    headers = {
        'Accept': '*/*',
        'Authority': 'https://hklive.tv/',
        'If-Modified-Since': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
        "Referer": f"https://hklive.tv/{id}",
        "Sec-Ch-Ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Path": url.split('https://hklive.tv')[1],
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67'}
    try:
        # response = requests.get(url, headers=headers)
        response = requests.get(url, headers=headers, stream=True)
        if response and response.status_code == 200:
            data = b''
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    data += chunk
            return data
        else:
            return None
    except:
        return None


def get_m3u8_raw_content(url, id):
    if not url:
        return None
    path = url.split('https://hklive.tv')[1].split('?')[0]
    etag = get_etag(id)
    headers = {
        'Accept': '*/*',
        'Authority': 'https://hklive.tv/',
        'If-Modified-Since': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
        "Referer": f"https://hklive.tv/{id}",
        "Sec-Ch-Ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Path": path,
        'User-Agent': '-user_agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67\"'
    }
    if etag is not None:
        headers['If-None-Match'] = etag
    try:
        response = requests.get(url, headers=headers)
        if response and response.status_code == 200:
            content = response.content
            try:
                etag = response.headers.get("Etag")
                if etag is not None and etag != '':
                    m3u_dict_hk[id] = etag
            except:
                pass
            new_m3u8_data = []
            ip = init_IP()
            fakeurl = f"http://127.0.0.1:5000/normal/"
            fakeurl = f"http://{ip}:{port_live}/normal/"
            arr = content.splitlines()
            find = False
            for i in range(len(arr)):
                line = arr[i]
                if line.startswith(
                        (b'#EXTM3U', b'#EXT-X', b'#EXTINF')):
                    new_m3u8_data.append(line)
                else:
                    try:
                        num = int(line.split(b'.')[0]) / 1000
                    except:
                        return None
                    # new_m3u8_data.append(f'{url}{line.decode()}'.encode())
                    new_m3u8_data.append(fakeurl.encode() + b'hkdtmb,' + id.encode() + b',' + line)
            return b'\n'.join(new_m3u8_data)
        else:
            return None
    except:
        return None


migu_lock = threading.Lock()
skylinewebcams_lock = threading.Lock()
cq_lock = threading.Lock()
efs_lock = threading.Lock()


# 推流普通ts文件
@app.route('/normal/<path:path>.ts')
def video_m3u8_normal_ts(path):
    # with ts_lock:
    type, id, number = path.split(',')
    if type == 'hkdtmb':
        try:
            bytesdata = async_to_sync('get_ts_data2', id, number)
            if bytesdata:
                return Response(bytesdata, mimetype='video/MP2T', headers={'Cache-Control': 'no-cache'})
        except Exception as e:
            pass
    return


# id,etag
m3u_dict_hk = {}

def get_etag(id):
    try:
        etag = m3u_dict_hk.get(id)
        if etag is None or etag == '':
            return None
        return etag
    except:
        return None

# 路由normal
@app.route('/normal/<path:filename>.m3u8')
def serve_files_normal(filename):
    global redisKeyNormalM3U
    id = filename
    if id == 'qiumihui,':
        chaoronghe31_single('qiumihui,')
        return redirect(getFileNameByTagName('failTs'))
    elif id == 'longzhu,':
        chaoronghe31_single('longzhu,')
        return redirect(getFileNameByTagName('failTs'))
    elif id == '857,':
        chaoronghe31_single('857,')
        return redirect(getFileNameByTagName('failTs'))
    elif id.startswith('hkdtmb,'):
        # with hk_locl:
        if id not in tv_dict_normal:
            tv_dict_normal.clear()
            m3u_dict_hk.clear()
            tv_dict_normal[id] = ''
        hkid = id.split(',')[1]
        url = redisKeyNormalM3U.get(id)
        m3u8_url = url
        if url is None:
            m3u8_url = async_to_sync('get_m3u8_link2', hkid, hkid)
        if m3u8_url is None:
            return redirect(getFileNameByTagName('failTs'))
        try:
            m3u8_data = async_to_sync('get_m3u8_raw_content2', m3u8_url, hkid)
        except:
            m3u8_data = None
        if m3u8_data is None:
            return
        # 特殊的，这个url可能失效
        redisKeyNormalM3U[id] = m3u8_url
        return Response(m3u8_data, headers=headers_default2)
    url = tv_dict_normal.get(id)
    if not url:
        url = redisKeyNormalM3U.get(id)
        if url is None or url == '':
            if id.startswith('857,'):
                with efs_lock:
                    url = tv_dict_normal.get(id)
                    if not url:
                        url = get_hd_url_857(id)
                        redisKeyNormalM3U[id] = url
            elif id.startswith('skylinewebcams,'):
                with skylinewebcams_lock:
                    url = tv_dict_normal.get(id)
                    if not url:
                        url = get_hd_m3u8_url_sky(id)
                        redisKeyNormalM3U[id] = url
            elif id.startswith('migu,'):
                with migu_lock:
                    url = tv_dict_normal.get(id)
                    if not url:
                        url = get_hd_url_migu(id)
                        redisKeyNormalM3U[id] = url
                        reset_clock('migu')
            elif id.startswith('cq,'):
                with cq_lock:
                    url = tv_dict_normal.get(id)
                    if not url:
                        url = get_hd_url_cq(id)
                        redisKeyNormalM3U[id] = url
                        reset_clock('cq')
        tv_dict_normal.clear()
        tv_dict_normal[id] = url
    else:
        if id.startswith('migu,'):
            if is_update_clock_live('migu') and time_clock_update_dict['miguId'] == id:
                with migu_lock:
                    if is_update_clock_live('migu') and time_clock_update_dict['miguId'] == id:
                        url = get_hd_url_migu(id)
                        redisKeyNormalM3U[id] = url
                        tv_dict_normal[id] = url
                        update_clock('migu')
        elif id.startswith('cq,'):
            if is_update_clock_live('cq') and time_clock_update_dict['cqId'] == id:
                with cq_lock:
                    if is_update_clock_live('cq') and time_clock_update_dict['cqId'] == id:
                        url = get_hd_url_cq(id)
                        redisKeyNormalM3U[id] = url
                        tv_dict_normal[id] = url
                        update_clock('cq')

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    return redirect(url)


###################################################模仿redis服务器############################################


@app.route('/api/data', methods=['GET'])
def get_data():
    global message_dict
    returndict = jsonify(message_dict)
    message_dict.clear()
    return returndict


@app.route('/api/ping', methods=['GET'])
def ping():
    return jsonify({'result': ''})


@app.route('/api/data', methods=['POST'])
def post_data():
    global message_dict
    message = request.form.get('message')
    message_dict[message] = ''
    return jsonify({'result': ''})


@app.route('/api/data2', methods=['POST'])
def post_data_key_data():
    cachekey = request.form.get('cacheKey')
    action = request.form.get('action')
    file_path = os.path.join(DB_PATH, f'{cachekey}.txt')
    if action == 'get_single':
        return get_single(file_path)
    # 删除一个数据表
    elif action == 'delete':
        return delete_cache(file_path)
    # map增加表中一些条数据
    elif action == 'add_map':
        # 字符串格式的json数据
        add_dict = json.loads(request.form.get('dict_data'))
        return add_map(file_path, add_dict)
    # 增加/修改表中一条数据
    elif action == 'add_single':
        # 字符串格式的json数据
        value = request.form.get('dict_data')
        return add_single(file_path, value)
    # 删除map里的单个key/多个key
    elif action == 'delete_keys':
        # 字符串格式的json数据
        dict_data = json.loads(request.form.get('dict_data'))
        return delete_keys(file_path, dict_data)
    # 查询map
    elif action == 'get_map':
        return get_map(file_path)


###################################################模仿redis服务器#############################################

# 手动上传m3u文件格式化统一转换
@app.route('/api/process-file', methods=['POST'])
@requires_auth
def process_file():
    file = request.files['file']
    # file_content = file.read().decode('utf-8')
    file_content = file.read()
    # file_content = read_file_with_encoding(file)
    my_dict = formatdata_multithread(file_content.splitlines(), 10)
    # my_dict = formattxt_multithread(file_content.splitlines(), 100)
    # my_dict = formatdata_multithread(file.readlines(), 100)
    distribute_data(my_dict, f"{secret_path}tmp.m3u", 10)
    return send_file(f"{secret_path}tmp.m3u", as_attachment=True)


# 手动上传m3u文件提取名字统一分组
@app.route('/api/process-file2', methods=['POST'])
@requires_auth
def process_file2():
    file = request.files['file']
    file_content = file.read()
    group = request.form.get('data')
    datalist = []
    for line in file_content.splitlines():
        datalist.append(decode_bytes(line).strip())
    file_content = "\n".join(datalist)
    regex_pattern = r'tvg-name="(.*?)"'
    all_matches = re.findall(regex_pattern, file_content)
    group_dict = {}
    for i in all_matches:
        group_dict[i] = group
    # 将字典转换为JSON字符串并返回
    json_str = json.dumps(group_dict)
    filename = f'{secret_path}group.json'
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w') as f:
        f.write(json_str)
    return send_file(filename, as_attachment=True)


# 手动上传m3u文件提取名字统一分组
@app.route('/api/process-file3', methods=['POST'])
@requires_auth
def process_file3():
    file = request.files['file']
    file_content = file.read()
    group = request.form.get('data')
    group_dict = {}
    # 数据源，字典（词库+新分组名字），新分组名字
    find_m3u_name_txt(file_content.splitlines(), group_dict, group)
    # 将字典转换为JSON字符串并返回
    json_str = json.dumps(group_dict)
    filename = f'{secret_path}group.json'
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w') as f:
        f.write(json_str)
    return send_file(filename, as_attachment=True)


# 手动上传m3u文件转换成txt文件
@app.route('/api/process-file4', methods=['POST'])
@requires_auth
def process_file4():
    file = request.files['file']
    file_content = file.read()
    # 数据源，字典（词库+新分组名字），新分组名字
    resultContent = m3uToTxt(file_content.splitlines())
    filename = f'{secret_path}source.txt'
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(resultContent)
    return send_file(filename, as_attachment=True)


# 获取节点订阅密码
@app.route('/api/getExtraDnsPort3', methods=['GET'])
@requires_auth
def getExtraDnsPort3():
    num = init_pass('proxy')
    return jsonify({'button': num})


# 获取IPV6订阅密码
@app.route('/api/getExtraDnsPort2', methods=['GET'])
@requires_auth
def getExtraDnsPort2():
    num = init_pass('ipv6')
    return jsonify({'button': num})


# 获取IPV4订阅密码
@app.route('/api/getExtraDnsServer2', methods=['GET'])
@requires_auth
def getExtraDnsServer2():
    num = init_pass('ipv4')
    return jsonify({'button': num})


# 获取域名黑名单订阅密码
@app.route('/api/getChinaDnsPort2', methods=['GET'])
@requires_auth
def getChinaDnsPort2():
    num = init_pass('blacklist')
    return jsonify({'button': num})


# 获取域名白名单订阅密码
@app.route('/api/getChinaDnsServer2', methods=['GET'])
@requires_auth
def getChinaDnsServer2():
    num = init_pass('whitelist')
    return jsonify({'button': num})


# 获取直播源订阅密码
@app.route('/api/getThreadNum2', methods=['GET'])
@requires_auth
def getThreadNum2():
    num = init_pass('m3u')
    return jsonify({'button': num})


# 删除加密订阅密码历史记录
@app.route('/api/deletewm3u14', methods=['POST'])
@requires_auth
def deletewm3u14():
    return dellist(request, REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS)


# 拉取全部加密订阅密码历史记录
@app.route('/api/getall14', methods=['GET'])
@requires_auth
def getall14():
    return jsonify(redis_get_map(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS))


@app.route('/api/upload_json', methods=['POST'])
@requires_auth
def upload_json():
    # 从请求体中获取 rediskey 和文件内容
    data = request.get_json()
    rediskey = data.get('rediskey')
    file_content = data.get('content')
    return upload_json_base(rediskey, file_content)


# 一键上传全部配置集合文件
@app.route('/api/upload_json_file7', methods=['POST'])
@requires_auth
def upload_json_file7():
    return upload_oneKey_json(request)


# 赞助-比特币
@app.route('/api/get_image')
def get_image():
    filename = '/app/img/bitcoin.png'
    return send_file(filename, mimetype='image/png')


# 查询功能开启状态
@app.route("/api/getSwitchstate", methods=['POST'])
@requires_auth
def getSwitchstate():
    id = request.json['id']
    global function_dict
    status = function_dict[id]
    return jsonify({"checkresult": status})


# 批量切换功能开关
@app.route('/api/serverMode', methods=['POST'])
@requires_auth
def serverMode():
    mode = request.json['mode']
    if mode == 'server':
        switchSingleFunction('switch2', '1')
        switchSingleFunction('switch3', '1')
        switchSingleFunction('switch', '1')
        switchSingleFunction('switch4', '1')
        switchSingleFunction('switch5', '1')
        switchSingleFunction('switch6', '0')
        switchSingleFunction('switch7', '1')
        switchSingleFunction('switch8', '1')
        switchSingleFunction('switch9', '1')
        switchSingleFunction('switch10', '1')
        switchSingleFunction('switch11', '1')
        switchSingleFunction('switch12', '1')
        switchSingleFunction('switch13', '1')
        switchSingleFunction('switch14', '1')
        switchSingleFunction('switch15', '1')
        switchSingleFunction('switch16', '1')
        switchSingleFunction('switch17', '1')
        switchSingleFunction('switch18', '1')
        switchSingleFunction('switch19', '1')
        switchSingleFunction('switch20', '1')
        switchSingleFunction('switch21', '1')
        switchSingleFunction('switch22', '1')
        switchSingleFunction('switch23', '1')
        switchSingleFunction('switch24', '1')
        switchSingleFunction('switch25', '1')
        switchSingleFunction('switch26', '1')
        switchSingleFunction('switch27', '1')
        switchSingleFunction('switch28', '1')
        switchSingleFunction('switch30', '1')
        switchSingleFunction('switch31', '1')
        switchSingleFunction('switch32', '1')
        switchSingleFunction('switch33', '0')
        switchSingleFunction('switch34', '0')
    elif mode == 'client':
        switchSingleFunction('switch2', '0')
        switchSingleFunction('switch3', '0')
        switchSingleFunction('switch', '0')
        switchSingleFunction('switch4', '0')
        switchSingleFunction('switch5', '0')
        switchSingleFunction('switch6', '0')
        switchSingleFunction('switch7', '0')
        switchSingleFunction('switch8', '0')
        switchSingleFunction('switch9', '0')
        switchSingleFunction('switch10', '0')
        switchSingleFunction('switch11', '0')
        switchSingleFunction('switch12', '0')
        switchSingleFunction('switch13', '0')
        switchSingleFunction('switch14', '0')
        switchSingleFunction('switch15', '0')
        switchSingleFunction('switch16', '0')
        switchSingleFunction('switch17', '0')
        switchSingleFunction('switch18', '0')
        switchSingleFunction('switch19', '0')
        switchSingleFunction('switch20', '0')
        switchSingleFunction('switch21', '0')
        switchSingleFunction('switch22', '0')
        switchSingleFunction('switch23', '0')
        switchSingleFunction('switch24', '1')
        switchSingleFunction('switch25', '0')
        switchSingleFunction('switch26', '1')
        switchSingleFunction('switch27', '1')
        switchSingleFunction('switch28', '1')
        switchSingleFunction('switch30', '0')
        switchSingleFunction('switch31', '0')
        switchSingleFunction('switch32', '0')
        switchSingleFunction('switch33', '0')
        switchSingleFunction('switch34', '0')
    return 'success'


# 修改DNS超时时间戳
@app.route('/api/savetimeout', methods=['POST'])
@requires_auth
def savetimeout():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_DNS_TIMEOUT, int(data))
    dnstimeout[REDIS_KEY_DNS_TIMEOUT] = int(data)
    return "数据已经保存"


# DNS并发查询数
@app.route('/api/gettimeout', methods=['GET'])
@requires_auth
def gettimeout():
    num = init_dns_timeout()
    return jsonify({'button': num})


# 修改DNS并发查询数量
@app.route('/api/savequeryThreadNum', methods=['POST'])
@requires_auth
def savequeryThreadNum():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_DNS_QUERY_NUM, int(data))
    dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = int(data)
    return "数据已经保存"


# 获取DNS并发查询数量
@app.route('/api/getQueryThreadNum', methods=['GET'])
@requires_auth
def getQueryThreadNum():
    num = init_dns_query_num()
    return jsonify({'button': num})


# 删除DNS简易黑名单
@app.route('/api/deletewm3u13', methods=['POST'])
@requires_auth
def deletewm3u13():
    return_value = dellist(request, REDIS_KEY_DNS_SIMPLE_BLACKLIST)
    redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG}_3_1')
    return return_value


# 删除youtube直播源
@app.route('/api/deletewm3u24', methods=['POST'])
@requires_auth
def deletewm3u24():
    deleteurl = request.json.get('deleteurl')
    del redisKeyYoutube[deleteurl]
    return dellist(request, REDIS_KEY_YOUTUBE)


# 删除bilibili直播源
@app.route('/api/deletewm3u25', methods=['POST'])
@requires_auth
def deletewm3u25():
    deleteurl = request.json.get('deleteurl')
    del redisKeyBilili[deleteurl]
    return dellist(request, REDIS_KEY_BILIBILI)


# 删除huya直播源
@app.route('/api/deletewm3u26', methods=['POST'])
@requires_auth
def deletewm3u26():
    deleteurl = request.json.get('deleteurl')
    del redisKeyHuya[deleteurl]
    return dellist(request, REDIS_KEY_HUYA)


# 删除YY直播源
@app.route('/api/deletewm3u27', methods=['POST'])
@requires_auth
def deletewm3u27():
    deleteurl = request.json.get('deleteurl')
    del redisKeyYY[deleteurl]
    return dellist(request, REDIS_KEY_YY)


# 删除DOUYIN直播源
@app.route('/api/deletewm3u29', methods=['POST'])
@requires_auth
def deletewm3u29():
    deleteurl = request.json.get('deleteurl')
    del redisKeyDOUYIN[deleteurl]
    return dellist(request, REDIS_KEY_DOUYIN)


# 删除alist直播源
@app.route('/api/deletewm3u30', methods=['POST'])
@requires_auth
def deletewm3u30():
    deleteurl = request.json.get('deleteurl')
    del redisKeyAlist[deleteurl]
    return dellist(request, REDIS_KEY_ALIST)


# 删除TWITCH直播源
@app.route('/api/deletewm3u28', methods=['POST'])
@requires_auth
def deletewm3u28():
    deleteurl = request.json.get('deleteurl')
    del redisKeyTWITCH[deleteurl]
    return dellist(request, REDIS_KEY_TWITCH)


# 删除NORMAL直播源
@app.route('/api/deletewm3u31', methods=['POST'])
@requires_auth
def deletewm3u31():
    deleteurl = request.json.get('deleteurl')
    del redisKeyNormal[deleteurl]
    return dellist(request, REDIS_KEY_NORMAL)


# 添加DNS简易黑名单
@app.route('/api/addnewm3u13', methods=['POST'])
@requires_auth
def addnewm3u13():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    addurl = stupidThink(addurl)
    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST, my_dict)
    redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG}_0_{addurl}')
    return jsonify({'addresult': "add success"})


# 拉取全部DNS简易黑名单
@app.route('/api/getall13', methods=['GET'])
@requires_auth
def getall13():
    return jsonify(redis_get_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST))


# 拉取全部youtube
@app.route('/api/getall24', methods=['GET'])
@requires_auth
def getall24():
    global redisKeyYoutube
    return returnDictCache(REDIS_KEY_YOUTUBE, redisKeyYoutube)


# 拉取全部bilibili
@app.route('/api/getall25', methods=['GET'])
@requires_auth
def getall25():
    global redisKeyBilili
    return returnDictCache(REDIS_KEY_BILIBILI, redisKeyBilili)


# 拉取全部huya
@app.route('/api/getall26', methods=['GET'])
@requires_auth
def getall26():
    global redisKeyHuya
    return returnDictCache(REDIS_KEY_HUYA, redisKeyHuya)


# 拉取全部YY
@app.route('/api/getall27', methods=['GET'])
@requires_auth
def getall27():
    global redisKeyYY
    return returnDictCache(REDIS_KEY_YY, redisKeyYY)


# 拉取全部DOUYIN
@app.route('/api/getall29', methods=['GET'])
@requires_auth
def getall29():
    global redisKeyDOUYIN
    return returnDictCache(REDIS_KEY_DOUYIN, redisKeyDOUYIN)


# 拉取全部alist
@app.route('/api/getall30', methods=['GET'])
@requires_auth
def getall30():
    global redisKeyAlist
    return returnDictCache(REDIS_KEY_ALIST, redisKeyAlist)


# 拉取全部TWITCH
@app.route('/api/getall28', methods=['GET'])
@requires_auth
def getall28():
    global redisKeyTWITCH
    return returnDictCache(REDIS_KEY_TWITCH, redisKeyTWITCH)


# 拉取全部normal
@app.route('/api/getall31', methods=['GET'])
@requires_auth
def getall31():
    global redisKeyNormal
    return returnDictCache(REDIS_KEY_NORMAL, redisKeyNormal)


# 删除DNS简易白名单
@app.route('/api/deletewm3u12', methods=['POST'])
@requires_auth
def deletewm3u12():
    return_value = dellist(request, REDIS_KEY_DNS_SIMPLE_WHITELIST)
    redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG}_3_1')
    return return_value


# 添加DNS简易白名单
@app.route('/api/addnewm3u12', methods=['POST'])
@requires_auth
def addnewm3u12():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    addurl = stupidThink(addurl)
    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_DNS_SIMPLE_WHITELIST, my_dict)
    redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG}_0_{addurl}')
    return jsonify({'addresult': "add success"})


# 拉取全部DNS简易白名单
@app.route('/api/getall12', methods=['GET'])
@requires_auth
def getall12():
    return jsonify(redis_get_map(REDIS_KEY_DNS_SIMPLE_WHITELIST))


# 获取主机IP
@app.route('/api/getIP', methods=['GET'])
@requires_auth
def getIP():
    num = init_IP()
    return jsonify({'button': num})


# 修改主机IP
@app.route('/api/changeIP', methods=['POST'])
@requires_auth
def changeIP():
    data = request.json['selected_button']
    if data == "":
        data = getMasterIp()
    redis_add(REDIS_KEY_IP, data)
    ip[REDIS_KEY_IP] = data
    return "数据已经保存"


@app.route('/api/download_config', methods=['POST'])
@requires_auth
def handle_post_request():
    protocol = request.json.get('protocol')
    return download_json_file_base(protocol)


# 删除M3U白名单
@app.route('/api/deletewm3u11', methods=['POST'])
@requires_auth
def deletewm3u11():
    deleteurl = request.json.get('deleteurl')
    group = m3u_whitlist.get(deleteurl)
    del m3u_whitlist[deleteurl]
    checkAndRemoveM3uRank(group)
    return dellist(request, REDIS_KEY_M3U_WHITELIST)


# 删除M3U白名单分组优先级
@app.route('/api/deletewm3u16', methods=['POST'])
@requires_auth
def deletewm3u16():
    deleteurl = request.json.get('deleteurl')
    rank = m3u_whitlist_rank.get(deleteurl)
    del m3u_whitlist_rank[deleteurl]
    dealRemoveRankGroup(rank)
    return dellist(request, REDIS_KEY_M3U_WHITELIST_RANK)


# 切换功能开关
@app.route('/api/switchstate', methods=['POST'])
@requires_auth
def switchFunction():
    state = request.json['state']
    id = request.json['id']
    switchSingleFunction(id, state)
    return 'success'


# 删除M3U黑名单
@app.route('/api/deletewm3u15', methods=['POST'])
@requires_auth
def deletewm3u15():
    deleteurl = request.json.get('deleteurl')
    del m3u_blacklist[deleteurl]
    return dellist(request, REDIS_KEY_M3U_BLACKLIST)


# 删除单个下载加密上传
@app.route('/api/deletewm3u17', methods=['POST'])
@requires_auth
def deletewm3u17():
    deleteurl = request.json.get('deleteurl')
    del downAndSecUploadUrlPassAndName[deleteurl]
    # 序列化成JSON字符串
    json_string = json.dumps(downAndSecUploadUrlPassAndName)
    # 将JSON字符串存储到Redis中
    redis_add(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME, json_string)
    return jsonify({'deleteresult': "delete success"})


# 删除单个下载解密
@app.route('/api/deletewm3u18', methods=['POST'])
@requires_auth
def deletewm3u18():
    deleteurl = request.json.get('deleteurl')
    del downAndDeSecUrlPassAndName[deleteurl]
    # 序列化成JSON字符串
    json_string = json.dumps(downAndDeSecUrlPassAndName)
    # 将JSON字符串存储到Redis中
    redis_add(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME, json_string)
    return jsonify({'deleteresult': "delete success"})


# 添加M3U白名单
@app.route('/api/addnewm3u11', methods=['POST'])
@requires_auth
def addnewm3u11():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    checkAndUpdateM3uRank(name, -99)
    m3u_whitlist[addurl] = name
    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_M3U_WHITELIST, my_dict)
    return jsonify({'addresult': "add success"})


# 添加youtube直播源
@app.route('/api/addnewm3u24', methods=['POST'])
@requires_auth
def addnewm3u24():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    redisKeyYoutube[addurl] = name
    return addlist(request, REDIS_KEY_YOUTUBE)


# 添加bilibili直播源
@app.route('/api/addnewm3u25', methods=['POST'])
@requires_auth
def addnewm3u25():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyBilili
    redisKeyBilili[addurl] = name
    return addlist(request, REDIS_KEY_BILIBILI)


# 添加huya直播源
@app.route('/api/addnewm3u26', methods=['POST'])
@requires_auth
def addnewm3u26():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyHuya
    redisKeyHuya[addurl] = name
    return addlist(request, REDIS_KEY_HUYA)


# 添加YY直播源
@app.route('/api/addnewm3u27', methods=['POST'])
@requires_auth
def addnewm3u27():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyYY
    redisKeyYY[addurl] = name
    return addlist(request, REDIS_KEY_YY)


# 添加DOUYIN直播源
@app.route('/api/addnewm3u29', methods=['POST'])
@requires_auth
def addnewm3u29():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyDOUYIN
    redisKeyDOUYIN[addurl] = name
    return addlist(request, REDIS_KEY_DOUYIN)


# 添加alist直播源
@app.route('/api/addnewm3u30', methods=['POST'])
@requires_auth
def addnewm3u30():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyAlist
    redisKeyAlist[addurl] = name
    return addlist(request, REDIS_KEY_ALIST)


# 添加TWITCH直播源
@app.route('/api/addnewm3u28', methods=['POST'])
@requires_auth
def addnewm3u28():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyTWITCH
    redisKeyTWITCH[addurl] = name
    return addlist(request, REDIS_KEY_TWITCH)


# 添加normal直播源
@app.route('/api/addnewm3u31', methods=['POST'])
@requires_auth
def addnewm3u31():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyNormal
    redisKeyNormal[addurl] = name
    return addlist(request, REDIS_KEY_NORMAL)


# 添加M3U白名单分组优先级
@app.route('/api/addnewm3u16', methods=['POST'])
@requires_auth
def addnewm3u16():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    checkAndUpdateM3uRank(addurl, name)
    return jsonify({'addresult': "add success"})


# 添加下载加密上传-特殊字典结构保存到redis
@app.route('/api/addnewm3u17', methods=['POST'])
@requires_auth
def addnewm3u17():
    addurl = request.json.get('url')
    password = request.json.get('password')
    name = request.json.get('secretName')
    if len(downAndSecUploadUrlPassAndName.items()) == 0:
        # 从Redis中读取JSON字符串
        json_string_redis = redis_get(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME)
        # 反序列化成Python对象
        my_dict_redis = json.loads(json_string_redis)
        downAndSecUploadUrlPassAndName.update(my_dict_redis)
    downAndSecUploadUrlPassAndName[addurl] = {'password': password, 'secretName': name}
    # 序列化成JSON字符串
    json_string = json.dumps(downAndSecUploadUrlPassAndName)
    # 将JSON字符串存储到Redis中
    redis_add(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME, json_string)
    return jsonify({'addresult': "add success"})


# 添加下载解密-特殊字典结构保存到redis
@app.route('/api/addnewm3u18', methods=['POST'])
@requires_auth
def addnewm3u18():
    addurl = request.json.get('url')
    password = request.json.get('password')
    name = request.json.get('secretName')
    if len(downAndDeSecUrlPassAndName.items()) == 0:
        # 从Redis中读取JSON字符串
        json_string_redis = redis_get(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME)
        # 反序列化成Python对象
        my_dict_redis = json.loads(json_string_redis)
        downAndDeSecUrlPassAndName.update(my_dict_redis)
    downAndDeSecUrlPassAndName[addurl] = {'password': password, 'secretName': name}
    # 序列化成JSON字符串
    json_string = json.dumps(downAndDeSecUrlPassAndName)
    # 将JSON字符串存储到Redis中
    redis_add(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME, json_string)
    return jsonify({'addresult': "add success"})


# 添加M3U黑名单
@app.route('/api/addnewm3u15', methods=['POST'])
@requires_auth
def addnewm3u15():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    m3u_blacklist[addurl] = name
    return addlist(request, REDIS_KEY_M3U_BLACKLIST)


# 拉取全部m3u白名单配置
@app.route('/api/getall11', methods=['GET'])
@requires_auth
def getall11():
    init_m3u_whitelist()
    return jsonify(m3u_whitlist)


# 拉取全部m3u白名单分组优先级配置
@app.route('/api/getall16', methods=['GET'])
@requires_auth
def getall16():
    init_m3u_whitelist()
    return jsonify(m3u_whitlist_rank)


# 拉取全部下载加密上传
@app.route('/api/getall17', methods=['GET'])
@requires_auth
def getall17():
    return jsonify(downAndSecUploadUrlPassAndName)


# 拉取全部下载解密
@app.route('/api/getall18', methods=['GET'])
@requires_auth
def getall18():
    return jsonify(downAndDeSecUrlPassAndName)


# 拉取全部m3u黑名单配置
@app.route('/api/getall15', methods=['GET'])
@requires_auth
def getall15():
    init_m3u_blacklist()
    return jsonify(m3u_blacklist)


# 通用获取同步账户数据-cachekey,flag(bbs-gitee,pps-github,lls-webdav)
@app.route('/api/getSyncAccountData', methods=['POST'])
@requires_auth
def getSyncAccountData():
    cacheKey = request.json['cacheKey']
    type = request.json['inputvalue']
    if type == 'bbs':
        global redisKeyGitee
        num = init_gitee(cacheKey, REDIS_KEY_GITEE, redisKeyGitee)
        return jsonify({'password': num})
    elif type == 'pps':
        global redisKeyGithub
        num = init_gitee(cacheKey, REDIS_KEY_GITHUB, redisKeyGithub)
        return jsonify({'password': num})
    elif type == 'lls':
        global redisKeyWebDav
        num = init_gitee(cacheKey, REDIS_KEY_WEBDAV, redisKeyWebDav)
        return jsonify({'password': num})


# 修改同步账户数据    gitee-bbs github-pps webdav-lls
@app.route('/api/changeSyncData', methods=['POST'])
@requires_auth
def changeSyncData():
    cacheKey = request.json['cacheKey']
    type = request.json['type']
    value = request.json['inputvalue']
    if type == 'bbs':
        global redisKeyGitee
        update_gitee(cacheKey, value, REDIS_KEY_GITEE, redisKeyGitee)
    elif type == 'pps':
        global redisKeyGithub
        update_gitee(cacheKey, value, REDIS_KEY_GITHUB, redisKeyGithub)
    elif type == 'lls':
        global redisKeyWebDav
        update_gitee(cacheKey, value, REDIS_KEY_WEBDAV, redisKeyWebDav)
    return "数据已经保存"


# 通用随机订阅密码切换
@app.route("/api/changeSubscribePassword", methods=['POST'])
@requires_auth
def changeSubscribePassword():
    cacheKey = request.json['cacheKey']
    num = update_m3u_subscribe_pass(cacheKey)
    return jsonify({"password": num})


# 通用随机订阅密码切换-下载加密上传功能
@app.route("/api/changeSubscribePassword2", methods=['POST'])
@requires_auth
def changeSubscribePassword2():
    url = request.json['cacheKey']
    password = generateEncryptPassword()
    global downAndSecUploadUrlPassAndName
    myDict = downAndSecUploadUrlPassAndName.get(url)
    if myDict:
        myDict['password'] = password
        # 序列化成JSON字符串
        json_string = json.dumps(downAndSecUploadUrlPassAndName)
        # 将JSON字符串存储到Redis中
        redis_add(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME, json_string)
    return jsonify({"password": password})


# 查询订阅文件名字
@app.route("/api/getFileName", methods=['POST'])
@requires_auth
def getFileName():
    cacheKey = request.json['cacheKey']
    num = getFileNameByTagName(cacheKey)
    return jsonify({"password": num})


# 通用订阅文件名字手动修改
@app.route("/api/changeFileName", methods=['POST'])
@requires_auth
def changeFileName():
    cacheKey = request.json['cacheKey']
    newName = request.json['inputvalue']
    num = changeFileName2(cacheKey, newName)
    return jsonify({"password": num})


# 通用订阅密码手动修改
@app.route("/api/changeSubscribePasswordByHand", methods=['POST'])
@requires_auth
def changeSubscribePasswordByHand():
    cacheKey = request.json['cacheKey']
    password = request.json['inputvalue']
    num = update_m3u_subscribe_pass_by_hand(cacheKey, password)
    return jsonify({"password": num})


# 获取外国DNS端口
@app.route('/api/getExtraDnsPort', methods=['GET'])
@requires_auth
def getExtraDnsPort():
    num = init_extra_dns_port()
    return jsonify({'button': num})


# 修改外国DNS端口
@app.route('/api/saveExtraDnsPort', methods=['POST'])
@requires_auth
def saveExtraDnsPort():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_EXTRA_DNS_PORT, int(data))
    extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = int(data)
    redis_public_message(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG)
    return "数据已经保存"


# 获取外国DNS服务器
@app.route('/api/getExtraDnsServer', methods=['GET'])
@requires_auth
def getExtraDnsServer():
    num = init_extra_dns_server()
    return jsonify({'button': num})


# 修改外国DNS服务器
@app.route('/api/saveExtraDnsServer', methods=['POST'])
@requires_auth
def saveExtraDnsServer():
    data = request.json['selected_button']
    if data == "":
        data = "127.0.0.1"
    redis_add(REDIS_KEY_EXTRA_DNS_SERVER, data)
    extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = data
    redis_public_message(REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG)
    return "数据已经保存"


# 获取中国DNS端口
@app.route('/api/getChinaDnsPort', methods=['GET'])
@requires_auth
def getChinaDnsPort():
    num = init_china_dns_port()
    return jsonify({'button': num})


# 修改中国DNS端口
@app.route('/api/savechinaDnsPort', methods=['POST'])
@requires_auth
def savechinaDnsPort():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_CHINA_DNS_PORT, int(data))
    chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = int(data)
    redis_public_message(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG)
    return "数据已经保存"


# 获取中国DNS服务器
@app.route('/api/getChinaDnsServer', methods=['GET'])
@requires_auth
def getChinaDnsServer():
    num = init_china_dns_server()
    return jsonify({'button': num})


# 修改中国DNS服务器
@app.route('/api/savechinaDnsServer', methods=['POST'])
@requires_auth
def savechinaDnsServer():
    data = request.json['selected_button']
    if data == "":
        data = "127.0.0.1"
    redis_add(REDIS_KEY_CHINA_DNS_SERVER, data)
    chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = data
    redis_public_message(REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG)
    return "数据已经保存"


# 获取黑白名单并发检测线程数
@app.route('/api/getThreadNum', methods=['GET'])
@requires_auth
def getThreadNum():
    num = init_threads_num()
    return jsonify({'button': num})


# 修改黑白名单并发检测线程数
@app.route('/api/saveThreadS', methods=['POST'])
@requires_auth
def saveThreadS():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_THREADS, min(int(data), 1000))
    threadsNum[REDIS_KEY_THREADS] = min(int(data), 1000)
    redis_public_message(f'{REDIS_KEY_UPDATE_THREAD_NUM_FLAG}_{data}')
    return "数据已经保存"


# 选择目标转换的远程配置
@app.route('/api/chooseProxyModel', methods=['POST'])
@requires_auth
def chooseProxyModel():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = button
    redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, dict)
    return "success"


# 选择目标转换的远程服务器
@app.route('/api/chooseProxyServer', methods=['POST'])
@requires_auth
def chooseProxyServer():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = button
    redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, dict)
    return "success"


# 服务器启动时加载选择的配置
@app.route('/api/getSelectedModel', methods=['GET'])
@requires_auth
def getSelectedModel():
    dict = redis_get_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    if dict and len(dict.keys()) > 0:
        value = dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]
        if value:
            return jsonify({'button': value})
        else:
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = "ACL4SSR_Online 默认版 分组比较全(本地离线模板)"
            # 设定默认选择的模板
            redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, tmp_dict)
            return jsonify({'button': tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]})
    else:
        tmp_dict = {}
        tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = "ACL4SSR_Online 默认版 分组比较全(本地离线模板)"
        # 设定默认选择的模板
        redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, tmp_dict)
        return jsonify({'button': tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]})


# 服务器启动时加载选择的服务器
@app.route('/api/getSelectedServer', methods=['GET'])
@requires_auth
def getSelectedServer():
    dict = redis_get_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    if dict and len(dict.keys()) > 0:
        value = dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]
        if value:
            return jsonify({'button': value})
        else:
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = "bridge模式:本地服务器"
            redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, tmp_dict)
            return jsonify({'button': tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]})
    else:
        tmp_dict = {}
        tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = "bridge模式:本地服务器"
        redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, tmp_dict)
        return jsonify({'button': tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]})


# 拉取列表-代理模板
@app.route('/api/reloadProxyModels', methods=['GET'])
@requires_auth
def reloadProxyModels():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_SERVER))


# 删除节点远程后端服务器订阅
@app.route('/api/deletewm3u10', methods=['POST'])
@requires_auth
def deletewm3u10():
    returnJson = dellist(request, REDIS_KEY_PROXIES_SERVER)
    setRandomValueChosen(REDIS_KEY_PROXIES_SERVER, REDIS_KEY_PROXIES_SERVER_CHOSEN)
    return returnJson


# 添加节点后端订阅
@app.route('/api/addnewm3u10', methods=['POST'])
@requires_auth
def addnewm3u10():
    return addlist(request, REDIS_KEY_PROXIES_SERVER)


# 拉取全部后端服务器配置
@app.route('/api/getall10', methods=['GET'])
@requires_auth
def getall10():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_SERVER))


# 删除节点远程配置订阅
@app.route('/api/deletewm3u9', methods=['POST'])
@requires_auth
def deletewm3u9():
    returnJson = dellist(request, REDIS_KEY_PROXIES_MODEL)
    setRandomValueChosen(REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN)
    return returnJson


# 添加节点远程配置订阅
@app.route('/api/addnewm3u9', methods=['POST'])
@requires_auth
def addnewm3u9():
    return addlist(request, REDIS_KEY_PROXIES_MODEL)


# 拉取全部节点订阅远程配置
@app.route('/api/getall9', methods=['GET'])
@requires_auth
def getall9():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_MODEL))


# 服务器启动时加载选择的节点类型id
@app.route('/api/getSelectedButtonId', methods=['GET'])
@requires_auth
def getSelectedButtonId():
    button = getProxyButton()
    return jsonify({'button': button})


# 选择目标转换的节点类型id
@app.route('/api/chooseProxy', methods=['POST'])
@requires_auth
def chooseProxy():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_TYPE] = button
    redis_add_map(REDIS_KEY_PROXIES_TYPE, dict)
    return "success"


# 删除节点订阅
@app.route('/api/deletewm3u8', methods=['POST'])
@requires_auth
def deletewm3u8():
    return dellist(request, REDIS_KEY_PROXIES_LINK)


# 添加节点订阅
@app.route('/api/addnewm3u8', methods=['POST'])
@requires_auth
def addnewm3u8():
    return addlist(request, REDIS_KEY_PROXIES_LINK)


# 拉取全部节点订阅
@app.route('/api/getall8', methods=['GET'])
@requires_auth
def getall8():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_LINK))


# 全部节点订阅链接超融合
@app.route('/api/chaoronghe6', methods=['GET'])
@requires_auth
def chaoronghe_proxy():
    return chaoronghe6()


# 下载解密
@app.route('/api/chaoronghe10', methods=['GET'])
@requires_auth
def chaoronghe_downAndDesecret():
    return chaoronghe10()


# 下载加密上传执行
@app.route('/api/chaoronghe9', methods=['GET'])
@requires_auth
def chaoronghe_downAndUpload():
    return chaoronghe9()


# 简易DNS白名单超融合:白名单dnsmasq配置+白名单代理规则
@app.route('/api/chaoronghe8', methods=['GET'])
@requires_auth
def chaoronghe_simpleWhitelist():
    return chaoronghe8()


# 简易DNS黑名单超融合：op黑名单代理域名+代理规则
@app.route('/api/chaoronghe7', methods=['GET'])
@requires_auth
def chaoronghe_simpleBlacklist():
    return chaoronghe7()


# 生成全部alist直播源
@app.route('/api/chaoronghe30', methods=['GET'])
@requires_auth
def chaoronghe_alist():
    return chaoronghe30()


# 生成全部douyin直播源
@app.route('/api/chaoronghe29', methods=['GET'])
@requires_auth
def chaoronghe_douyin():
    return chaoronghe29()


# 生成全部YY直播源
@app.route('/api/chaoronghe27', methods=['GET'])
@requires_auth
def chaoronghe_yy():
    return chaoronghe27()


# 生成全部huyta直播源
@app.route('/api/chaoronghe26', methods=['GET'])
@requires_auth
def chaoronghe_huya():
    return chaoronghe26()


# 生成全部bilibili直播源
@app.route('/api/chaoronghe25', methods=['GET'])
@requires_auth
def chaoronghe_bilibili():
    return chaoronghe25()


# 推流加密ts文件
@app.route('/alist/<path:path>.ts')
def video_m3u8_alist_ts(path):
    uuid_ts = path
    start_time = time.time()  # 获取当前时间戳
    reliveAlistTsTime = int(getFileNameByTagName('reliveAlistTsTime'))
    while (time.time() - start_time) < reliveAlistTsTime:
        bytes_data_ts = get_true_alist_ts_url(uuid_ts)
        if bytes_data_ts:
            return Response(bytes_data_ts, mimetype='video/MP2T')
    return


# 推流加密m3u8列表
@app.route('/alist/<path:path>.m3u8')
def video_m3u8_alist(path):
    if path not in redisKeyAlistM3u.keys():
        return "Video not found", 404
    m3u8_path = os.path.join(SLICES_ALIST_M3U8, f"{path}.m3u8")
    # 读取M3U8播放列表文件并返回给客户端
    with open(m3u8_path, "rb") as f:
        m3u8_data = f.read()
    if m3u8_data:
        return Response(m3u8_data, headers={'Content-Type': 'application/vnd.apple.mpegurl'})
    else:
        return "Video not found", 404


# 生成全部TWITCH直播源
@app.route('/api/chaoronghe28', methods=['GET'])
@requires_auth
def chaoronghe_TWITCH():
    return chaoronghe28()


# 生成全部youtube直播源
@app.route('/api/chaoronghe24', methods=['GET'])
@requires_auth
def chaoronghe_youtube():
    return chaoronghe24()


# 生成全部normal直播源
@app.route('/api/chaoronghe31', methods=['GET'])
@requires_auth
def chaoronghe_normal():
    return chaoronghe31()


@app.route('/api/download_json_file7', methods=['GET'])
@requires_auth
def download_json_file7():
    file_paths = []
    # 生成JSON文件数据
    json_data = generate_multi_json_string(allListArr)
    if os.path.exists(f"{secret_path}allData.json"):
        os.remove(f"{secret_path}allData.json")
    # 保存JSON数据到临时文件
    with open(f"{secret_path}allData.json", 'w') as f:
        f.write(json_data)
    file_paths.append(f"{secret_path}allData.json")
    getHugeDataList(file_paths)
    # 发送所有JSON文件到前端
    result = send_multiple_files(file_paths)
    # 删除所有数据项
    delete_all_items_in_db(file_paths)
    return result


# 删除密码
@app.route('/api/deletewm3u6', methods=['POST'])
@requires_auth
def deletewm3u6():
    return dellist(request, REDIS_KEY_PASSWORD_LINK)


# 添加密码
@app.route('/api/addnewm3u6', methods=['POST'])
@requires_auth
def addnewm3u6():
    return addlist(request, REDIS_KEY_PASSWORD_LINK)


# 拉取全部密码
@app.route('/api/getall6', methods=['GET'])
@requires_auth
def getall6():
    return jsonify(redis_get_map(REDIS_KEY_PASSWORD_LINK))


# 全部ipv6订阅链接超融合
@app.route('/api/chaoronghe5', methods=['GET'])
@requires_auth
def chaoronghe_ipv6():
    return chaoronghe5()


# 拉取全部ipv6订阅
@app.route('/api/getall5', methods=['GET'])
@requires_auth
def getall5():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_IPV6_LINK))


# 删除ipv6订阅
@app.route('/api/deletewm3u5', methods=['POST'])
@requires_auth
def deletewm3u5():
    return dellist(request, REDIS_KEY_WHITELIST_IPV6_LINK)


# 添加ipv6订阅
@app.route('/api/addnewm3u5', methods=['POST'])
@requires_auth
def addnewm3u5():
    return addlist(request, REDIS_KEY_WHITELIST_IPV6_LINK)


# 删除ipv4订阅
@app.route('/api/deletewm3u4', methods=['POST'])
@requires_auth
def deletewm3u4():
    return dellist(request, REDIS_KEY_WHITELIST_IPV4_LINK)


# 添加ipv4订阅
@app.route('/api/addnewm3u4', methods=['POST'])
@requires_auth
def addnewm3u4():
    return addlist(request, REDIS_KEY_WHITELIST_IPV4_LINK)


# 全部ipv4订阅链接超融合
@app.route('/api/chaoronghe4', methods=['GET'])
@requires_auth
def chaoronghe_ipv4():
    return chaoronghe4()


# 拉取全部ipv4订阅
@app.route('/api/getall4', methods=['GET'])
@requires_auth
def getall4():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_IPV4_LINK))


# 全部域名黑名单订阅链接超融合
@app.route('/api/chaoronghe3', methods=['GET'])
@requires_auth
def chaoronghe_blacklist():
    return chaoronghe3()


# 删除黑名单订阅
@app.route('/api/deletewm3u3', methods=['POST'])
@requires_auth
def deletewm3u3():
    return dellist(request, REDIS_KEY_BLACKLIST_LINK)


# 添加黑名单订阅
@app.route('/api/addnewm3u3', methods=['POST'])
@requires_auth
def addnewm3u3():
    return addlist(request, REDIS_KEY_BLACKLIST_LINK)


# 拉取全部黑名单订阅
@app.route('/api/getall3', methods=['GET'])
@requires_auth
def getall3():
    return jsonify(redis_get_map(REDIS_KEY_BLACKLIST_LINK))


# 全部域名白名单订阅链接超融合
@app.route('/api/chaoronghe2', methods=['GET'])
@requires_auth
def chaoronghe_whitelist():
    return chaoronghe2()


# 拉取全部白名单订阅
@app.route('/api/getall2', methods=['GET'])
@requires_auth
def getall2():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_LINK))


# 添加白名单订阅
@app.route('/api/addnewm3u2', methods=['POST'])
@requires_auth
def addnewm3u2():
    return addlist(request, REDIS_KEY_WHITELIST_LINK)


# 删除白名单订阅
@app.route('/api/deletewm3u2', methods=['POST'])
@requires_auth
def deletewm3u2():
    return dellist(request, REDIS_KEY_WHITELIST_LINK)


# 删除全部本地直播源
@app.route('/api/removeallm3u', methods=['GET'])
@requires_auth
def removeallm3u():
    redis_del_map(REDIS_KEY_M3U_DATA)
    return "success"


# 删除全部加密订阅密码历史记录
@app.route('/api/removem3ulinks14', methods=['GET'])
@requires_auth
def removem3ulinks14():
    redis_del_map(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS)
    return "success"


# 删除全部简易DNS黑名单
@app.route('/api/removem3ulinks13', methods=['GET'])
@requires_auth
def removem3ulinks13():
    redis_del_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST)
    redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG}_1_1')
    return "success"


# 删除全部youtube直播源
@app.route('/api/removem3ulinks24', methods=['GET'])
@requires_auth
def removem3ulinks24():
    redisKeyYoutube.clear()
    redis_del_map(REDIS_KEY_YOUTUBE)
    return "success"


# 删除全部bilibili直播源
@app.route('/api/removem3ulinks25', methods=['GET'])
@requires_auth
def removem3ulinks25():
    redisKeyBilili.clear()
    redis_del_map(REDIS_KEY_BILIBILI)
    return "success"


# 删除全部huya直播源
@app.route('/api/removem3ulinks26', methods=['GET'])
@requires_auth
def removem3ulinks26():
    redisKeyHuya.clear()
    redis_del_map(REDIS_KEY_HUYA)
    return "success"


# 删除全部YY直播源
@app.route('/api/removem3ulinks27', methods=['GET'])
@requires_auth
def removem3ulinks27():
    redisKeyYY.clear()
    redis_del_map(REDIS_KEY_YY)
    return "success"


# 删除全部DOUYIN直播源
@app.route('/api/removem3ulinks29', methods=['GET'])
@requires_auth
def removem3ulinks29():
    redisKeyDOUYIN.clear()
    redis_del_map(REDIS_KEY_DOUYIN)
    return "success"


# 删除全部alist直播源
@app.route('/api/removem3ulinks30', methods=['GET'])
@requires_auth
def removem3ulinks30():
    redisKeyAlist.clear()
    redis_del_map(REDIS_KEY_ALIST)
    redisKeyAlistM3u.clear()
    redis_del_map(REDIS_KEY_Alist_M3U)
    redisKeyAlistM3uTsPath.clear()
    redis_del_map(REDIS_KEY_Alist_M3U_TS_PATH)
    return "success"


# 删除全部TWITCH直播源
@app.route('/api/removem3ulinks28', methods=['GET'])
@requires_auth
def removem3ulinks28():
    redisKeyTWITCH.clear()
    redis_del_map(REDIS_KEY_TWITCH)
    return "success"


# 删除全部normal直播源
@app.route('/api/removem3ulinks31', methods=['GET'])
@requires_auth
def removem3ulinks31():
    redisKeyNormal.clear()
    redis_del_map(REDIS_KEY_NORMAL)
    redisKeyNormalM3U.clear()
    redis_del_map(REDIS_KEY_NORMAL_M3U)
    return "success"


# 删除全部简易DNS白名单
@app.route('/api/removem3ulinks12', methods=['GET'])
@requires_auth
def removem3ulinks12():
    redis_del_map(REDIS_KEY_DNS_SIMPLE_WHITELIST)
    redis_public_message(f'{REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG}_1_1')
    return "success"


# 删除全部M3U白名单
@app.route('/api/removem3ulinks11', methods=['GET'])
@requires_auth
def removem3ulinks11():
    m3u_whitlist.clear()
    redis_del_map(REDIS_KEY_M3U_WHITELIST)
    return "success"


# 删除全部M3U白名单分组优先级
@app.route('/api/removem3ulinks16', methods=['GET'])
@requires_auth
def removem3ulinks16():
    m3u_whitlist_rank.clear()
    ranked_m3u_whitelist_set.clear()
    redis_del_map(REDIS_KEY_M3U_WHITELIST_RANK)
    return "success"


# 删除全部下载加密上传
@app.route('/api/removem3ulinks17', methods=['GET'])
@requires_auth
def removem3ulinks17():
    downAndSecUploadUrlPassAndName.clear()
    redis_del_map(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME)
    return "success"


# 删除全部下载解密
@app.route('/api/removem3ulinks18', methods=['GET'])
@requires_auth
def removem3ulinks18():
    downAndDeSecUrlPassAndName.clear()
    redis_del_map(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME)
    return "success"


# 删除全部M3U黑名单
@app.route('/api/removem3ulinks15', methods=['GET'])
@requires_auth
def removem3ulinks15():
    m3u_blacklist.clear()
    redis_del_map(REDIS_KEY_M3U_BLACKLIST)
    return "success"


# 删除全部节点后端服务器配置
@app.route('/api/removem3ulinks10', methods=['GET'])
@requires_auth
def removem3ulinks10():
    redis_del_map(REDIS_KEY_PROXIES_SERVER)
    redis_del_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    initProxyServer()
    return "success"


# 删除全部节点远程配置订阅
@app.route('/api/removem3ulinks9', methods=['GET'])
@requires_auth
def removem3ulinks9():
    redis_del_map(REDIS_KEY_PROXIES_MODEL)
    redis_del_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    initProxyModel()
    return "success"


# 删除全部节点订阅
@app.route('/api/removem3ulinks8', methods=['GET'])
@requires_auth
def removem3ulinks8():
    redis_del_map(REDIS_KEY_PROXIES_LINK)
    return "success"


# 删除全部密码本
@app.route('/api/removem3ulinks6', methods=['GET'])
@requires_auth
def removem3ulinks6():
    redis_del_map(REDIS_KEY_PASSWORD_LINK)
    return "success"


# 删除全部ipv6订阅链接
@app.route('/api/removem3ulinks5', methods=['GET'])
@requires_auth
def removem3ulinks5():
    redis_del_map(REDIS_KEY_WHITELIST_IPV6_LINK)
    return "success"


# 删除全部ipv4订阅链接
@app.route('/api/removem3ulinks4', methods=['GET'])
@requires_auth
def removem3ulinks4():
    redis_del_map(REDIS_KEY_WHITELIST_IPV4_LINK)
    return "success"


# 删除全部白名单源订阅链接
@app.route('/api/removem3ulinks3', methods=['GET'])
@requires_auth
def removem3ulinks3():
    redis_del_map(REDIS_KEY_BLACKLIST_LINK)
    return "success"


# 删除全部白名单源订阅链接
@app.route('/api/removem3ulinks2', methods=['GET'])
@requires_auth
def removem3ulinks2():
    redis_del_map(REDIS_KEY_WHITELIST_LINK)
    return "success"


# 删除全部直播源订阅链接
@app.route('/api/removem3ulinks', methods=['GET'])
@requires_auth
def removem3ulinks():
    redis_del_map(REDIS_KEY_M3U_LINK)
    return "success"


# 导出本地永久直播源
@app.route('/api/download_m3u_file', methods=['GET'])
@requires_auth
def download_m3u_file():
    my_dict = redis_get_map(REDIS_KEY_M3U_DATA)
    distribute_data(my_dict, f"{secret_path}temp_m3u.m3u", 10)
    # 发送JSON文件到前端
    return send_file(f"{secret_path}temp_m3u.m3u", as_attachment=True)


# 手动上传m3u文件把直播源保存到数据库
@app.route('/api/upload_m3u_file', methods=['POST'])
@requires_auth
def upload_m3u_file():
    file = request.files['file']
    # file_content = file.read().decode('utf-8')
    file_content = file.read()
    # file_content = read_file_with_encoding(file)
    my_dict = formatdata_multithread(file_content.splitlines(), 10)
    # my_dict = formattxt_multithread(file_content.splitlines(), 100)
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    if len(tmp_url_tvg_name_dict.keys()) > 0:
        redis_add_map(REDIS_KET_TMP_CHINA_CHANNEL, tmp_url_tvg_name_dict)
        tmp_url_tvg_name_dict.clear()
    return '文件已上传'


# 删除直播源
@app.route('/api/deletem3udata', methods=['POST'])
@requires_auth
def deletem3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    redis_del_map_key('localm3u', deleteurl)
    return jsonify({'deletem3udata': "delete success"})


# 添加直播源
@app.route('/api/addm3udata', methods=['POST'])
@requires_auth
def addm3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return jsonify({'addresult': "add success"})


# 拉取全部本地直播源
@app.route('/api/getm3udata', methods=['GET'])
@requires_auth
def getm3udata():
    return jsonify(redis_get_map(REDIS_KEY_M3U_DATA))


# 添加直播源到本地
@app.route('/api/savem3uarea', methods=['POST'])
@requires_auth
def savem3uarea():
    # 获取 HTML 页面发送的 POST 请求参数
    m3utext = request.json.get('m3utext')
    # 格式优化
    my_dict = formattxt_multithread(m3utext.split("\n"), 'process_data_abstract')
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return jsonify({'addresult': "add success"})


# 添加直播源订阅
@app.route('/api/addnewm3u', methods=['POST'])
@requires_auth
def addnewm3u():
    return addlist(request, REDIS_KEY_M3U_LINK)


# 删除直播源订阅
@app.route('/api/deletewm3u', methods=['POST'])
@requires_auth
def deletewm3u():
    return dellist(request, REDIS_KEY_M3U_LINK)


# 拉取全部直播源订阅
@app.route('/api/getall', methods=['GET'])
@requires_auth
def getall():
    return jsonify(redis_get_map(REDIS_KEY_M3U_LINK))


# 全部m3u订阅链接超融合
@app.route('/api/chaoronghe', methods=['GET'])
@requires_auth
def chaoronghe_m3u():
    return chaoronghe()


if __name__ == '__main__':
    try:
        app.run(debug=False, host='0.0.0.0', port=22771)
    finally:
        print("close")
