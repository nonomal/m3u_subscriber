# m3usubscriber
## m3u超融合

## 直播源订阅、直播源检测、直播源分组、白名单黑名单订阅、节点订阅、订阅合并、订阅加密、dns分流器、youtube直播源


![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%871.png?raw=true)

### 安装步骤:

#### 一、host模式:推荐使用

## 普通:一般用下面的就可以

docker run   -d --name m3usubscriber  --restart unless-stopped --net=host -e TZ=Asia/Shanghai jkld310/m3usubscriber:latest

docker run   -d --name m3usubscriber --restart unless-stopped --net=host -e TZ=Asia/Shanghai jkld310/m3usubscriber:arm64v8

docker run   -d --name m3usubscriber --restart unless-stopped --net=host -e TZ=Asia/Shanghai jkld310/m3usubscriber:x86_64

## 特权:开放全部线程和管理权限

docker run   -d --name m3usubscriber --restart unless-stopped --net=host --memory=1000m --cpus=0.000 --privileged=true --cap-add=ALL -e TZ=Asia/Shanghai jkld310/m3usubscriber:latest

docker run   -d --name m3usubscriber  --restart unless-stopped --net=host --memory=1000m --cpus=0.000 --privileged=true --cap-add=ALL -e TZ=Asia/Shanghai jkld310/m3usubscriber:arm64v8

docker run    -d --name m3usubscriber --restart unless-stopped --net=host --memory=500m --cpus=0.000 --privileged=true --cap-add=ALL -e TZ=Asia/Shanghai jkld310/m3usubscriber:x86_64

#### 二、bridge模式:有BUG

docker run   -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770  -e TZ=Asia/Shanghai jkld310/m3usubscriber:latest

docker run   -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770  -e TZ=Asia/Shanghai jkld310/m3usubscriber:arm64v8

docker run   -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770  -e TZ=Asia/Shanghai jkld310/m3usubscriber:x86_64

#### 13-添加了类似acl4ssr的功能，需要额外安装docker容器subconverter或者公共转换服务器，我直接把acl4ssr作者的代理模板存进去了，做了保底措施，当只能下载其他情况全部失效的情况下会把一个加密订阅解锁后作为最终代理文件

#### 14-增加了基于redis的dns分流器，配合白名单和黑名单进行分流，转发7874端口(外国+中国域名漏网之鱼，可以使用openclash)，转发5336端口(大部分命中的中国域名，可以使用

adguardhome)，dns监听端口-22770(在软路由dhcp/dns设置转发127.0.0.1#22770)，自用

备注：dns分流器可以自己设置服务器和端口，建议使用host模式减少一层路由。

实际使用中建议把它作为软路由adguardhome插件的上游dns，adguardhome劫持dnsmasq的53端口，

在分流器里外国dns设置openclash，国内dns我填写了第二个adguardhome，这个全部是大陆dns

这样子顺便可以集中使用adguardhome插件的广告过滤

#### 15-增加了加密订阅功能，可以套娃订阅别人的加密订阅，在备注输入密码就可以自动解密加密文件下载

#### 16-增加了简易DNS分流黑白名单，可以选择手动维护，也可以选择开启系统自动维护，该部分主要是记录个人日常冲浪习惯的域名，黑白名单订阅是这个数据的来源和兜底

17-加了开关细化控制各个功能

#### 18-同步账户支持GITEE,GITHUB,WEBDAV。用途只有一个，把文件加密后同步到公共平台

#### 26-静态加密alist直播源，通过项目里的切片加密工具把普通视频转换成加密的直播源文件块，把切片文件数据包括文件夹上传至任意网络存储空间，之后在alist挂载，接着在alist直播源里填写

# 28-权鉴账号密码:admin\password

4-仅供个人使用，请勿商用，代码已经全部开源，后果自负

5-该镜像主要是辅助openclash使用的，可以稍微解决国内分流的糟糕体验

6-有兴趣提供交流想法的朋友可以来电报群沟通https://t.me/+stAaKNYl3mtmN2Zl

7-各位朋友有兴趣打赏一下叫花子吧,您的赞助可以更大地激励我维护该项目:

比特币

![image](https://github.com/paperbluster/m3u_subscriber/blob/main/bitcoin.png?raw=true)

bitcoin:BC1QCA337CSCNUFCGLLKZF4UTPLFX0YDZ66UAE38U9?amount=0.00010000&label=%E8%AF%B7%E6%88%91%E5%96%9D%E6%9D%AF%E8%8C%B6%E5%90%A7&message=%E8%AF%B7%E6%88%91%E5%96%9D%E6%9D%AF%E8%8C%B6%E5%90%A7

bc1qca337cscnufcgllkzf4utplfx0ydz66uae38u9


