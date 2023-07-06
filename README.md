# m3usubscriber
## m3u超融合

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

# 28-权鉴账号密码:admin\password

4-仅供个人使用，请勿商用，代码已经全部开源，后果自负

6-有兴趣提供交流想法的朋友可以来电报群沟通https://t.me/+stAaKNYl3mtmN2Zl

7-各位朋友有兴趣打赏一下叫花子吧,您的赞助可以更大地激励我维护该项目:

比特币

![image](https://github.com/paperbluster/m3u_subscriber/blob/main/bitcoin.png?raw=true)

bitcoin:BC1QCA337CSCNUFCGLLKZF4UTPLFX0YDZ66UAE38U9?amount=0.00010000&label=%E8%AF%B7%E6%88%91%E5%96%9D%E6%9D%AF%E8%8C%B6%E5%90%A7&message=%E8%AF%B7%E6%88%91%E5%96%9D%E6%9D%AF%E8%8C%B6%E5%90%A7

bc1qca337cscnufcgllkzf4utplfx0ydz66uae38u9


