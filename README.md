# m3usubscriber
## m3u超融合

![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%871.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/dns%E5%88%86%E6%B5%81%E7%BB%93%E7%BB%93%E6%9E%84.jpg?raw=true)

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

登陆面板:容器所在机器ip:22771

1-仅供个人使用，请勿商用，代码已经全部开源，后果自负

2-dns分流器建议挂host模式,然后指定127.0.0.1:22770作为软路由里某个adguardhome作为唯一上游dns服务器，这个adguardhome我是使用软路由自带的，直接劫持dns请求给它,这个adguardhome就作为最上游的dns劫持器和广告过滤器,m3u_subscriber就作为分流器。然后挂了另一个adguardhome容器作
为dns1服务器,dns2服务器就使用软路由自带的openclash,简易dns分流实际上是默认开启自动维护个人分流记录，相当于adguardhome的记录，只不过是根据分流分开记录，可以根据对应记录看是不是有分错的数据

。有分错的数据一直搞不定去dns分流器设置-》假设这部分顶级域名全部走分流DNS1,使用,分隔/假设这部分顶级域名全部走分流DNS2,使用,分隔这两个地方强制对一级、二级域名进行分流定义，这个强制分流是不依

赖任何网络第三方数据的，不建议加很多数据，一般情况保持默认。如果分流dns1/2域名的数据来源有污染就没办法了




