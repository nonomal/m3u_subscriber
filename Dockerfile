FROM ubuntu:latest
# 将当前目录下的 python 脚本复制到容器中的 /app 目录
# 创建目录
RUN mkdir -p /app/ini /app/img /app/secret /app/m3u8 /app/templates /app/db
COPY ./*.py /app/
COPY ./ini/*.ini /app/ini/
COPY ./list/*.list /app/secret/
COPY ./list/*.yml /app/secret/
COPY ./bitcoin.png /app/img/
# 将前端文件复制到容器中的 /usr/share/nginx/html 目录
COPY index.html /app/templates

# 将Python依赖包复制到容器中
COPY requirements.txt /app/requirements.txt
RUN apt-get update && \
    apt-get install -yqq --no-install-recommends python3.9 python3-pip python3-dev && \
    pip3 install --no-cache-dir -r /app/requirements.txt && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 暴露容器的端口 22771-web 22770-dns 22772
EXPOSE 22771 22770
# 启动多个程序进程
COPY run.sh /app/run.sh
RUN chmod 777 /app/run.sh  /app/main.py  /app/dns.py
CMD ["/bin/bash", "-c", "/app/run.sh"]
