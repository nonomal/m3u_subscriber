#!/bin/bash
# 启动Python DNS服务进程
python3 /app/dns.py &
# 启动Flask应用程序
export FLASK_APP=/app/main.py
flask run --host=0.0.0.0  --port=22771 &
# just keep this script running
while [[ true ]]; do
    sleep 1
done