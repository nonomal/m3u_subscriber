import requests
import dns.resolver

resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8']  # 将 DNS 服务器设置为 Google 的公共 DNS

url = 'https://www.example.com'
ip_address = resolver.query(url).response.answer[0].items[0].address
headers = {'Host': url, 'User-Agent': 'Mozilla/5.0'}
response = requests.get('http://' + ip_address, headers=headers)

print(response.content)
