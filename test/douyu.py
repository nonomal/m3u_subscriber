import requests

id = '206858'
rate = -1

url = 'https://wxapp.douyucdn.cn/api/nc/stream/roomPlayer'
data = {
    'room_id': id,
    'big_ct': 'cpn-androidmpro',
    'did': '10000000000000000000000000001501',
    'mt': '2',
    'rate': rate
}

response = requests.post(url, data=data)
json = response.json()['data']['live_url']