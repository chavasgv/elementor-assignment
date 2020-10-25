
import requests
import json

url = 'https://www.virustotal.com/vtapi/v2/url/report'

apikey='***key****'





file1 = open('D:\\elementor test\\usr\\sites\\request1.csv', 'r') 
Lines = file1.readlines()
for l in Lines:
    params = {'apikey': apikey, 'resource':l}
    response = requests.get(url, params=params)
    res = (response.json())
    print (json.dumps(res, sort_keys=True, indent=4))