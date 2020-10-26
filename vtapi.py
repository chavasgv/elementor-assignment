
import requests
import json
from collections import Counter
import datetime
from apikey import apikey

url = 'https://www.virustotal.com/vtapi/v2/url/report'




def get_data(ApiUrl, ApiKey, URL):
    params = {'apikey': apikey, 'resource': URL}
    return      requests.get(url, params=params)

def Site_Risk(malicious, malware, phishing):
    if max(malicious, malware, phishing) > 0:
        return 'risk'
    return 'safe'




file1 = open('D:\\elementor\\elementor-assignment\\usr\\sites\\request1.csv', 'r') 
Lines = file1.readlines()
for l in Lines:
    params = {'apikey': apikey, 'resource': l}
    data = get_data(url, apikey, l)
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:     
        res = data.json()['scans']
        counts = Counter([res[key]['result'] for key in res])
        clean = counts['clean site']
        unrated = counts['unrated site']
        malicious = counts['malicious site']
        malware = counts['malware site']
        phishing = counts['phishing site']
        
  
        
        print('{},{},{},{},{},{},{}'.format(dt,l.strip(),Site_Risk(malicious, malware, phishing), clean , unrated , malicious , malware , phishing ))
    
    except:
        print ('{} :  skipping {} status.code={}'.format(dt,l.strip(),data.status_code))
    
       