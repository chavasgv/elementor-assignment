

url = 'https://www.virustotal.com/vtapi/v2/url/report'
apikey = 'YOUR_API_KEY'
url_file ='D:\\elementor\\elementor-assignment\\usr\\sites\\request1.csv'

#sql connect 
db_name='elemntor'
table = 'url_risk'


import mysql.connector
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="YOUR_PASSWORD",
)