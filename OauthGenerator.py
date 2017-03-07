import urllib.request
import urllib.parse
import json
import re

content = urllib.request.urlopen('https://lyncdiscoverinternal.extron.com/')

contentHandler = content.read(400).decode()
JSONObject = json.loads(contentHandler)
userURL = JSONObject['_links']['user']['href']

OauthURL = urllib.request.Request(userURL)
try:
    urllib.request.urlopen(OauthURL)
except urllib.error.HTTPError as e: # Update this to parse ONLY for 401 error: 404/403/other will cause an issue
    authHandler = e.getheader('WWW-Authenticate')
    OauthToken = re.findall('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', authHandler)
else:
    print('A different error occurred: You should have received a 401.')

if OauthToken:
    payload = urllib.parse.urlencode({"charset": "UTF-8", "grant_type": "password", "username": "jlasher@extron.com", "password": "Waynesboro9303!"})
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': 96}
    payload = payload.encode('utf-8')
    raw_token = urllib.request.Request(OauthToken[0], payload, headers)
    with urllib.request.urlopen('https://lyncweb.extron.com/WebTicket/oauthtoken', payload) as f:
        access_token = f.read().decode('utf-8')

    JSONToken = json.loads(access_token)
    token = JSONToken['access_token']
    print(token)


'''
1. Send the above discovery URL and get the "user" URL
2. POST "user" URL to get 401 authentication response
3. Authentication response contains oauthtoken URL. Save that
4. Use oauthtoken URL in POST wtih OAuth token grant type: password
5. Password POST Request is as follows:
    POST https://<someurl>.com/WebTicket/oauthtoken HTTP/1.1
    Content-Type: application/x-www-form-urlencoded;charset='utf-8'
    Username: jlasher@extron.com
    Password: <mypassword>
6. Collect your OAuth token
'''
