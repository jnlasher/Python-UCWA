import urllib.request
import urllib.parse
import json
import re
from pprint import pprint

content = urllib.request.urlopen('https://lyncdiscoverinternal.domain.com/')

contentHandler = content.read(400).decode()
JSONObject = json.loads(contentHandler)
userURL = JSONObject['_links']['user']['href']

OauthURL = urllib.request.Request(userURL)
try:
    urllib.request.urlopen(OauthURL)
except urllib.error.HTTPError as e: # TODO: Update this to parse ONLY for 401 error: 404/403/other will cause an issue
    print(e.code)
    authHandler = e.getheader('WWW-Authenticate')
    OauthToken = re.findall('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', authHandler)
    print(OauthToken[0])
else: # This is not very elegant... to be updated
    print('A different error occurred: You should have received a 401.')

if OauthToken: # TODO: Update this to prompt for credentials instead of hard coding them.
    DATA = {
        'charset':'UTF-8',
        'grant_type':'password',
        'username':'email@domain.com',
        'password':'password'
            }
    HEADERS = {
        'Content-Type':'application/x-www-form-urlencoded',
        'Content-Length':len(json.dumps(DATA))
              }
    req = urllib.request.Request(url=OauthToken[0],data=DATA,headers=HEADERS,method='PUT')
    with urllib.request.urlopen(req) as OauthHandler:
        pass
    print(OauthHandler.status)
    print(OauthHandler.reason)



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
