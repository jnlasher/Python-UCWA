import urllib.request
import urllib.parse
import json
import re

class OauthHandler:
    def __init__(self):
        self.discovery = 'https://lyncdiscoverinternal.extron.com/'
        self.applicationsURL = None
        self.updatedOauthToken = None

    def discoverPublic(self,userID,pwd):
        contentHandler = urllib.request.urlopen(self.discovery)
        content = json.loads(contentHandler.read().decode())
        userAuth = content['_links']['user']['href']
        oauthURL = self.__urlHelper(userAuth)
        oauthToken = self.__getAuthToken(oauthURL[0], userID, pwd)
        tokenHeader = {'Authorization':"Bearer {}".format(oauthToken)}
        listingHandler = self.__urlHelper(userAuth, headers=tokenHeader)
        listing = json.loads(listingHandler)
        self.applicationsURL = listing['_links']['applications']['href']
        print(listing)
        matchString = '(https?:\/\/(?:[^\/]+)(?:[\/,]|$)|^(.*)$)'
        discoveryDomain = re.findall(matchString, content['_links']['self']['href'])
        localDomain = re.findall(matchString, listing['_links']['self']['href'])

        if discoveryDomain == localDomain:
            print('Correct pool. Generating application...')
            self.updatedOauthToken = oauthToken
            #Send POST to applications resource under listing['_links']['applications']['href']
            #Verify 201 response and store applications data
        else:
            print('Incorrect pool, updating token...')
            updatedOauthURL = self.__urlHelper(listing['_links']['self']['href'])
            self.updatedOauthToken = self.__getAuthToken(updatedOauthURL[0], userID, pwd)
            print(updatedOauthURL)
            print(self.updatedOauthToken)



    def createApplication(self, userAgent, endpointID, culture='en-US'):
        url = self.applicationsURL #some URL from above function
        payload = json.dumps({'UserAgent':userAgent, 'EndpointId':endpointID, 'Culture':culture})
        headers = {
            'authorization': "Bearer {}".format(self.updatedOauthToken),
            'content-type': "application/json",
            'cache-control': "no-cache"
        }

        request = urllib.request.Request(url, headers=headers, data=payload.encode())
        with urllib.request.urlopen(request) as response:
            listing = response.read().decode()
        print(listing)


    def __getAuthToken(self, url, userID, pwd):
        payload = urllib.parse.urlencode({"charset": "UTF-8", "grant_type": "password", "username": userID, "password": pwd})
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': len(str(payload))}
        with urllib.request.urlopen(url, payload.encode()) as f:
            access_token = f.read().decode('utf-8')
        JSONToken = json.loads(access_token)
        token = JSONToken['access_token']
        return token


    def __urlHelper(self, url, payload=None, headers={}):
        try:
            request = urllib.request.Request(url, headers=headers, data=payload)
            with urllib.request.urlopen(request) as response:
                responseData = response.read().decode()
        except urllib.error.HTTPError as err:
            if err.code == 401:
                authHandler = err.getheader('WWW-Authenticate')
                responseData = re.findall('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', authHandler)
            else:
                print('HTTP Error occurred. Status: {}'.format(err.code))
        return responseData
