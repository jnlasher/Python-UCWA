import urllib.request
import urllib.parse
import json
import re

## TODO: Update the error handler function by subclassing the HTTPError

class OauthHandler:
    def __init__(self):
        self.discovery = 'https://lyncdiscoverinternal.extron.com/'
        self.oauthToken = None
        self.application = None
        
    
    def startApplication(self, userID, pwd, userAgent, endpointID, culture='en-US'):
        # Run a GET request on the discovery URL to find the user URLs
        userLinks = self.getDiscovery()
        userAuth = userLinks['_links']['user']['href'] # User discovery URLs
        oauthURL = self._urlHelper('GET', userAuth) # GET authentication url
        
        # Prepare the data and headers to get the token, then POST to the oauthURL
        authBody = urllib.parse.urlencode({"charset": "UTF-8", "grant_type": "password", "username": userID, "password": pwd})
        authHeaders = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': len(str(authBody))}
        oauthResponse = self._urlHelper('POST', oauthURL, payload=authBody, headers=authHeaders)
        oauthToken = oauthResponse['access_token']
        
        # Send the original GET request with the token header set
        tokenHeader = {'Authorization': "Bearer {}".format(oauthToken)}
        rawStr = self._urlHelper('GET', userAuth, headers=tokenHeader)
        appLinks = json.loads(rawStr)
        
        # Check if the token is in the same application pool as the root pool
        # If not, we need to generate a new token or we will get a 500 error
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'
        pubDomain = re.search(matchString, userLinks['_links']['self']['href'])
        locDomain = re.search(matchString, appLinks['_links']['self']['href'])  
        if pubDomain.group(0) == locDomain.group(0):
            print('Correct pool')
            self.oauthToken = oauthToken
            
        else:
            print('Incorrect pool')
            locOauthURL = self._urlHelper('GET', appLinks['_links']['self']['href']) 
            locOauth = self._urlHelper('POST', locOauthURL, payload=authBody, headers=authHeaders)
            self.oauthToken = locOauth['access_token']
            print(self.oauthToken)
            
        # POST the corrected token to the application URL to generate the application
        appURL = appLinks['_links']['applications']['href']
        appHeaders = {
            'authorization': "Bearer {}".format(self.oauthToken),
            'content-type': "application/json",
            'cache-control': "no-cache"}
        appData = json.dumps({'UserAgent':userAgent, 'EndpointId':endpointID, 'Culture':culture})
        rawApp = self._urlHelper('POST', appURL, payload=appData, headers=appHeaders)
        print(self.application)
        
    # Opener function to get the public domain links
    def getDiscovery(self):
        contentHandler = urllib.request.urlopen(self.discovery)
        content = json.loads(contentHandler.read().decode())
        return content
        
    # Helper for the GET and POST requests when starting the application    
    def _urlHelper(self, _method, url, payload = None, headers = {}):
        if _method == 'GET':
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request) as response:
                    data = response.read().decode()
                    return data
            except urllib.error.HTTPError as err:
                if err.code == 401:
                    data = self.handleAuth(err)
                    return data
        elif _method == 'POST':
            request = urllib.request.Request(url, headers=headers, data=payload.encode())
            with urllib.request.urlopen(request) as response:
                data = response.read().decode()
            handler = json.loads(data)
            return handler
            
    # Handles authentication for 401 errors during the startApplication process        
    def handleAuth(self, eobj):
        errheaders = str(eobj.hdrs)
        pattern = re.compile('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        authURL = pattern.search(errheaders) 
        return authURL.group(0)
