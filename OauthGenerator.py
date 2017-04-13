from extronlib.system import Wait
import urllib.request
import urllib.parse
import json
import re

## TODO: Update the error handler function by subclassing the HTTPError

class OauthHandler:
    def __init__(self):
        self.discovery = 'https://lyncdiscoverinternal.extron.com/'
        self.oauthToken = ''
        self.locDomain = None
        self.application = {}
        self.meTasks = {}
        self.peopleTasks = {}
    
    def StartApplication(self, userID, pwd, userAgent, endpointID, culture='en-US'):
        # Run a GET request on the discovery URL to find the user URLs
        userLinks = self.getDiscovery()
        userAuth = userLinks['_links']['user']['href'] # User discovery URLs
        oauthURL = self._urlHelper('GET', userAuth, self.oauthToken) # GET authentication url
        
        # Prepare the data and headers to get the token, then POST to the oauthURL
        oauthResponse = self.getToken(oauthURL, userID, pwd)
        oauthToken = oauthResponse['access_token']
        
        # Send the original GET request with the token header set
        rawStr = self._urlHelper('GET', userAuth, token=oauthToken)
        appLinks = json.loads(rawStr)
        
        # Check if the token is in the same application pool as the root pool
        # If not, we need to generate a new token or we will get a 500 error
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'
        pubDomain = re.search(matchString, userLinks['_links']['self']['href'])
        locDomain = re.search(matchString, appLinks['_links']['self']['href'])
        self.locDomain = locDomain.group(0)
        if pubDomain.group(0) == locDomain.group(0):
            self.oauthToken = oauthToken
            print(self.oauthToken)
        else:
            locOauthURL = self._urlHelper('GET', appLinks['_links']['self']['href'], token='') 
            locOauth = self.getToken(locOauthURL, userID, pwd)
            self.oauthToken = locOauth['access_token']
            print(self.oauthToken)
            
        # POST the corrected token to the application URL to generate the application
        appURL = appLinks['_links']['applications']['href']
        appData = {'UserAgent':userAgent, 'EndpointId':endpointID, 'Culture':culture}
        self.application = self._urlHelper('POST', appURL, self.oauthToken, msg=appData)
        self.meTasks = self.application['_embedded']['me']['_links']
        self.peopleTasks = self.application['_embedded']['people']['_links']
        print(self.application)  
          
    # Opener function to get the public domain links
    def getDiscovery(self):
        contentHandler = urllib.request.urlopen(self.discovery)
        content = json.loads(contentHandler.read().decode())
        return content
           
            
    # Helper for the GET and POST requests when starting the application    
    def _urlHelper(self, _method, url, token, msg = None):
        if _method == 'GET':
            headers = {
                'Authorization': 'Bearer {}'.format(token),
                'Accept': 'application/json'
            }
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request) as response:
                    data = response.read().decode()
                    return data
            except urllib.error.HTTPError as err:
                if err.code == 401:
                    data = self.handleAuth(err)
                    return data
            else:
                raise err
        elif _method == 'POST':
            headers = {
                'Authorization': 'Bearer {}'.format(token),
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            payload = json.dumps(msg)
            request = urllib.request.Request(url, headers=headers, data=payload.encode())
            try:
                with urllib.request.urlopen(request) as response:
                    data = response.read().decode()
                if data != '':
                    return json.loads(data)
                else:
                    return {}
            except urllib.error.HTTPError as err:
                print('HTTPError {}'.format(err.code))
            except urllib.error.URLError as err:
                print('URL error: {}'.format(err.message)) # Handle URL not found error
            else:
                raise err
         
         
    # Handles authentication for 401 errors during the startApplication process        
    def handleAuth(self, eobj):
        errheaders = str(eobj.hdrs)
        pattern = re.compile('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        authURL = pattern.search(errheaders) 
        return authURL.group(0)  

    
    def getToken(self, url, userId, pwd):
        authBody = urllib.parse.urlencode({
            "charset": "UTF-8", 
            "grant_type": "password", 
            "username": userId, 
            "password": pwd
        })
        authHeaders = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': len(str(authBody))}
        request = urllib.request.Request(url, headers=authHeaders, data=authBody.encode())
        with urllib.request.urlopen(request) as response:
            token = response.read().decode()
            return json.loads(token)
            
# Get/Set self presence data
    def setAvailable(self, resource, token):
        path = self.meTasks['makeMeAvailable']['href']
        msg = {'SupportedModalities': ["Messaging"]}
        return self._urlHelper('POST', resource + path, token, msg=msg)


    def UpdateTasks(self, qualifier, option=None):
        path = self.application['_links']['self']['href']
        if 'makeMeAvailable' in self.meTasks:
            print('setAvailable triggered')
            self.setAvailable(self.locDomain, self.oauthToken)
            self.meTasks = self._urlHelper('GET', self.locDomain+path, self.oauthToken)

        command = self.meTasks[qualifier]['href']
        if option:
            msg = {"availability":option}
            return self._urlHelper('POST', self.locDomain+command, self.oauthToken, msg=msg)
        else:
            return self._urlHelper('GET', self.locDomain+command, self.oauthToken)

# Get Presence data of a contact
    def GetPresence(self, sip):
        uri = '{}/{}/presence'.format(self.peopleTasks['self']['href'], sip)
        print('uri: ' + uri)
        data = self._urlHelper('GET', self.locDomain+uri, self.oauthToken)
        print(data)
        # https://rnc-l13-webvip.extron.com/ucwa/oauth/v1/applications/102869412579/people/jhudson@extron.com/presence

# Subscribe presence data of a contact
    def ContactSubscription(self, duration, *args):
        uris = ['sip:{}'.format(arg) for arg in args]
        msg = {"duration":duration, "Uris":uris}
