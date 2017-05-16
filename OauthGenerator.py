import urllib.request
import urllib.parse
import urllib.error
import json
import re


class UCWAApplication:
    def __init__(self, userID, pwd, userAgent, endpointID):
        self.userID = userID
        self.pwd = pwd
        self.userAgent = userAgent
        self.endpointID = endpointID
        self.culture = 'en-US'
        self.rootDomain = ''
        self.oauthToken = ''
        self.application = {}
        self.meTasks = {}
        self.peopleTasks = {}
        self.Communication = {}

    def StartApplication(self):
        """Create the application and store it for use. This needs to be called before any of the below commands."""
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'

        userLinks = self.getDiscovery()
        userAuth = userLinks['_links']['user']['href']
        oauthURL = self._urlHelper('GET', userAuth, self.oauthToken)
        oauthResponse = self.getToken(oauthURL)
        oauthToken = oauthResponse['access_token']
        oauthURL = self._urlHelper('GET', userAuth, token=oauthToken)
        appLinks = json.loads(oauthURL)

        publicDomain = re.search(matchString, userLinks['_links']['self']['href'])
        localDomain = re.search(matchString, appLinks['_links']['self']['href'])
        if publicDomain.group(0) == localDomain.group(0):
            self.oauthToken = oauthToken # No changes in group necessary
            self.rootDomain = publicDomain.group(0)
        else: # Different domains, need to correct pool error
            oauthURL = self._urlHelper('GET', appLinks['_links']['self']['href'], token='')
            newToken = self.getToken(oauthURL)
            self.oauthToken = newToken['access_token']
            self.rootDomain = localDomain.group(0)

        appURL = appLinks['_links']['applications']['href']
        appData = {'UserAgent':self.userAgent, 'EndpointId':self.endpointID, 'Culture':self.culture}
        rawApp = self._urlHelper('POST', appURL, self.oauthToken, msg=appData)
        self.application = json.loads(rawApp)
        self.meTasks = self.application['_embedded']['me']['_links']
        self.peopleTasks = self.application['_embedded']['people']['_links']
        self.Communication = self.application['_embedded']['communication']['_links']
## End creating application
## Begin Application Tasks
    def GetPresence(self, sip):
    # Get the presence data of a contact
        uri = '{}/{}/presence'.format(self.peopleTasks['self']['href'], sip)
        try:
            data = self._urlHelper('GET', self.rootDomain+uri, self.oauthToken)
            return data
        except urllib.error.HTTPError as err:
            HandleHTTPResponse().Handler(err)

    """ TODO
    def ContactSubscription(self, duration, *args):
    # Subscribe presence data of a contact
        uris = ['sip:{}'.format(arg) for arg in args]
        msg = {"duration":duration, "Uris":uris}
    """

    def StartMessaging(self, sip, importance='Normal', context='', subject='New Message'):
        data = {
          "importance":importance,
          "sessionContext":context,
          "subject":subject,
          "telemetryId":None,
          "to":sip,
          "operationId":self.endpointID
        }
        messageuri = self.rootDomain+self.Communication['_links']['startMessaging']['href']
        eventsuri = self.rootDomain+self.application['_links']['events']['href']
        self._urlHelper('POST', messageuri, self.oauthToken, msg=data)
        events = json.dumps(self._urlHelper('GET', eventsuri, self.oauthToken))

        while events['sender']['events']['_embedded']['messagingInvitation']['state'] == 'Connecting':
            nextEvent = events['_links']['next']['href']
            eventsuri = self.rootDomain+nextEvent
            # @Wait(1)
            events = json.dumps(self._urlHelper('GET', eventsuri, self.oauthToken))

        if events['sender']['events']['_embedded']['messagingInvitation']['state'] == 'Connected':
            val = events['_embedded']['messaging']['_links']['sendMessage']['href']
        else:
            val = False

        return val

    def SendMessage(self, message, url):
        if url:
            self._urlHelper('POST', self.rootDomain+url, self.oauthToken, msg=message)

    def StopMessaging(self, url):
        if url:
            self._urlHelper('POST', self.rootDomain+url, self.oauthToken)

# ----------------------------------------------------------------------------------------------------------------------
    def SetAvailable(self, resource, token):
        path = self.meTasks['makeMeAvailable']['href']
        msg = {'SupportedModalities': ["Messaging"]}
        return self._urlHelper('POST', resource + path, token, msg=msg)

    def UpdateTasks(self, qualifier, option=None):
        path = self.application['_links']['self']['href']
        if 'makeMeAvailable' in self.meTasks:
            self.SetAvailable(self.rootDomain, self.oauthToken)
            self.meTasks = json.loads(self._urlHelper('GET', self.rootDomain+path, self.oauthToken))['_embedded']['me']['_links']

        command = self.meTasks[qualifier]['href']
        if option:
            msg = {"availability":option}
            try:
                return self._urlHelper('POST', self.rootDomain+command, self.oauthToken, msg=msg)
            except urllib.error.HTTPError as err:
                HandleHTTPResponse().Handler(err)
        else:
            try:
                return self._urlHelper('GET', self.rootDomain+command, self.oauthToken)
            except urllib.error.HTTPError as err:
                HandleHTTPResponse().Handler(err)

##############################################################################
## Begin Helper Functions
## Helper functions are used by the above functions to create headers and make
## requests to the RESTful API. It is recommended that you do not change these
##############################################################################
    def _urlHelper(self, method, url, token, msg=None):
        request = urllib.request.Request(url)
        request.add_header('Authorization', 'Bearer {}'.format(token))
        request.add_header('Accept', 'application/json')
        if method == 'GET':
            pass # No data required to send
        elif method == 'POST': # Prepare data and headers
            request.add_header('Content-Type', 'application/json')
            payload = json.dumps(msg)
            request.data = payload.encode()
        try:
            with urllib.request.urlopen(request) as response:
                data = response.read().decode()
            if data != '':
                return data
            else:
                return {}
        except urllib.error.HTTPError as err:
            data = HandleHTTPResponse().Handler(err)
            return data

    def getDiscovery(self):
        try:
            handler = urllib.request.urlopen('https://lyncweb.extron.com/')
            content = json.loads(handler.read().decode())
            return content
        except urllib.error.HTTPError as err:
            HandleHTTPResponse().Handler(err)

    def getToken(self, url):
        authBody = urllib.parse.urlencode({
            "charset": "UTF-8",
            "grant_type": "password",
            "username": self.userID,
            "password": self.pwd
        })
        authHeaders = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': len(str(authBody))}
        request = urllib.request.Request(url, headers=authHeaders, data=authBody.encode())
        try:
            with urllib.request.urlopen(request) as response:
                token = response.read().decode()
                return json.loads(token)
        except urllib.error.HTTPError as err:
            HandleHTTPResponse().Handler(err)

    def Renewal(self):
        print('Renewing application')
        tokenURL = self.rootDomain + '/WebTicket/oauthtoken'
        appURL = self.rootDomain + '/ucwa/oauth/v1/applications'
        data = {'UserAgent':self.userAgent, 'EndpointId':self.endpointID, 'Culture':self.culture}

        self.oauthToken = self.getToken(tokenURL) # Renew the token
        self.application = json.loads(self._urlHelper('POST', appURL, self.oauthToken, msg=data)) # Update the Application


class HandleHTTPResponse:
    def __init__(self):
        user = None
        pwd = None
        agent = None
        ID = None
        self.update = UCWAApplication(user, pwd, agent, ID)

    def Handler(self, response):
        code = response.code
        if code == 200:
            pass
        elif code == 201:
            print('Application was created')
            pass
        elif code == 400:
            raise Exception('Bad Request -> The URL was invalid.')
        elif code == 401:
            return self.AuthHandler(response)
        elif code == 403:
            raise Exception('ERROR: You do not have access to the UCWA URL.')
        elif code == 404:
            print('Updating application')
            return self.UpdateApplication()
        elif code == 500:
            raise Exception('This is a problem with multiple realms. It should be corrected in the main application')
        elif code in range(400, 503):
            print('Unhandled Exception')
            raise urllib.error.HTTPError
        else:
            return 'An HTTP status was not found. Check your network connection.'

    def AuthHandler(self, response):
        data = str(response.hdrs)
        pattern = re.compile('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        url = pattern.search(data)
        return url.group(0)

    def UpdateApplication(self):
        return self.update.Renewal()
