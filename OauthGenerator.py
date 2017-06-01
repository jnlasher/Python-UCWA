import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time
from random import randint


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
        self.communication = {}

    def StartApplication(self):
        """Create the application and store it for use. This needs to be called before any of the below commands."""
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'
        userLinks = self._GetDiscovery()
        userAuth = userLinks['_links']['user']['href']
        oauthURL = self._HTTPHelper('GET', userAuth, self.oauthToken)
        oauthResponse = self._GetToken(oauthURL)
        oauthToken = oauthResponse['access_token']
        oauthURL = self._HTTPHelper('GET', userAuth, token=oauthToken)
        appLinks = json.loads(oauthURL)

        publicDomain = re.search(matchString, userLinks['_links']['self']['href'])
        localDomain = re.search(matchString, appLinks['_links']['self']['href'])
        # This checks if the domains are different. If requests are made to the wrong server, a 500 error is returned
        if publicDomain.group(0) == localDomain.group(0):  # No changes in group necessary
            self.oauthToken = oauthToken
            self.rootDomain = publicDomain.group(0)
        else:                                              # Different domains, need to correct pool error
            oauthURL = self._HTTPHelper('GET', appLinks['_links']['self']['href'], token='')
            newToken = self._GetToken(oauthURL)
            self.oauthToken = newToken['access_token']
            self.rootDomain = localDomain.group(0)

        appURL = appLinks['_links']['applications']['href']
        appData = {'UserAgent':self.userAgent, 'EndpointId':self.endpointID, 'Culture':self.culture}
        rawApp = self._HTTPHelper('POST', appURL, self.oauthToken, msg=appData)
        # Store the main application dictionary, and subsequent dictionaries for requests
        self.application = json.loads(rawApp)
        self.meTasks = self.application['_embedded']['me']['_links']
        self.peopleTasks = self.application['_embedded']['people']['_links']
        self.communication = self.application['_embedded']['communication']['_links']
    ## End creating application ----------------------------------------------------------------------------------------
    ## Begin Application Tasks  ----------------------------------------------------------------------------------------
    def GetPresence(self, sip):
        """ This is used to get the presence information of a contact. You must pass the users SIP address. """

        uri = '{}/{}/presence'.format(self.peopleTasks['self']['href'], sip)
        try:
            data = self._HTTPHelper('GET', self.rootDomain+uri, self.oauthToken)
            return data
        except urllib.error.HTTPError as err:
            HandleHTTPResponse(self.userID, self.pwd, self.userAgent, self.endpointID).Handler(err)

    def StartMessaging(self, sip, importance='Normal', context=None, subject='New Message'):
        """ This begins messaging and creates a dictionary of URLs that can be used when calling the "Messaging" method.
        :param sip: The SIP address of the user
        :param importance: Importance level (defined by MS SFB in order of 'Normal', 'Low', or 'High')
        :param context: Required hex string to track the conversation. If none is entered, a random number is generated
        :param subject: Subject of the conversation. New Message is the default
        :return: Returns a dictionary with URLs for the conversation
        """

        if context is None: # Create a unique, 6-digit context id if none entered
            context = str(randint(10**(6-1), (10**6)-1))
        data = {
          "importance":importance,
          "sessionContext":context,
          "subject":subject,
          "telemetryId":None,
          "to":'sip:{}'.format(sip),
          "operationId":self.endpointID
        }
        messageURI = self.rootDomain+self.communication['startMessaging']['href']
        eventsURI = self.rootDomain+self.application['_links']['events']['href']
        self._HTTPHelper('POST', messageURI, self.oauthToken, msg=data)
        events = json.loads(self._HTTPHelper('GET', eventsURI, self.oauthToken))
        print('events data: {}'.format(events))
        status = self._FindResponse(events)

        while status == 'Connecting':
            nextEvent = self.rootDomain+events['_links']['next']['href']
            events = json.loads(self._HTTPHelper('GET', eventsURI, self.oauthToken))
            time.sleep(1)
            status = self._FindResponse(events)

        for item in events['sender']:
            for x in item['events']:
                if 'status' in x:
                    state = x['status']
                else:
                    state = None
        print('state: {}'.format(state))
        if state == 'Success':
            for item in events['sender']:
                for x in item['events']:
                    if '_embedded' in x and 'messaging' in x['_embedded']:
                        val = x['_embedded']['messaging']['_links']
                    else:
                        val = None

        print(val)
        return val

    def Messaging(self, messageDict, option, message=None):
        """ This handles the messaging operations, given by the "StartMessaging" method.
        Options are: conversation, self, sendMessage, setIsTyping, stopMessaging, typingParticipants
        If sendMessage is used, a message must be entered or the recipient will see a blank notification."""

        url = self.rootDomain + messageDict[option]['href']
        print('url: {}'.format(url))
        print('message: {}'.format(message))
        request = urllib.request.Request(url)
        request.add_header('Authorization', 'Bearer {}'.format(self.oauthToken))
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'text/plain')
        request.data = message.encode()
        with urllib.request.urlopen(request) as response:
            data = response.read().decode()
        if data != '':
            print(data)
        else:
            print('No data returned')


# ----------------------------------------------------------------------------------------------------------------------
    ## The below functions are used to handle the status of the connected user. This is the user that was identified
    ## when the class was instantiated.

    def SetAvailable(self, resource, token):
        """ Can be called by the user if desired, but will be called by the UpdateTasks method if necessary
        :param resource: Local domain for the server
        :param token: The token created by the application
        :return: sends a POST request to the availability resource and updates the dictionary
        """
        path = self.meTasks['makeMeAvailable']['href']
        msg = {'SupportedModalities': ["Messaging"]}
        return self._HTTPHelper('POST', self.rootDomain + path, token, msg=msg)

    def UpdateTasks(self, qualifier, option=None):
        """ Updates a resource of the connected user or gets a resource status. This will call the SetAvailable method
        if required to get any information.
        :param qualifier: A valid resource location; 'presence' is used for setting status
        :param option: Required only for setting status. Must be a valid MS SFB status
        :return: Returns the requested information from the user resource
        """
        path = self.application['_links']['self']['href']
        if 'makeMeAvailable' in self.meTasks:
            self.SetAvailable(self.rootDomain, self.oauthToken)
            self.meTasks = json.loads(self._HTTPHelper('GET', self.rootDomain+path, self.oauthToken))['_embedded']['me']['_links']

        command = self.meTasks[qualifier]['href']
        if option:
            msg = {"availability":option}
            try:
                return self._HTTPHelper('POST', self.rootDomain+command, self.oauthToken, msg=msg)
            except urllib.error.HTTPError as err:
                HandleHTTPResponse(self.userID, self.pwd, self.userAgent, self.endpointID).Handler(err)
        else:
            try:
                return self._HTTPHelper('GET', self.rootDomain+command, self.oauthToken)
            except urllib.error.HTTPError as err:
                HandleHTTPResponse(self.userID, self.pwd, self.userAgent, self.endpointID).Handler(err)

    ##############################################################################
    ## Begin Helper Functions
    ## Helper functions are used by the above functions to create headers and make
    ## requests to the RESTful API. It is recommended that you do not change these
    ##############################################################################
    def _HTTPHelper(self, method, url, token, msg=None):
        """ Handles HTTP requests that are used by the other methods. It sets appropriate headers and encodes data
        on POST requests. """
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
            data = HandleHTTPResponse(self.userID, self.pwd, self.userAgent, self.endpointID).Handler(err)
            return data

    def _GetDiscovery(self):
        """ Called when starting the application. Uses the discovery URL to find the domain of the server. """
        try:
            handler = urllib.request.urlopen('https://lyncdiscoverinternal.yourdomain.com/')
            content = json.loads(handler.read().decode())
            return content
        except urllib.error.HTTPError as err:
            HandleHTTPResponse(self.userID, self.pwd, self.userAgent, self.endpointID).Handler(err)

    def _GetToken(self, url):
        """ Gets a token for the application. This is required for all subsequent requests to the application. """
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
            HandleHTTPResponse(self.userID, self.pwd, self.userAgent, self.endpointID).Handler(err)

    def _FindResponse(self, eventDict):
        """ Helper function to find the messaging resource state. """
        for item in eventDict['sender']:
            for x in item['events']:
                if '_embedded' in x and 'conversation' in x['_embedded']:
                    status = x['_embedded']['conversation']['state']
                else:
                    continue
        return status if status else None

    def Renewal(self):
        """ This is used to update the application if it expires. """
        print('Renewing application')
        tokenURL = self.rootDomain + '/WebTicket/oauthtoken'
        appURL = self.rootDomain + '/ucwa/oauth/v1/applications'
        data = {'UserAgent':self.userAgent, 'EndpointId':self.endpointID, 'Culture':self.culture}
        print('Token URL: {}'.format(tokenURL))
        print('App URL: {}'.format(appURL))
        self.oauthToken = self._GetToken(tokenURL) # Renew the token
        self.application = json.loads(self._HTTPHelper('POST', appURL, self.oauthToken, msg=data)) # Update the Application

    def GetCurrent(self):
        """ Prints the current token and application resources. This is only required for debugging. """
        print(self.oauthToken)
        print(self.application)


class HandleHTTPResponse(UCWAApplication):
    """ This inherits from the MS SFB applications class and is used to handle the HTTP responses returned from the main
    class. """
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
        return self.Renewal()
