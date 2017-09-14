from urllib import parse, request, error
from random import randint
import json
import re
import time

debug = True
if not debug:
    print = lambda *a, **k: None


class UCWA:
    def __init__(self, domain, userID, userPWD, UserAgent, EndpointId):
        domain = self._prepareDomain(domain)
        self.discoveryURL = 'https://lyncdiscover.{}'.format(domain)
        self.userID = userID
        self.userPWD = userPWD
        self.UserAgent = UserAgent
        self.EndpointId = EndpointId
        # Instantiate method objects used when application is created
        self.oauthToken = None
        self.createdApplication = {}
        self.meTasks = {}
        self.peopleTasks = {}
        self.meetingTasks = {}
        self.communicationTasks = {}
        self.rootDomain = None
        self.eventURL = None
        self.headers = {}
        self.contactDetails = {}

    ## --------------------------------------------------------------------------------------- ##
    ## Call this before doing anything else
    ## --------------------------------------------------------------------------------------- ##
    def StartApplication(self):
        """ Begin the application resource """
        print('StartApplication()')

        # 1. GET on the autodiscover server and grab 'user' URL
        userURLs = self._getUser()
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'
        self.rootDomain = re.search(matchString, userURLs["_links"]["user"]["href"]).group(0)
        # 2. GET on the 'user' URL
        authURL = self._authUser(userURLs["_links"]["user"]["href"])
        # 3. POST to Oauth with credentials (token in last step)
        self.oauthToken = self._getToken(authURL)
        # 4. GET as in 2., but this time with token. Grab the applications URL
        authResponse = json.loads(self._authUser(userURLs["_links"]["user"]["href"]))
        # 5. POST to the applications URL and it should return application.
        appData = {'UserAgent': self.UserAgent, 'EndpointId': self.EndpointId, 'Culture': "en-US"}
        self.createdApplication = json.loads(
            self._httpRequestHelper('POST', authResponse["_links"]["applications"]["href"], appData))
        # Store the created data into manageable dictionaries we can point to the main application
        self.meTasks = self.createdApplication["_embedded"]["me"]["_links"]
        self.peopleTasks = self.createdApplication["_embedded"]["people"]["_links"]
        self.meetingTasks = self.createdApplication["_embedded"]["onlineMeetings"]["_links"]
        self.communicationTasks = self.createdApplication["_embedded"]["communication"]["_links"]
        self.eventURL = self.createdApplication["_links"]["events"]["href"]
        print('Event URL, ', self.eventURL)  # Proof the application was created

    ## --------------------------------------------------------------------------------------- ##
    ## Calls to be made by the user once application is created
    ## --------------------------------------------------------------------------------------- ##
    def GetPresence(self, sip):
        print('GetPresence(sip={})'.format(sip))
        url = self.rootDomain + self.peopleTasks['self']['href'] + '/' + sip + '/presence'
        return self._httpRequestHelper('GET', url)

    def OpenChannel(self, sip, context=None):
        """ Open a channel to begin sending/receiving messages to a specific contact """
        print('OpenChannel(sip={}, context={})'.format(sip, context))
        state = None
        messageOptions = None
        # Create a context for this conversation if none is provided. This is an arbitrary 6-digit str
        if not context:
            context = str(randint(10 ** (6 - 1), (10 ** 6) - 1))
        data = {
            "importance": "Normal",
            "sessionContext": context,
            "subject": "Sample Subject",
            "telemetryId": None,
            "to": "sip:{}".format(sip),
            "operationId": self.EndpointId
        }
        msgURL = self.rootDomain + self.communicationTasks["startMessaging"]["href"]
        print('msgURL=', msgURL)
        resp = self._httpRequestHelper('POST', msgURL, data)
        print('resp=', resp)

        # the Event url should be update on each call once the conversation has been opened
        newEvent = self._updateEvents()
        convStatus = self._searchResponse(newEvent, 'sender', 'state')

        # Check if the conversation is still connecting
        while convStatus == 'Connecting':
            newEvent = self._updateEvents()
            convStatus = self._searchResponse(newEvent, 'sender', 'state')
            time.sleep(1)  # Wait for a short time and check if it has connected

        # Check the status of the conversation for errors
        for item in newEvent["sender"]:
            for keyword in item["events"]:
                state = keyword.get('status', None)

        # If a successful connection is established, store the urls for communication
        if state == 'Success':
            print('Success')
            for item in newEvent["sender"]:
                for x in item["events"]:
                    if "_embedded" in x and "messaging" in x["_embedded"]:
                        messageOptions = x["_embedded"]["messaging"]["_links"]
                    else:
                        continue
        else:
            print('state != \'Success\'')
            print('newEvent=', newEvent)
            print('convStatus=', convStatus)
            print('Server error - {}'.format(state))

        return messageOptions

    def Message(self, messageOptions, option, text=None):
        """ send, stop, or view the current channel. option parameter accepts keys from the OpenChannel dictionary.
            These are: sendMessage, stopMessaging, conversation, and self"""
        print('Message(messageOptions={}, option={}, text={})'.format(messageOptions, option, text))
        if messageOptions is None:
            raise TypeError('messageOptions cannot be None')

        url = self.rootDomain + messageOptions[option]["href"]
        print("url, ", url)
        headers = {'Content-Type': "text/plain",
                   'Accept': "application/json",
                   'Authorization': "Bearer {}".format(self.oauthToken)}

        if not isinstance(text, bytes):
            text = text.encode()

        msgRequest = request.Request(url, data=text, headers=headers)
        with request.urlopen(msgRequest) as response:
            self._updateEvents()
            data = response.read().decode()
        return data if data else ''

    def GetMessage(self):
        print('GetMessage()')
        # Open the Event channel and store the data
        rel = self._updateEvents()
        # Return a dictionary containing information about the last incoming message
        return self.processEvent(rel)

    def UpdateContactList(self):
        print('UpdateContactList()')
        contactDetails = {}
        url = self.rootDomain + self.peopleTasks['myContacts']['href']
        d = json.loads(self._httpRequestHelper('GET', url))
        contactList = d['_embedded']['contact']
        for contact in contactList:
            eMail = contact['emailAddresses'] if 'emailAddresses' in contact else None
            mPhone = contact['mobilePhoneNumber'] if 'mobilePhoneNumber' in contact else None
            wPhone = contact['workPhoneNumber'] if 'workPhoneNumber' in contact else None
            uri = contact['uri'][4:]
            contactDetails[contact['name']] = {'emailAddresses': eMail,
                                               'mobile': mPhone,
                                               'work': wPhone,
                                               'uri': uri}
        self.contactDetails = contactDetails
        return contactDetails

    def GetContactDetails(self, name):
        print('GetContactDetails(name={})'.format(name))
        searchResponse = {}
        for key in self.contactDetails:
            if name in key:
                searchResponse[key] = self.contactDetails[key]
        return searchResponse

    ## --------------------------------------------------------------------------------------- ##
    ## Internal methods for preparing and formatting information
    ## --------------------------------------------------------------------------------------- ##
    def processEvent(self, evtDict):
        print('processEvent(evtDict={})'.format(evtDict))
        """ Check an event dictionary for message information """

        responseData = {}
        getContact = r'(people/)(.*)'
        getTimeStamp = r'\d{13}'
        getTypingStatus = r'(participants/)(.*)'
        message = None
        status = None
        typingStatus = None
        # Check the dictionary for error status as well as message information
        for item in evtDict['sender']:
            for key in item['events']:
                if '_embedded' in key:
                    message = key['_embedded']['message']
                if 'status' in key:
                    status = key['status']
                if 'in' in key and key['in']['rel'] == 'typingParticipants':
                    typingStatus = key['link']['href']

        if typingStatus:
            fromContact = re.search(getTypingStatus, typingStatus)
            responseData['From'] = fromContact
            responseData['Status'] = 'IsTyping'

        if message:
            fromContact = message['_links']['contact']['href']
            text = message['_links']['plainMessage']['href']
            timeStamp = message['timeStamp']

            # Data is encoded but is handled as a string. Process text in a custom method
            text = self._decodeResponse(text)

            fromContact = re.search(getContact, fromContact).group(2)
            timeStamp = re.search(getTimeStamp, timeStamp).group(0)

            # Convert from epoch time to standard date/time format
            s, ms = divmod(int(timeStamp), 1000)
            curTime = '{}.{:03d}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(s)), ms)

            # Build the response dictionary
            responseData['From'] = fromContact
            responseData['Message'] = text
            responseData['Time'] = curTime
            responseData['Status'] = status

        if not typingStatus and not message:
            responseData['Status'] = 'Keep-Alive'

        return responseData

    def _httpRequestHelper(self, method, url, payload=None):
        print('_httpRequestHelper(method={}, url={}, payload={})'.format(method, url, payload))
        self.headers = {
            'Accept': "application/json",
        }

        if self.oauthToken:  # Prepare the appropriate headers if token has been generated
            self.headers['Authorization'] = "Bearer {}".format(self.oauthToken)

        if method == 'POST':
            if payload and isinstance(payload, dict):
                payload = json.dumps(payload)
                self.headers['Content-Type'] = "application/json"
            else:
                self.headers['Content-Type'] = "application/x-www-form-urlencoded;charset='utf-8'"

        if payload and not isinstance(payload, bytes):  # Prepare the payload, if it exists
            payload = payload.encode()
        myRequest = request.Request(url, data=payload, headers=self.headers, method=method)
        try:
            with request.urlopen(myRequest) as response:
                data = response.read().decode()
        except error.HTTPError as err:
            data = self._handleExceptionResponse(err, url)
        except error.URLError as err:
            raise Exception('The server timed out: {}'.format(err.reason))
        except Exception as err:
            raise Exception('An unknown error occurred: {}'.format(err))

        return data if data else None

    def _handleExceptionResponse(self, err, url):
        print('_handleExceptionResponse(err={}, url={})'.format(err, url))
        code = err.code
        if code == 401:
            return self._authHandler(err)
        elif code == 404:
            print('Updating application')
            return self._updateApplication()
        elif not self.createdApplication and code == 500:
            return self._updateTokenDomain(url)
        else:
            raise Exception('HTTP response error: code:{} - reason:{} - url:{}'.format(err.code, err.reason, url))

    def _prepareDomain(self, val):
        print('_prepareDomain(val={})'.format(val))
        url = parse.urlparse(val)
        if url.netloc:
            val = url.netloc.replace("www.", "")
        else:
            val = url.path.replace("www.", "")
        return val

    def _getUser(self):
        print('_getUser()')
        return json.loads(self._httpRequestHelper('GET', self.discoveryURL))

    def _authUser(self, url):
        print('_authUser(url={})'.format(url))
        return self._httpRequestHelper('GET', url=url)

    def _getToken(self, url):
        print('_getToken(url={})'.format(url))
        loginData = parse.urlencode({
            "charset": "UTF-8",
            "grant_type": "password",
            "username": self.userID,
            "password": self.userPWD
        })
        loginData = loginData.encode()
        token = json.loads(self._httpRequestHelper('POST', url, loginData))
        return token["access_token"]

    def _updateTokenDomain(self, url):
        print('_updateTokenDomain(url={})'.format(url))
        # Don't recall the request with the HTTP helper method here in case there is an actual 500 error (it will loop)
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'
        self.rootDomain = re.search(matchString, url).group(0)
        tokenurl = self.rootDomain + '/WebTicket/oauthtoken'
        self.oauthToken = self._getToken(tokenurl)
        appData = json.dumps({'UserAgent': self.UserAgent, 'EndpointId': self.EndpointId, 'Culture': "en-US"})
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json',
                   'Authorization': 'Bearer {}'.format(self.oauthToken)}
        myRequest = request.Request(url, data=appData.encode(), headers=headers, method='POST')
        with request.urlopen(myRequest) as response:
            data = response.read().decode()
        return data

    def _authHandler(self, response):
        print('_authHandler(response={})'.format(response))
        data = str(response.hdrs)
        pattern = re.compile('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        url = pattern.search(data)
        return url.group(0)

    def _updateApplication(self):
        pass

    def _searchResponse(self, adict, key, value):
        print('_searchResponse(adict={}, key={}, value={})'.format(adict, key, value))
        status = None
        for item in adict[key]:
            for x in item['events']:
                if '_embedded' in x and 'conversation' in x['_embedded']:
                    status = x['_embedded']['conversation'][value]
                else:
                    continue
        return status if status else None

    def _updateEvents(self):
        print('_updateEvents()')
        url = self.rootDomain + self.eventURL
        eventLog = self._httpRequestHelper('GET', url)
        if eventLog:
            eventLog = json.loads(eventLog)
            self.eventURL = eventLog["_links"]["next"]["href"]

        print('eventLog=', eventLog)
        return eventLog

    def _decodeResponse(self, string):
        print('_decodeResponse(string={})'.format(string))
        matchString = r"charset=(.{1,})[,](\S{0,})"
        mObj = re.search(matchString, string)
        encoding = mObj.group(1)
        message = mObj.group(2)
        # The HTTP requests return encoded strings, but as string literals. This means Python built in functions won't
        # Work to process them. Instead it is parsed manually here
        if encoding == 'utf-8':
            message = " ".join(message.split('+'))

        return message

    ## --------------------------------------------------------------------------------------- ##
    ## Useful for debugging
    ## --------------------------------------------------------------------------------------- ##
    def callToken(self):
        return self.oauthToken

    def callApplication(self):
        return self.createdApplication
