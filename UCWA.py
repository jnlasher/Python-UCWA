from urllib import parse, request, error
from random import randint
import json
import re
import time
import zlib

debug = True
if not debug:
    print = lambda *a, **k: None

class SkypeClient:
    def __init__(self, domain, userID, userPWD, EndpointId):
        domain = self._prepareDomain(domain)
        print(domain)
        self.discoveryURL = 'https://lyncdiscover.{}'.format(domain)
        self.userID = userID
        self.userPWD = userPWD
        self.UserAgent = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
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

        # Status Feedback
        self.SearchResults = []
        self.ContactsList = []

    ## --------------------------------------------------------------------------------------- ##
    ## Call this before doing anything else
    ## --------------------------------------------------------------------------------------- ##
    def StartApplication(self):
        """ Begin the application resource """

        # 1. GET on the autodiscover server and grab 'user' URL
        userURLs = self._getUser()
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'
        self.rootDomain = re.search(matchString, userURLs["_links"]["user"]["href"]).group(0)
        # 2. GET on the 'user' URL
        authURL = self._authUser(userURLs["_links"]["user"]["href"])
        # 3. POST to Oauth with credentials (token in last step)
        if not self.oauthToken:
            self.oauthToken = self._getToken(authURL)
            # 4. GET as in 2., but this time with token. Grab the applications URL
            self.authResponse = json.loads(self._authUser(userURLs["_links"]["user"]["href"]))
        # 5. POST to the applications URL and it should return application.
        appData = {'UserAgent':self.UserAgent, 'EndpointId':self.EndpointId, 'Culture':"en-US"}
        self.createdApplication = json.loads(self._httpRequestHelper('POST', self.authResponse["_links"]["applications"]["href"], appData))
        # Store the created data into manageable dictionaries we can point to the main application
        #print(self.createdApplication)
        self.UserName = self.createdApplication["_embedded"]["me"]['name']
        self.meTasks = self.createdApplication["_embedded"]["me"]["_links"]
        #print(self.meTasks)
        self.peopleTasks = self.createdApplication["_embedded"]["people"]["_links"]
        #print(self.peopleTasks)
        self.meetingTasks = self.createdApplication["_embedded"]["onlineMeetings"]["_links"]
        #print(self.meetingTasks)
        self.communicationTasks = self.createdApplication["_embedded"]["communication"]["_links"]
        #print(self.communicationTasks)
        self.eventURL = self.createdApplication["_links"]["events"]["href"]
        print('Event URL, ', self.eventURL) # Proof the application was created
        if 'makeMeAvailable' in self.meTasks:
            self.makeMeAvailable()

    ## --------------------------------------------------------------------------------------- ##
    ## Calls to be made by the user once application is created
    ## --------------------------------------------------------------------------------------- ##
    # Me Tasks Section
    def getMe(self):
        return self.UserName

    def callForwardingSettings(self):
        url = self.rootDomain + self.meTasks['callForwardingSettings']['href']
        return self._httpRequestHelper('GET', url)

    def makeMeAvailable(self):
        url = self.rootDomain + self.meTasks['makeMeAvailable']['href']
        data = {'signInAs': 'Online'}
        # Sets the User Available to the server to enable actions
        self._httpRequestHelper('POST', url, data)
        # Reload StartApplication to pull content
        self.StartApplication()

    def reportMyActivity(self):
        if 'reportMyActivity' in self.meTasks:
            url = self.rootDomain + self.meTasks['reportMyActivity']['href']
            return self._httpRequestHelper('POST', url)

    # This returns the image of self user
    def myPhoto(self):
        url = self.rootDomain + self.meTasks['photo']['href']
        return self._httpRequestHelper('GET', url)

    # Returns users primary number
    def phones(self):
        url = self.rootDomain + self.meTasks['phones']['href']
        request = json.loads(self._httpRequestHelper('GET', url))
        return request['_embedded']['phone'][0]['number']

    def getLocation(self):
        url = self.rootDomain + self.meTasks['location']['href']
        request = json.loads(self._httpRequestHelper('GET', url))
        print(request)
        return request['location']

    def setLocation(self, location): # Has not been tested
        url = self.rootDomain + self.meTasks['location']['href']
        data = {'location': location}
        self._httpRequestHelper('POST', url, data)

    def getNote(self):
        url = self.rootDomain + self.meTasks['note']['href']
        request = json.loads(self._httpRequestHelper('GET', url))
        return request['message']

    def setNote(self, note):
        url = self.rootDomain + self.meTasks['note']['href']
        data = {'message': note}
        self._httpRequestHelper('POST', url, data)

    def getPresence(self):
        url = self.rootDomain + self.meTasks['presence']['href']
        return json.loads(self._httpRequestHelper('GET', url))['availability']

    def setPresence(self, value): # Need to add some form of check for MakeMeAvailable
        values = ['Away', 'BeRightBack', 'Busy', 'DoNotDisturb', 'Offwork', 'Online']

        if value in values:
            url = self.rootDomain + self.meTasks['presence']['href']
            data = {'availability': value}
            self._httpRequestHelper('POST', url, data)
        else:
            raise KeyError('Value not valid')

    # This is for contacts number
    def processNumber(self, num):
        if len(num) != 4:
            return num[:-4]
        return num

    # People Tasks Section
    def myContacts(self):
        # Clear Contact list if there was already data
        if len(self.ContactsList) > 0: del self.ContactsList[:]

        url =self.rootDomain + self.peopleTasks['myContacts']['href']
        contactResults = json.loads(self._httpRequestHelper('GET', url))['_embedded']['contact']
        print(contactResults)
        for contact in contactResults:
            try:
                card = {'name': contact['name'],
                        'title': contact['title'] if 'title' in contact else None,
                        'department': contact['department']if 'department' in contact else None,
                        'extention': self.processNumber(contact['workPhoneNumber']) if 'workPhoneNumber' in contact else None,
                        'presence': self.rootDomain + contact['_links']['contactPresence']['href'] if 'contactPresence' in contact else None,
                        'email': contact['emailAddresses'][0]if 'emailAddresses' in contact else None,
                        'mobile': contact['mobilePhoneNumber'] if 'mobilePhoneNumber' in contact else None
                        }

                self.ContactsList.append(card)
            except Exception as e:
                print(e)
                print(contact)
                
        return self.ContactsList
                

    def myContactsAndGroupSubscription(self):
        pass

    def myGroupMemberships(self):
        pass

    def myPrivacyRelationships(self):
        pass

    def presenceSubscriptionMemberships(self):
        pass

    def presenceSubscriptions(self):
        pass

    # This will receive a precence URL and return the presence of the user
    def contactPrecence(self, url):
        packet = json.loads(self._httpRequestHelper('GET', url))

        data = {'availability': packet['availability'],
                'activity': packet['activity'] if 'activity' in packet else None
                }

        return data

    # Search Directory for incoming call number
    def incomingCallSearch(self, text):
        text = text.replace(' ', '%20')  # Convert Space to hex for the url
        url = self.rootDomain + self.peopleTasks['search']['href']+'?query='+text+'&limit='+str(2)  # Format URL

        # Returned Data
        searchResult = json.loads(self._httpRequestHelper('GET', url))['_embedded']['contact']

        contactData = json.loads(self._httpRequestHelper('GET', self.rootDomain + searchResult[1]['_links']['self']['href']))

        card = {'name': contactData['name'],
                'title': contactData['title'],
                'department': contactData['department'],
                'extention': self.processNumber(contactData['workPhoneNumber']),
                'presence': self.rootDomain + contactData['_links']['contactPresence']['href'],
                'email': contactData['emailAddresses'][0],
                'mobile': contactData['mobilePhoneNumber'] if 'mobilePhoneNumber' in contactData else None
                }

        return card

    def search(self, text, limit=10):
        del self.SearchResults[:]  # Clears the Search Result List
        text = text.replace(' ', '%20')  # Convert Space to hex for the url
        url = self.rootDomain + self.peopleTasks['search']['href']+'?query='+text+'&limit='+str(limit)  # Format URL

        # Returned Data
        searchResult = json.loads(self._httpRequestHelper('GET', url))['_embedded']['contact']

        for contact in searchResult:

            contactData = json.loads(self._httpRequestHelper('GET', self.rootDomain + contact['_links']['self']['href']))

            card = {'name': contactData['name'],
                    'title': contactData['title'] if 'title' in contactData else None,
                    'department': contactData['department'] if 'department' in contactData else None,
                    'extention': self.processNumber(contact['workPhoneNumber']) if 'workPhoneNumber' in contactData else None,
                    'presence': self.rootDomain + contactData['_links']['contactPresence']['href'],
                    'email': contactData['emailAddresses'][0] if 'email' in contactData else None,
                    'mobile': contactData['mobilePhoneNumber'] if 'mobilePhoneNumber' in contactData else None
                    }
            self.SearchResults.append(card)


    def subscribedContacts(self):
        pass

    # Online Meeting Task Section
    def myOnlineMeetings(self):
        url = self.rootDomain + self.meetingTasks['myOnlineMeetings']['href']
        print(url)
        # single = json.loads(self._httpRequestHelper('GET', url))['_embedded']['myAssignedOnlineMeeting'][0]['_links']['self']['href']
        # return self._httpRequestHelper('GET', self.rootDomain + single)
        return json.loads(self._httpRequestHelper('GET', url))['_embedded']['myOnlineMeeting']

    def onlineMeetingDefaultValues(self):
        pass

    def onlineMeetingEligibleValues(self):
        pass

    def onlineMeetingInvitationCustomization(self):
        pass

    def onlineMeetingPolicies(self):
        pass

    def phoneDialInInformation(self):
        url = self.rootDomain + self.meetingTasks['phoneDialInInformation']['href']
        return self._httpRequestHelper('GET', url)

    def OpenChannel(self, sip, context=None):
        """ Open a channel to begin sending/receiving messages to a specific contact """
        state = None
        messageOptions = None
        # Create a context for this conversation if none is provided. This is an arbitrary 6-digit str
        if not context:
            context = str(randint(10**(6-1), (10**6)-1))
        data = {
            "importance":"Normal",
            "sessionContext":context,
            "subject":"IM from{}".format(self.UserName),
            "telemetryId":None,
            "to":"sip:{}".format(sip),
            "operationId":self.EndpointId
        }
        msgURL = self.rootDomain + self.communicationTasks["startMessaging"]["href"]
        self._httpRequestHelper('POST', msgURL, data)
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
                if 'status' in keyword:
                    state = keyword['status']
                else:
                    state = None

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
            print('Server error - {}'.format(state))
        print(messageOptions)
        return messageOptions if messageOptions else None

    def Message(self, messageOptions, option, text=None):
        """ send, stop, or view the current channel. option parameter accepts keys from the OpenChannel dictionary.
            These are: sendMessage, stopMessaging, conversation, and self"""

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
        # Open the Event channel and store the data
        rel = self._updateEvents()
        # Return a dictionary containing information about the last incoming message
        return self.processEvent(rel)

    ## --------------------------------------------------------------------------------------- ##
    ## Internal methods for preparing and formatting information
    ## --------------------------------------------------------------------------------------- ##
    def processEvent(self, evtDict):
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

    # Account for gzip compression for faster HTTP GET request responses
    def _httpRequestHelper(self, method, url, payload=None):
        self.headers = {
            'Accept': "application/json",
            'Connection': "keep-alive",
            'Accept-Encoding': "gzip, deflate"
        }
        data = None
        if self.oauthToken:  # Prepare the appropriate headers if token has been generated
            self.headers['Authorization'] = "Bearer {}".format(self.oauthToken)

        if method == 'POST':
            if 'Accept-Encoding' in self.headers: self.headers.pop('Accept-Encoding')

            if payload and isinstance(payload, dict):
                payload = json.dumps(payload)

                self.headers['Content-Type'] = "application/json"
            elif payload == None:
                self.headers['Content-Length'] = 0
            else:
                self.headers['Content-Type'] = "application/x-www-form-urlencoded;charset='utf-8'"
        else:
            if 'Accept-Encoding' not in self.headers: self.headers['Accept-Encoding'] = "gzip, deflate"
        if payload and not isinstance(payload, bytes): # Prepare the payload, if it exists
            payload = payload.encode()
        myRequest = request.Request(url, data=payload, headers=self.headers, method=method)
        try:
            with request.urlopen(myRequest) as response:
                if 'Accept-Encoding' not in self.headers:
                    data = response.read().decode()
                else:
                    data = zlib.decompress(response.read(), 16 + zlib.MAX_WBITS).decode()
                #print(data.decode())
        except error.HTTPError as err:
            data = self._handleExceptionResponse(err, url)
        except error.URLError as err:
            raise Exception('The server timed out: {}'.format(err.reason))
        except UnicodeDecodeError:
            data = self._httpRequestHelper(method, url, payload)
        except Exception as err:
            raise Exception('An unknown error occurred: {}'.format(err))
        finally:
            return data if data else None

    def _handleExceptionResponse(self, err, url):
        code = err.code
        if code == 401:
            return self._authHandler(err)
        elif code == 404:
            print('Updating application')
            return self._updateApplication()
        elif not self.createdApplication and code == 500:
            return self._updateTokenDomain(url)
        else:
            raise Exception('HTTP response error: {} - {}'.format(err.code, err.reason))

    def _prepareDomain(self, val):
        url = parse.urlparse(val)
        if url.netloc:
            val = url.netloc.replace("www.", "")
        else:
            val = url.path.replace("www.", "")
        return val

    def _getUser(self):
        return json.loads(self._httpRequestHelper('GET', self.discoveryURL))

    def _authUser(self, url):
        return self._httpRequestHelper('GET', url=url)

    def _getToken(self, url):
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
        # Don't recall the request with the HTTP helper method here in case there is an actual 500 error (it will loop)
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'
        self.rootDomain = re.search(matchString, url).group(0)
        tokenurl = self.rootDomain + '/WebTicket/oauthtoken'
        self.oauthToken = self._getToken(tokenurl)
        appData = json.dumps({'UserAgent': self.UserAgent, 'EndpointId': self.EndpointId, 'Culture': "en-US"})
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer {}'.format(self.oauthToken)}
        myRequest = request.Request(url, data=appData.encode(), headers=headers, method='POST')
        with request.urlopen(myRequest) as response:
            data = response.read().decode()
        return data

    def _authHandler(self, response):
        data = str(response.hdrs)
        pattern = re.compile('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        url = pattern.search(data)
        return url.group(0)

    def _updateApplication(self):
        pass

    def _searchResponse(self, adict, key, value):
        status = None
        for item in adict[key]:
            for x in item['events']:
                if '_embedded' in x and 'conversation' in x['_embedded']:
                    status = x['_embedded']['conversation'][value]
                else:
                    continue
        return status if status else None

    def _updateEvents(self):
        url = self.rootDomain + self.eventURL
        eventLog = self._httpRequestHelper('GET', url)
        eventLog = json.loads(eventLog)
        self.eventURL = eventLog["_links"]["next"]["href"]

        print(eventLog)
        return eventLog

    def _decodeResponse(self, string):
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
