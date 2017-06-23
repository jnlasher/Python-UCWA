from urllib import parse, request, error
from random import randint
import json
import re
import time
import threading


class UCWA:
    def __init__(self, domain, userID, userPWD, UserAgent, EndpointId):
        domain = self.prepareDomain(domain)
        self.discoveryURL = 'https://lyncdiscover.{}'.format(domain)
        self.userID = userID
        self.userPWD = userPWD
        self.UserAgent = UserAgent
        self.EndpointId = EndpointId
        # Instantiate method objects used when application is created
        self.oauthToken = None
        self.createdApplication = None
        self.meTasks = None
        self.peopleTasks = None
        self.meetingTasks = None
        self.communicationTasks = None
        self.rootDomain = None
        self.eventURL = None
        self.Messaging = False

    ## --------------------------------------------------------------------------------------- ##
    ## Call this before doing anything else
    ## --------------------------------------------------------------------------------------- ##
    def StartApplication(self):
        # 1. GET on the autodiscover server and grab 'user' URL
        userURLs = self.getUser()
        matchString = 'https?:\/\/(?:[^\/]+)|^(.*)$'
        self.rootDomain = re.search(matchString, userURLs["_links"]["user"]["href"]).group(0)
        # 2. GET on the 'user' URL
        authURL = self.authUser(userURLs["_links"]["user"]["href"])
        # 3. POST to Oauth with credentials (token in last step)
        loginData = parse.urlencode({
            "charset": "UTF-8",
            "grant_type": "password",
            "username": self.userID,
            "password": self.userPWD
        })
        loginData = loginData.encode()
        token = json.loads(self._httpRequestHelper('POST', authURL, loginData))
        self.oauthToken = token["access_token"]
        # 4. GET as in 2., but this time with token. Grab the applications URL
        authResponse = json.loads(self.authUser(userURLs["_links"]["user"]["href"]))
        # 5. POST to the applications URL and it should return application.
        appData = {'UserAgent':self.UserAgent, 'EndpointId':self.EndpointId, 'Culture':"en-US"}
        self.createdApplication = json.loads(self._httpRequestHelper('POST', authResponse["_links"]["applications"]["href"], appData))
        # Store the created data into manageable dictionaries we can point to the main application
        self.meTasks = self.createdApplication["_embedded"]["me"]["_links"]
        self.peopleTasks = self.createdApplication["_embedded"]["people"]["_links"]
        self.meetingTasks = self.createdApplication["_embedded"]["onlineMeetings"]["_links"]
        self.communicationTasks = self.createdApplication["_embedded"]["communication"]["_links"]
        self.eventURL = self.createdApplication["_links"]["events"]["href"]
        print('Event URL, ', self.eventURL)

    ## --------------------------------------------------------------------------------------- ##
    ## Calls to be made by the user once application is created
    ## --------------------------------------------------------------------------------------- ##
    def OpenChannel(self, sip, context=None):
        if not context: # Create a context for this conversation if none is provided. This is an arbitrary 6-digit str
            context = str(randint(10**(6-1), (10**6)-1))
        data = {
            "importance":"Normal",
            "sessionContext":context,
            "subject":"Sample Subject",
            "telemetryId":None,
            "to":"sip:{}".format(sip),
            "operationId":self.EndpointId
        }
        msgURL = self.rootDomain + self.communicationTasks["startMessaging"]["href"]
        self._httpRequestHelper('POST', msgURL, data)
        newEvent = self.updateEvents() # the Event url should be update on each call once the conversation has been opened
        convStatus = self.searchResponse(newEvent, 'sender', 'state')

        while convStatus == 'Connecting':
            newEvent = self.updateEvents()
            convStatus = self.searchResponse(newEvent, 'sender', 'state')
            time.sleep(1) # Wait for a short time and check if it has connected
            print(newEvent)

        for item in newEvent["sender"]:
            for keyword in item["events"]:
                if 'status' in keyword:
                    state = keyword['status']
                else:
                    state = None

        if state == 'Success':
            print('Success, ', newEvent)
            for item in newEvent["sender"]:
                for x in item["events"]:
                    if "_embedded" in x and "messaging" in x["_embedded"]:
                        messageOptions = x["_embedded"]["messaging"]["_links"]
                    else:
                        continue
        else:
            messageOptions = None
            print('Server error - {}'.format(state))

        return messageOptions if messageOptions else None


    def Message(self, messageOptions, option, text=None):
        """ option parameter accepts keys from the OpenChannel dictionary.
            These are: sendMessage, stopMessaging, """
        url = self.rootDomain + messageOptions[option]["href"]
        headers = { 'Authorization': 'Bearer {}'.format(self.oauthToken),
                    'Accept': 'application/json',
                    'Content-Type': 'text/plain'}
        text = text.encode()

        msgRequest = request.Request(url, data=text, headers=headers)
        with request.urlopen(msgRequest) as response:
            print(response.getcode())
            self._eventHandler(response)
            data = response.read().decode()
        return data if data else ''





    ## --------------------------------------------------------------------------------------- ##
    ## Internal methods for preparing and formatting information
    ## --------------------------------------------------------------------------------------- ##
    def prepareDomain(self, val):
        url = parse.urlparse(val)
        if url.netloc:
            val = url.netloc.replace("www.", "")
        else:
            val = url.path.replace("www.", "")
        return val

    def getUser(self):
        return json.loads(self._httpRequestHelper('GET', self.discoveryURL))

    def authUser(self, url, token=None):
        return self._httpRequestHelper('GET', url=url)

    def _httpRequestHelper(self, method, url, payload=None):
        headers = {
            'Accept':"application/json",
        }

        if self.oauthToken: # Prepare the appropriate headers if token has been generated
            headers['Authorization'] = "Bearer {}".format(self.oauthToken)

        if method == 'POST':
            if payload and isinstance(payload, dict):
                payload = json.dumps(payload)
                headers['Content-Type'] = "application/json"
            else:
                headers['Content-Type'] = "application/x-www-form-urlencoded;charset='utf-8'"

        if payload and not isinstance(payload, bytes): # Prepare the payload, if it exists
            payload = payload.encode()

        myRequest = request.Request(url, data=payload, headers=headers, method=method)
        try:
            with request.urlopen(myRequest) as response:
                data = response.read().decode()
        except error.HTTPError as err:
            data = self._handleExceptionResponse(err)
        except error.URLError as err:
            raise Exception('The server timed out: {}'.format(err.reason))
        except Exception as err:
            raise Exception('An unknown error occurred: {}'.format(err))

        return data if data else None

    def _handleExceptionResponse(self, err):
        code = err.code
        if code == 401:
            return self.authHandler(err)
        elif code == 404:
            print('Updating application')
            return self.updateApplication()
        else:
            raise Exception('HTTP response error: {} - {}'.format(err.code, err.reason))

    def authHandler(self, response):
        data = str(response.hdrs)
        pattern = re.compile('http[s]?:\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        url = pattern.search(data)
        return url.group(0)

    def updateApplication(self):
        pass

    def searchResponse(self, adict, key, value):
        for item in adict[key]:
            for x in item['events']:
                if '_embedded' in x and 'conversation' in x['_embedded']:
                    status = x['_embedded']['conversation'][value]
                else:
                    continue
        return status if status else None

    def updateEvents(self):
        url = self.rootDomain + self.eventURL
        eventLog = self._httpRequestHelper('GET', url)
        eventLog = json.loads(eventLog)
        self.eventURL = eventLog["_links"]["next"]["href"]

        if self.Messaging == True:
            threading.Timer(2, self.updateEvents).start()

        return eventLog

    def _eventHandler(self, response):
        if response.getcode() == 201:
            print('message sent')
            self.Messaging = True
            self.updateEvents()
        elif response.getcode() == 204:
            self.Messaging = False
            print('messaging terminated')

    ## --------------------------------------------------------------------------------------- ##
    ## Useful for debugging
    ## --------------------------------------------------------------------------------------- ##
    def callToken(self):
        return self.oauthToken

    def callApplication(self):
        return self.createdApplication
