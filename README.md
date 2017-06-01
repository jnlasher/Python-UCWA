# Python-UCWA
Files for connecting to the REST API of Skype for Business

# Creating the App

1) Instantiate the class with the user ID (SIP address) and password of a valid account. User Agent and Endpoint ID are both arbitrary identifiers. 
Then call the ```StartApplication``` method
```bash
myapp = myapp = UCWAApp.UCWAApplication(userID, pwd, userAgent, endpointID)
myapp.StartApplication()
```

# Using the resources

### Getting and Setting the User status
1) To get the status of the user that created the application, call the UpdateTasks method on your app with the 'presence' qualifier:
```bash
Mystatus = myapp.UpdateTasks('presence')
```
This returns a JSON object and current status is found in the ['availability'] resource.

2) To set the user status, call the UpdateTasks method with the 'presence' qualifier and pass an option that is available from the MS SFB list. 
```bash
myapp.UpdateTasks('presence', 'Busy')
```

### Getting status of contacts
1) To get the status of a contact, pass the SIP address of the contact to the GetPresence method:
```bash
status = myapp.GetPresence('somename@mydomain.com')
```
This returns a JSON object and status can be found under the ['availability'] key

### Sending a message
1) To send a message you must first open the messaging channel with the StartMessaging method:
```bash
message = myapp.StartMessaging(UserDict.get(person)['sip'])
```
2) If successful, this will return a list of possible options which are: conversation, self, sendMessage, setIsTyping, stopMessaging, typingParticipants. It is possible
for the recipient to cancel the request, which will return an NoneType object.

3) Sending a string object to the sendMessage resource will send the message to the open conversation:
```bash
myapp.Messaging(status, 'sendMessage', message='this is a new message.')
```
Note: It is advisable to wrap this in some logic that handles a NoneType response

4) Upon finishing communications, it is important to stop the messaging channel with
```bash
myapp.Messaging(status, 'stopMessaging')
```
