# Python-UCWA
Files for connecting to the REST API of Skype for Business

# Use

1) Instantiate the class variable, call discoverPublic on that to generate the appropriate token
**This has been updated to correct for multiple pool errors created by having different servers

This requires a username (email) and password that access to the correct domain. 

2) Call createApplication to generate the listing of applications.
You will need a userAgent name (which specifies the name of the application), endpoint ID (arbitrary ID for use in the application), and culture (english, US by default)
