RUNNING THE CODE:

when running on uvic ssh server, running with python3 works best 
(when doing it on my personal computer though, I was running with "python WebTester.py [uri]")

to run the code do:

python3 WebTester.py [uri address here]

the code will default to http if no protocol is given. 

If you are running with the passwordserver.py it should work the same way (although i used 
'python' instead of 'python3' on my personal computer):

ie 
python3 WebTester.py 127.0.0.1:8000/

or
python3 WebTester.py http://127.0.0.1:8000/


SOURCES:
- parse_uri function: used https://docs.python.org/3/library/urllib.parse.html for hints on how to parse the uri input
- create_socket and connect_to_server function: used  https://www.geeksforgeeks.org/python/socket-programming-python/ for socket programming help
- used chatgpt to help me come up with some of the error handling techniques in parse_uri, get_http_response, use_tls_handshake, and main functions
- lines 431-439: chatgpt helped me debug (i was getting errors in my response for https uris) by telling me to make the tls connection with both
 h2 and http/1.1 alpn protocols when checking for h2 and close then open a new tls connection with only http/1.1 as the alpn protocol afterwards 
 to get a valid http response when checking for cookies. 
