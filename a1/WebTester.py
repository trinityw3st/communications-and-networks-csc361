import sys
from urllib.parse import urlparse
import socket
import ssl

from WebTesterClasses import URI, Cookie


def parse_uri(input_uri: str) -> URI:
    """ 
        Takes the input and parses it's protocol, host, port and filepath into a URI type 
        and returns the URI type with all the fields filled in.
    """
    # Before parsing the URI, check that an input was provided
    if not input_uri or input_uri == " ":
        raise ValueError("No URI provided in the input. Please include a uri in the command line when running the file, i.e. 'https://www.uvic.ca'.")
    
    # if no protocol is provided, default to http
    if "://" not in input_uri:
        input_uri = "http://" + input_uri
    
    uri = URI() # Initialize a URI type
    parsed_uri = urlparse(input_uri)
    
    uri.protocol = parsed_uri.scheme
    if uri.protocol not in ("http", "https"):
        raise ValueError(f"Unsupported protocol '{uri.protocol}'. Must be 'http' or 'https'.")

    uri.host = parsed_uri.hostname
    if not parsed_uri.hostname:
        raise ValueError(f"Invalid URI: could not get the host from '{input_uri}'")
    
    if (not parsed_uri.port):
        # if no port number given, default port num is given
        if (uri.protocol == "https"):
            uri.port = 443
        elif (uri.protocol == "http"):
            uri.port = 80
        else:
            raise ValueError("Protocol given was not 'http' or 'https', can't find default port number.")
    else:
        uri.port = int(parsed_uri.port)
    
    # If no path provided, default to "/"
    uri.filepath = parsed_uri.path if parsed_uri.path else "/"
    
    return uri


def get_set_cookies(response_lines: list) -> list:
    """
        Short function to extract the 'Set-Cookie' entries from the response.
    """
    set_cookies = []
    
    for line in response_lines:
        if line.lower().startswith("set-cookie"):
            set_cookie = line.split(": ")
            set_cookies.append(set_cookie[1])
    
    return set_cookies


def parse_set_cookies(set_cookies: list) -> list:
    """
        Takes a list of cookies and returns a list where each list entry is of the type Cookie.
        Helps so that we can later format the cookie output to 'cookie name: _____, expires: _____, domain: _____'.
    """
    cookies_output = []
    for cookie in set_cookies:
        current_cookie = Cookie()
        cookie_name = ""
        cookie_parts = cookie.split("; ")
        cookie_name = cookie_parts[0].split("=")[0]
        current_cookie.cookie_name = cookie_name

        for part in cookie_parts:
            if part.lower().startswith("expires"):
                expiry = part.split("=")[1]
                current_cookie.expires = expiry
            
            if part.lower().startswith("domain"):
                domain = part.split("=")[1]
                current_cookie.domain = domain
        
        cookies_output.append(current_cookie)
    return cookies_output    


def print_response_body(host: str, finds_http2: bool, set_cookies: list, password_protected: bool):
    """
        Prints the response body that tells us the website, if it supports http2, it's cookies
        and if it is password protected.
    """
    print("---Response Body---")
    print(f"website: {host}")
    print(f"1. Supports http2: {finds_http2}")
    
    if (len(set_cookies) > 0):
        print(f"2. List of Cookies:")
        cookie_output = parse_set_cookies(set_cookies)
        for c in cookie_output:
            print(c)
    else:
        print(f"2. No cookies.")

    print(f"3. Password-protected: {password_protected}")


def create_socket() -> socket.socket:
    """
        Creates and returns the socket.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        print("Socket creation failed with error %s" %(err))
    return sock


def connect_to_server(sock: socket.socket, host: str, port: int):
    """
        Connects to the server of the URI using the socket created, the host, and the port.
    """ 
    try: 
        host_ip = socket.gethostbyname(host)
    except socket.gaierror:
        # could not resolve the host
        raise ConnectionError(f"Could not resolve the host: {host}. \nPlease ensure that you give a valid host as input or that the format of the uri is correct.")

    # connect to the server
    try:
        sock.connect((host_ip, port))
    except ConnectionRefusedError:
        raise ConnectionError(f"Connection refused when connecting to {host}:{port}.")
    except TimeoutError:
        raise ConnectionError(f"Connection timed out while connecting to {host}:{port}.")


def make_tls_connection(host: str, alpn_protocols) -> ssl.SSLSocket:
    """
        Creates a ssl-wrapped socket and connects it with tls. Returns the connection.
    """
    tls_port = 443
    # create ssl-wrapped socket
    context = ssl.create_default_context()
    context.set_alpn_protocols(list(alpn_protocols))
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    conn.connect((host, tls_port))

    return conn

def check_tls_h2(conn: ssl.SSLSocket) -> bool:
    """
        Checks if the https connected host supports http2.
    """
    # get the negotiated protocol from the SSL/TLS handshake
    negotiated_protocol = conn.selected_alpn_protocol()
    h2_in_np = False
    if negotiated_protocol is not None:
        if 'h2' in negotiated_protocol:
            h2_in_np = True
    
    return h2_in_np


def find_new_location(response_lines: list) -> str:
    """
        Finds the redirect location to be used from the response (for 301/302 redirects).
    """
    location = ""
    for i in response_lines:
        if i.lower().startswith("location"):
            location_line = i.split()
            location = location_line[1]

    if location == "":
        raise ValueError("Response received implies redirect but no 'Location' found in the header.")        
    return location


def get_http_response(sock: socket.socket, host: str, protocol: str) -> str:
    """
        Returns the formatted response from a successful GET request for http servers.
    """
    # check http servers with a GET request
    print("---Request begin---")
    request = f"GET / HTTP/1.1\r\n"
    request += f"Host: {host}\r\n"
    request += f"Connection: Keep-Alive\r\n"
    print(f"{request}\n")
    request += f"Upgrade: h2c\r\n" # Upgrade to HTTP/2 (cleartext, h2c)
    request += f"Accept: */*\r\n"
    request += f"\r\n" # End of headers
    
    sock.send(request.encode("ascii"))

    response = sock.recv(10000)
    print("---Request end---")
    print("HTTP request sent, awaiting response...\n")

    response_raw = response.decode('utf-8')
    raw_and_header = response_raw.split("\r\n\r\n")
    response_header = raw_and_header[0]

    response_lines = response_header.split("\r\n")

    # Checking valid response and getting response code to prepare for redirect if needed (i.e., 301, 302 etc)
    try:  
        http_line = response_lines[0]
        #print(http_line)
        http_line_parts = http_line.split()
        if len(http_line_parts) < 2 or not http_line_parts[1].isdigit():
            raise ValueError(f"Invalid HTTP response: '{http_line}'")
        http_code = int(http_line_parts[1])
    except IndexError:
        raise ValueError("Empty response received. Can't resolve response code.")
    except ValueError as e:
        raise ValueError(f"Got a weirdly formed HTTP response : {e}")
    
    
    if 300 <= http_code < 400:
        # Handling 301/302 response: go to new location and retry
        try:
            new_location = find_new_location(response_lines)
        except ValueError as e:
            raise ValueError(f"Couldnt find redirect location in response header: {e}")
        print(f"\nGot '{http_line}'\n....Redirecting to redirect location: {new_location}\n")
        sock.close()
        new_uri = parse_uri(new_location) 
        if (new_uri.protocol == "http"):
            sock = create_socket()
            connect_to_server(sock, new_uri.host, new_uri.port)
            return get_http_response(sock, new_uri.host, new_uri.protocol)
        elif (new_uri.protocol == "https"):
            conn = make_tls_connection(new_uri.host, ('http/1.1',))
            response_header = use_tls_handshake(conn, new_uri.host)
            conn.close()
            return response_header
    
            
    sock.close()
    return response_header


def use_tls_handshake(conn, host: str) -> bool:
    """
        Basically the same as get_http_response in the way that it sends an http request to return the formatted 
        response header.

        Main difference is that we do not upgrade to http2 and it has a different type of connection to close.
        (could have refactored these two functions a bit better but I ran out of time.)
    """
    #send requests
    print("---Request begin---")
    request = f"GET / HTTP/1.1\r\n"
    request += f"Host: {host}\r\n"
    request += f"Connection: Keep-Alive\r\n"
    print(f"{request}\n") # only print request again if we havent already
    request += f"Accept: */*\r\n"
    request += f"\r\n" # End of headers
    
    conn.send(request.encode("ascii"))
    #recieve response
    response = conn.recv(10000)
    print("---Request end---")
    print("HTTP request sent, awaiting response...\n")
    response_raw = response.decode('utf-8')
    
    raw_and_header = response_raw.split("\r\n\r\n")
    response_header = raw_and_header[0]
    response_lines = response_header.split("\r\n")
    
    # Checking valid response and getting response code to prepare for redirect if needed (i.e., 301, 302 etc)
    try:  
        http_line = response_lines[0]
        #print(http_line)
        http_line_parts = http_line.split()
        if len(http_line_parts) < 2 or not http_line_parts[1].isdigit():
            raise ValueError(f"Invalid HTTP response: '{http_line}'")
        http_code = int(http_line_parts[1])
    except IndexError:
        raise ValueError("Empty response received. Can't resolve response code.")
    except ValueError as e:
        raise ValueError(f"Got a weirdly formed HTTP response : {e}")
    
    
    if 300 <= http_code < 400:
        # Handling 301/302 response: go to new location and retry
        try:
            new_location = find_new_location(response_lines)
        except ValueError as e:
            raise ValueError(f"Could not find redirect location in response: {e}")
        print(f"\nGot '{http_line}'\n....Redirecting to redirect location: {new_location}\n")
        conn.close()
        new_uri = parse_uri(new_location) 
        if (new_uri.protocol == "http"):
            sock = create_socket()
            connect_to_server(sock, new_uri.host, new_uri.port)
            return get_http_response(sock, new_uri.host, new_uri.protocol)    
        elif (new_uri.protocol == "https"):
            conn = make_tls_connection(new_uri.host, ('http/1.1',))
            return use_tls_handshake(conn, new_uri.host)
    
    conn.close()
    
    return response_header


def check_password_protection(host: str, filepath: str, port: int) -> bool:
    """
        Checks if the given uri is password protected. Returns true if it is password protected.
    """
    if not filepath:
        filepath = "/"

    request = (
        f"GET {filepath} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    password_protected = False

    try:
        if port == 443:
            # HTTPS: wrap the socket with TLS credit chatgpt here
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host) as sock:
                sock.connect((host, port))
                sock.sendall(request.encode("ascii"))
                response = sock.recv(10000)
                response_raw = response.decode('utf-8')    
        else:
            # HTTP: plain socket
            with socket.create_connection((host, port)) as sock:
                sock.sendall(request.encode("ascii"))
                response = sock.recv(10000)
                response_raw = response.decode('utf-8')
    except socket.error as e:
        print(f"Socket error while checking password protection: {e}")
        sys.exit(1)
        
    if not response_raw.strip():
        print("Empty response from server during password check. Exiting here.")
        sys.exit(1)        
    
    raw_and_header = response_raw.split("\r\n\r\n")
    response_header = raw_and_header[0]

    response_header_lines = response_header.split("\r\n")
    response_code = response_header_lines[0].split()[1]
    
    www_auth_present = False
    for i in response_header_lines:
        if i.lower().startswith("www-authenticate"):
            www_auth_present = True
    
    if (response_code == "401" and www_auth_present):
        password_protected = True

    return password_protected


def check_http(uri: URI):
    """
        Function to go through main functions of this assignment for an input with http as the protocol for the uri, 
            - create socket
            - connect to server
            - get http response to
                - check for http2
                    - if the http response doesnt find http2 use a tls handshake to double check
                - check for cookies
                - check for password protection (in a diff request)
            - print response body
    """
    # Create socket
    sock = create_socket()

    # Connect to the server of the URI
    connect_to_server(sock, uri.host, uri.port)

    # Get http response
    response = get_http_response(sock, uri.host, uri.protocol)
    response_lines = response.split("\r\n")
    
    # Check for http2 
    finds_http2 = False
    if (finds_http2 == False and (uri.port == 443 or uri.port == 80)):
        #open a new tls connection port and test alpn (but dont do this for local host)
        conn = make_tls_connection(uri.host, ('http/1.1', 'h2'))
        finds_http2 = check_tls_h2(conn)
        conn.close()
    
    for i in response_lines:
        if i.lower().startswith("http2"):
            finds_http2 = True

    # Get the set cookies
    set_cookies = get_set_cookies(response_lines)
    
    # Check if it is password protected
    password_protected = check_password_protection(uri.host, uri.filepath, uri.port)

    print("---Response Header---")
    print(f"{response}\n")

    # Print the response body
    print_response_body(uri.host, finds_http2, set_cookies, password_protected)
    

def check_https(uri: URI):
    """
        Function to go through main functions of this assignment for an input with https as the protocol for the uri, 
        this one uses a "tls handshake"
            - create ssl wrapped socket
            - connect to server
            - check for http2 in tls connection
            - get an http response to
                - check for cookies
                - check for password protection (in a diff request)
            - print response body
    """
    
    # check for http2 in tls connection 
    finds_http2 = False
    conn = make_tls_connection(uri.host, ('h2', 'http/1.1'))
    finds_http2 = check_tls_h2(conn)
    conn.close()

    # get a readable http/1.1 response
    conn = make_tls_connection(uri.host, ('http/1.1',))
    response = use_tls_handshake(conn, uri.host)
    
    # Get get cookies info
    response_lines = response.split("\r\n")
    set_cookies = get_set_cookies(response_lines)
    
    # Check if the website is password protected
    password_protected = check_password_protection(uri.host, uri.filepath, uri.port)

    print("---Response Header---")
    print(f"{response}\n")

    # Print the response body
    print_response_body(uri.host, finds_http2, set_cookies, password_protected)



def main():  
    # The program first accepts URI (protocol://host[:port]/filepath) from stdin and parses it. 
    try:
        uri_from_input = sys.argv[1]
    except IndexError:
        print("Command must be of the form: python WebTester.py [uri]\nor\npython3 WebTester.py [uri] if running on uvic server.\n")
        print("(uri must be of the form protocol://host[:port]/filepath or host[:port]/filepath)")
        sys.exit(1)
    
    # parse the uri and start working on getting information from the servers in check_http or check_https
    try: 
        uri = parse_uri(uri_from_input)
        if (uri.protocol == "http"):
            check_http(uri)
        elif (uri.protocol == "https"):
            check_https(uri)
        else:
            raise ValueError(f"Unsupported protocol:\nThis program only works with 'http' or 'https' protocols, protocol {uri.protocol} is not the correct input\n")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)      



if __name__ == "__main__":
    main()