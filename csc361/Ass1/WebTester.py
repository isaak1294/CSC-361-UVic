

import re
import socket
import ssl
import sys

# 1. Program accepts URI from stdin and parses it

if len(sys.argv) != 2:
    print('Unexpected number of arguments. Format is: python3 WebTester.py <URI>')
    exit()

uri = sys.argv[1]

context = ssl.create_default_context()

# 2. Connect to the server of the URI

try:
    with socket.create_connection((uri, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=uri) as ssock:
            print('Connection established')
            https = True
            print('version:' + ssock.version())

            if ssock.selected_alpn_protocol() == 'h2':
                http2 = True
            else:
                http2 = False
            sock.close()

except Exception as e:
    print(e)
    https = False
    http2 = False

# 3. Send an HTTP request

def get_request(uri):
    request = 'GET / HTTP/1.1\r\nHost: ' + uri + '\r\n\r\n'

    try:
        with socket.create_connection((uri, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=uri) as ssock:
                ssock.send(request.encode())
                response = ssock.recv(10000).decode('utf-8', 'ignore')
                sock.close()
	
    except Exception as e:
        exit(e)

    return response

response = get_request(uri)

# Redirect handling

if re.search('HTTP/1.\d 30\d', response):
    print('Redirected')

    redirect = re.search('Location: https?://(.*?)/', response, re.IGNORECASE)

    if redirect is not None:
        uri = redirect[1]

        print('New URI: ' + uri)


        if https == True:
            try:
                with socket.create_connection((uri, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=uri) as ssock:
                        print('Connection established')
                        https = True
                        print('version:' + ssock.version())

                        if ssock.selected_alpn_protocol() == 'h2':
                            http2 = True
                        else:
                            http2 = False
                        sock.close()

            except Exception as e:
                print(e)
                https = False
                http2 = False

        if https == False:
            try:
                with socket.create_connection((uri, 80)) as sock:
                    with context.wrap_socket(sock, server_hostname=uri) as ssock:
                        print('Connection established')
                        https = True
                        print('version:' + ssock.version())
                        sock.close()
            except Exception as e:
                print(e)
                http = False

        response = get_request(uri)

# Cookie time:

cookies = re.findall('Set-Cookie: (.*?)\r\n', response)


# Print results:

if http2:
    print('HTTP/2 is enabled')
else:
    print('HTTP/2 is not enabled')
for cookie in cookies:
    print('Cookie:' + cookie)