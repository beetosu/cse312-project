import socketserver
from os import listdir
from secrets import token_hex
import json
from modify import modify_request, modify_response

xsrf_tokens = []

def preventInjection(text):
    return text.replace("&","&amp;").replace("<", "&lt;").replace(">", "&gt;")

'''
    Takes request, and returns a request object in the following format:
    {
        "type": GET or POST.
        "path": the path of the request.
        "headers": the headers of the request in key-value pairs.
        "queries": the key-value pairs represented by the query string.
        "headerqueries": queries in specific headers, contained separate key-value pairs based on parent header.
        "body": holds the key-value pairs for a POST request body.
    }
'''
def parse_request(req):
    reqObj = {
        "headers": {},
        "queries": {},
        "path": '',
        "headerqueries": {}
    }
    while True:
        line = req.readline().strip().decode("ascii")
        if line == '':
            break
        pair = line.split(': ')
        if len(pair) == 1:
            header = pair[0].split(" ")
            reqObj["type"] = header[0]
            path = header[1].split("?")
            if len(path) != 1:
                queries = path[1].split("&")
                for query in queries:
                    querypair = query.split("=")
                    reqObj["queries"][querypair[0]] = querypair[1]
            reqObj["path"] = path[0]
        else:
            headerQ = pair[1].split("; ")
            if len(headerQ) > 1:
                reqObj["headerqueries"][pair[0]] = {}
                for i in range(1, len(headerQ)):
                    kv = headerQ[i].split("=")
                    if len(kv) == 2:
                        reqObj["headerqueries"][pair[0]][kv[0]] = kv[1]
                reqObj["headers"][pair[0]] = headerQ[0]
            else:
                reqObj["headers"][pair[0]] = pair[1]
    # If this is a POST request, parse the body
    if reqObj["headerqueries"].get("Content-Type") != None and reqObj["type"] == 'POST':
        boundary = '--' + reqObj["headerqueries"]["Content-Type"]["boundary"]
        isFile = False
        file = bytes()
        while True:
            lineBytes = req.readline()
            line = lineBytes.strip()
            if line == bytes(boundary + '--', 'ascii'):
                break
            if bytes("Content-Disposition: form-data", 'ascii') in line:
                name=line.decode("ascii").split('name="')[1].split('"')[0]
            elif bytes("Content-Type: image/", 'ascii') in line or bytes("Content-Type: application/", 'ascii') in line or bytes("Content-Type: audio/", 'ascii') in line:
                isFile = True
            elif line == bytes(boundary, 'ascii') and isFile:
                isFile = False
                reqObj["queries"][name] = file
                file = bytes()
            elif (line != bytes('', 'ascii') or (isFile and file != bytes())) and line != bytes(boundary, 'ascii'):
                if isFile:
                    file += lineBytes
                else: 
                    reqObj["queries"][name] = preventInjection(line.decode("ascii"))
    return reqObj


def handle_queries(queries, path, type):
    pass


'''
    Parses through an html template to produce a usable html file
'''
def parse_template(html, queries):
    if b'{{token}}' in html:
        token = token_hex(16)
        xsrf_tokens.append(token)
        html = html.replace(b'{{token}}', bytes(token, 'utf-8'))
    return html


'''
    Takes a request object (built from parse_request) and returns a response object
    The response object is mostly dervived from valid_requests, with some extra headers
    built in/generated automatically. 
'''
def build_response(reqObj):
    response = valid_requests.get(reqObj["type"], not_found_response).get(reqObj["path"], not_found_response)
    if 'xsrf_token' in reqObj['queries'].keys():
        if reqObj['queries']['xsrf_token'] not in xsrf_tokens:
            response = forbidden_response
        else:
            handle_queries(reqObj["queries"], reqObj["path"], reqObj["type"])
    resObj = {
        "head": f'HTTP/1.1 {response["code"]}',
        "headers": {
            "Content-Type": response["type"],
            "X-Content-Type-Options": "nosniff",
        },
        "path": reqObj.get("path", '/error')
    }
    for k, v in response["headers"].items():
        resObj["headers"][k] = v
    
    print(resObj)

    if "body" in response.keys():
        resObj["headers"]["Content-Length"] = len(response["body"])
        resObj["body"] = bytes(response["body"], 'UTF-8')
    else:
        file = open(response["path"], 'rb').read()
        if resObj["headers"]["Content-Type"] in 'text/html':
            resObj["body"] = parse_template(file, reqObj["queries"])
        else:
            resObj["body"] = file
        
        resObj["headers"]["Content-Length"] = len(resObj["body"])
    return resObj

'''
    Object which contains all valid requests for the server, everything else defaults to a 404 error.
    The requests are stored by TYPE->PATH, and fit the following format:
    
    {
        "code": the response number/phrase sent to the browser ("200 OK", "301 Redirect", etc.)
        "type": the type of the response body ("text/plain", "image/jpeg", etc.)
        "body" (opt.): if the response body is not stored in a file, it goes here.
        "path" (opt.): if the response body is derived from a file, it goes here.
        "headers": any other headers, in key-value format.
    }
''' 
with open('requests.json') as f:
    valid_requests = json.load(f)

# The generic 404 error response object.
not_found_response = {
    "code": "404 Not Found",
    "type": "text/plain",
    "body": "The content you are looking for could not be found.",
    "headers": {}
}

forbidden_response = {
    "code": "403 Forbidden",
    "type": "text/plain",
    "body": "The content you are attempting to access is forbidden.",
    "headers": {}
}

# Calls the functions to handle/send requests/responses.
class TCPRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        reqObj = parse_request(self.rfile)
        reqObj = modify_request(reqObj)

        resObj = build_response(reqObj)
        resObj = modify_response(resObj)

        res = bytes(f'{resObj["head"]}\r\n', "ascii")
        for k, v in resObj["headers"].items():
            res += bytes(f'{k}: {v}\r\n', "ascii")
        for cookie in resObj.get("cookies", []):
            res += bytes(f'Set-Cookie: {cookie["name"]}={cookie["value"]}; Max-Age={cookie["max-age"]}; HttpOnly\r\n', 'ascii')
        res += bytes("\r\n", "ascii")
        res += resObj["body"]
        self.wfile.write(res)

server = socketserver.TCPServer(("0.0.0.0", 8000), TCPRequestHandler)
print("server running @ http://localhost:8000")
server.serve_forever()