import socketserver
from os import listdir
from secrets import token_bytes, token_hex, token_urlsafe
import json
import mysql_functions
import bcrypt
import hashlib


mysql_functions.db_init()

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
                if isFile:
                    reqObj["queries"][name] = file
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
    response['cookies'] = []
    if 'xsrf_token' in reqObj['queries'].keys():
        if reqObj['queries']['xsrf_token'] not in xsrf_tokens:
            response = forbidden_response
        else:
            handle_queries(reqObj["queries"], reqObj["path"], reqObj["type"])
    isError, errorMsg, response = check_request(reqObj, response)
    if isError:
        response = error_response
        response["body"] = errorMsg
    resObj = {
        "head": f'HTTP/1.1 {response["code"]}',
        "headers": {
            "Content-Type": response["type"],
            "X-Content-Type-Options": "nosniff",
        },
        "path": reqObj.get("path", '/error')
    }
    resObj['cookies'] = response.get('cookies', [])
    for k, v in response["headers"].items():
        resObj["headers"][k] = v
    
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
    resObj = fix_response(reqObj, resObj)
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

for file in listdir("pictures"):
    valid_requests["GET"][f'/pictures/{file}'] = {
        "code": "200 OK",
        "type": "image/jpeg",
        "path": f'./pictures/{file}',
        "headers": {}
    }

# The generic 404 error response object.
not_found_response = {
    "code": "404 Not Found",
    "type": "text/plain",
    "body": "The content you are looking for could not be found.",
    "headers": {}
}

error_response = {
    "code": "400 Bad Request",
    "type": "text/plain",
    "body": "",
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
        resObj = build_response(reqObj)

        res = bytes(f'{resObj["head"]}\r\n', "ascii")
        for k, v in resObj["headers"].items():
            res += bytes(f'{k}: {v}\r\n', "ascii")
        for cookie in resObj.get("cookies", []):
            res += bytes(f'Set-Cookie: {cookie["name"]}={cookie["value"]}; Max-Age={cookie["max-age"]}; HttpOnly\r\n', 'ascii')
        res += bytes("\r\n", "ascii")
        res += resObj["body"]
        self.wfile.write(res)

xsrf_tokens = []

def check_password(password):
    if len(password) < 8:
        return 'Password is too small'
    try:
        chars = bytes(password, 'utf-8')
        conditions = [
            {
                'name': 'lowercase',
                'condition': lambda x : x >= 97 and x <= 122,
                'met': False,
                'message': 'Your password needs at least one lowercase letter, enter something else'
            },
            {
                'name': 'uppercase',
                'condition': lambda x : x >= 65 and x <= 90,
                'met': False,
                'message': 'Your password needs at least one uppercase letter, enter something else'
            },
            {
                'name': 'number',
                'condition': lambda x : x >= 48 and x <= 57,
                'met': False,
                'message': 'Your password needs at least one number, enter something else'
            },
            {
                'name': 'special characters',
                'condition': lambda x : (x >= 33 and x <= 47) or (x >= 58 and x <= 64) or (x >= 91 and x <= 96) or (x >= 123 and x <= 126),
                'met': False,
                'message': 'Your password needs at least one special character, enter something else'
            }
        ]
        for i in chars:
            if i < 33 or i > 126:
                return 'Invalid character occured.'
            for c in conditions:
                c['met'] = c['condition'](i) or c['met']
        for c in conditions:
            if not c['met']:
                return c['message']
    except (UnicodeDecodeError):
        return 'Invalid character occured.'


def fix_response(reqObj, resObj):
    if reqObj['path'] == '/profile/edit':
        user = mysql_functions.db_check_auth_token(reqObj["headers"].get("Cookie", '').split("=")[-1])
        if user is None:
            resObj['header'] = 'HTTP/1.1 403 Forbidden'
            resObj['headers']['Content-Type'] = 'text/plain'
            resObj['body'] = b'you are not logged in'
            resObj["headers"]["Content-Length"] = len(resObj["body"])
            return resObj
        userInfo = mysql_functions.db_get_user_info(user)
        resObj['body'] = resObj['body'].replace(b'{{fullName}}', bytes(userInfo[1] + ' ' + userInfo[2], 'ascii'))
        resObj['body'] = resObj['body'].replace(b'{{firstName}}', bytes(userInfo[1], 'ascii'))
        resObj['body'] = resObj['body'].replace(b'{{lastName}}', bytes(userInfo[2], 'ascii'))
        resObj['body'] = resObj['body'].replace(b'{{profilePicture}}', bytes(userInfo[0][1:], 'utf-8'))
    if reqObj['path'] == '/profile':
        user = reqObj['queries'].get('user')
        editButton = b''
        if user is None:
            user = mysql_functions.db_check_auth_token(reqObj["headers"].get("Cookie", '').split("=")[-1])
            if user is None:
                resObj['header'] = 'HTTP/1.1 403 Forbidden'
                resObj['headers']['Content-Type'] = 'text/plain'
                resObj['body'] = b'you are not logged in'
                resObj["headers"]["Content-Length"] = len(resObj["body"])
                return resObj
            editButton = b'<div class="container-return"><a href="/profile/edit">Edit Profile</a></div>'
        if not mysql_functions.db_check_user_exists(user):
            resObj['header'] = 'HTTP/1.1 401 Bad Request'
            resObj['headers']['Content-Type'] = 'text/plain'
            resObj['body'] = b'user could not be found'
            resObj["headers"]["Content-Length"] = len(resObj["body"])
            return resObj
        userInfo = mysql_functions.db_get_user_info(user)
        resObj['body'] = resObj['body'].replace(b'{{fullName}}', bytes(userInfo[1] + ' ' + userInfo[2], 'ascii'))
        resObj['body'] = resObj['body'].replace(b'{{profilePicture}}', bytes(userInfo[0], 'utf-8'))
        resObj['body'] = resObj['body'].replace(b'{{edit}}', editButton)
    if reqObj['path'] == '/list':
        user = mysql_functions.db_check_auth_token(reqObj["headers"].get("Cookie", '').split("=")[-1])
        if user is None:
            resObj['header'] = 'HTTP/1.1 403 Forbidden'
            resObj['headers']['Content-Type'] = 'text/plain'
            resObj['body'] = b'user must be logged in to access list'
            resObj["headers"]["Content-Length"] = len(resObj["body"])
            return resObj 
        resObj['body'] = resObj['body'].replace(b'{{username}}', bytes(user, 'ascii'))
        userInfo = mysql_functions.db_get_user_info(user)
        resObj['body'] = resObj['body'].replace(b'{{firstName}}', bytes(userInfo[1], 'ascii'))
        userList = mysql_functions.db_retrieve_list_of_users()
        userElement = b''
        for otherUser in userList:
            if otherUser[0] != user:
                userElement += b'<div class="contact-section">'
                userElement += bytes(f'<li class="list__item" id={otherUser[0]}>', 'ascii')
                userElement += bytes(f'<a href="/profile?user={otherUser[0]}"><p class="contact-name">{otherUser[0]}</p></a>', 'ascii')
                if otherUser[1] == "Online":
                    userElement += bytes(f'<a class="message" href="/dm?user={otherUser[0]}"><p class="Login">{otherUser[1]}</p></a></li></div><hr>', 'ascii')
                else:
                    userElement += bytes(f'<a class="message"><p class="Logout">{otherUser[1]}</p></a></li></div><hr>', 'ascii')
        resObj['body'] = resObj['body'].replace(b'{{users}}', userElement)
    elif reqObj['path'] == '/dm':
        recipiant = reqObj['queries'].get('user')
        if recipiant is None:
            resObj['header'] = 'HTTP/1.1 401 Bad Request'
            resObj['headers']['Content-Type'] = 'text/plain'
            resObj['body'] = b'no user specificed'
            resObj["headers"]["Content-Length"] = len(resObj["body"])
            return resObj
        if not mysql_functions.db_check_user_exists(recipiant):
            resObj['header'] = 'HTTP/1.1 401 Bad Request'
            resObj['headers']['Content-Type'] = 'text/plain'
            resObj['body'] = b'user could not be found'
            resObj["headers"]["Content-Length"] = len(resObj["body"])
            return resObj
        sender = mysql_functions.db_check_auth_token(reqObj["headers"].get("Cookie", '').split("=")[-1])
        if sender is None:
            resObj['header'] = 'HTTP/1.1 403 Forbidden'
            resObj['headers']['Content-Type'] = 'text/plain'
            resObj['body'] = b'invalid auth token'
            resObj["headers"]["Content-Length"] = len(resObj["body"])
            return resObj 
        if sender == recipiant:
            resObj['header'] = 'HTTP/1.1 401 Bad Request'
            resObj['headers']['Content-Type'] = 'text/plain'
            resObj['body'] = b'cannot send messages to self'
            resObj["headers"]["Content-Length"] = len(resObj["body"])
            return resObj
        userList = [sender, recipiant]
        userList.sort()
        channel = "".join(userList)
        resObj['body'] = resObj['body'].replace(b'{{recipiant}}', bytes(f"{recipiant}", 'ascii'))
        resObj['body'] = resObj['body'].replace(b'{{socketName}}', bytes(f"'{channel}'", 'ascii'))
        resObj['body'] = resObj['body'].replace(b'{{username}}', bytes(f"'{sender}'", 'ascii'))
        history = mysql_functions.db_retrieve_channel_messages("/" + channel)
        historyElem = b''
        if history is not None:
            for message in history:
                historyElem += bytes("<b>" + message[0] + "</b>: " + message[2] + "<br/>", 'utf-8')
        resObj['body'] = resObj['body'].replace(b'{{message}}', historyElem)
    resObj["headers"]["Content-Length"] = len(resObj["body"])
    return resObj


def check_request(reqObj, response):
    if reqObj['path'] == "/register" and reqObj['type'] == 'POST':
        if reqObj['queries']['confirm'] != reqObj['queries']['password']:
            return True, 'passwords do not match', response
        error = check_password(reqObj['queries']['password'])
        if error is not None:
            return True, error, response
        with open(f'./pictures/{reqObj["queries"]["username"]}.jpg', 'wb') as f:
            f.write(reqObj['queries']['picture'])
        if not mysql_functions.db_insert_user(reqObj['queries']['username'], bcrypt.hashpw(reqObj['queries']['password'].encode(), bcrypt.gensalt()), reqObj['queries']['FirstName'], reqObj['queries']['LastName'], f'./pictures/{reqObj["queries"]["username"]}.jpg'):
            return True, 'error occured during registration', response
        valid_requests["GET"][f'/pictures/{reqObj["queries"]["username"]}.jpg'] = {
            "code": "200 OK",
            "type": "image/jpeg",
            "path": f'./pictures/{reqObj["queries"]["username"]}.jpg',
            "headers": {}
        }
    elif reqObj['path'] == "/login" and reqObj['type'] == 'POST':
        validLogin = mysql_functions.db_login_user(reqObj['queries']['username'], reqObj['queries']['password'])
        if not validLogin:
            return True, "invalid login", response
        token = token_urlsafe(16)
        hash_token = bcrypt.hashpw(token.encode(), bcrypt.gensalt())
        mysql_functions.db_insert_auth_token(reqObj['queries']['username'], hash_token)
        response["cookies"] = [{
                "name": "token",
                "value": token,
                "max-age": 86400,
        }]
    if reqObj['path'] == '/userInfo':
        user = mysql_functions.db_check_auth_token(reqObj["headers"].get("Cookie", '').split("=")[-1])
        if user is None:
            return True, "invalid auth token", response
        mysql_functions.db_update_user_info(user, reqObj['queries']['FirstName'], reqObj['queries']['LastName'])
    return False, '', response

server = socketserver.TCPServer(("0.0.0.0", 8000), TCPRequestHandler)
print("server running @ http://localhost:8000")
server.serve_forever()