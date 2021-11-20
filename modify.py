from secrets import token_hex

xsrf_tokens = []

def modify_request(reqObj):
    if reqObj['path'] == "/register":
        # do something
        pass
    elif reqObj['path'] == "/login":
        # do something
        pass
    return reqObj

def modify_response(resObj):
    if b'{{token}}' in resObj['body']:
        token = token_hex(16)
        xsrf_tokens.append(token)
        resObj['body'] = resObj['body'].replace(b'{{token}}', bytes(token, 'utf-8'))
        print(xsrf_tokens)
    return resObj