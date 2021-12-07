import asyncio
import websockets
import json

'''
A dictionary, where the keys are paths on the websocket, 
and the values are sets of clients connected on those paths.
'''
CONNECTIONS = {}

# The callback function, called when websocket is created.
async def send_message(websocket, path):
    # A placeholder for getting the messages on the database.
    try:
        # Register user on a preexisting path, or create a new path.
        if path not in CONNECTIONS:
            CONNECTIONS[path] = set()
        CONNECTIONS[path].add(websocket)
        
        # Send a newly sent client message to all other connections on that path.
        async for rawMessage in websocket:
            message = json.loads(rawMessage)
            if message.get('sender', 'not in this') in path:
                recieverPath = path.replace(message['sender'], '')
                websockets.broadcast(CONNECTIONS[recieverPath], rawMessage)
            websockets.broadcast(CONNECTIONS[path], rawMessage)
    finally:
        # Unregister user
        CONNECTIONS[path].remove(websocket)


async def main():
    async with websockets.serve(send_message, "0.0.0.0", 8001):
        await asyncio.Future()  # run forever

asyncio.run(main())
