import asyncio
import websockets
import json


async def echo(websocket, path):
    await websocket.send(json.dumps({"username": "you", "comment": "suck"}))
    async for message in websocket:
        await websocket.send(message)


async def main():
    async with websockets.serve(echo, "localhost", 8001):
        await asyncio.Future()  # run forever

asyncio.run(main())
