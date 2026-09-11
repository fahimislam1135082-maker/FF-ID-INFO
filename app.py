import asyncio
import time
import httpx
import json
import base64
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple

from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES

# Settings
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB52"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

SUPPORTED_REGIONS = ["IND", "BD", "SG", "PK", "BR", "US", "ID", "VN", "TH", "RU", "ME", "CIS", "TW", "EUROPE", "NA", "SAC"]

app = Flask(__name__)
CORS(app)

cache = TTLCache(maxsize=200, ttl=300)
cached_tokens = {}
uid_region_cache = {}

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r in {"IND", "BD"}:
        return "uid=3933356115&password=CA6DDAEE7F32A95D6BC17B15B8D5C59E091338B4609F25A1728720E8E4C107C4"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=4044223479&password=EB067625F1E2CB705C7561747A46D502480DC5D41497F4C90F3FDBC73B8082ED"
    else:
        return "uid=4108414251&password=E4F9C33BBEB23C0DA0AD7E60F63C8A05D6A878798E3CD32C4E2314C1EEFD4F72"

async def get_access_token(account: str, client: httpx.AsyncClient):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Content-Type': "application/x-www-form-urlencoded"}
    resp = await client.post(url, data=payload, headers=headers, timeout=6.0)
    data = resp.json()
    return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str, client: httpx.AsyncClient):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account, client)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Content-Type': "application/octet-stream", 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    resp = await client.post(url, data=payload, headers=headers, timeout=6.0)
    msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
    
    cached_tokens[region] = {
        'token': f"Bearer {msg.get('token','0')}",
        'region': msg.get('lockRegion','0'),
        'server_url': msg.get('serverUrl','0'),
        'expires_at': time.time() + 20000
    }

async def get_token_info(region: str, client: httpx.AsyncClient) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region, client)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def fetch_account_info(uid: str, region: str, client: httpx.AsyncClient):
    payload = await json_to_proto(json.dumps({'a': int(uid), 'b': 7}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region, client)
    
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Content-Type': "application/octet-stream", 
        'Authorization': token, 
        'X-Unity-Version': "2018.4.11f1", 
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    endpoint = f"{server}/GetPlayerPersonalShow"
    resp = await client.post(endpoint, data=data_enc, headers=headers, timeout=6.0)
    
    proto_res = decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
    data = json.loads(json_format.MessageToJson(proto_res))
    if not data or "basicInfo" not in data:
        raise ValueError("Profile not found")
    return data

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(sorted(request.args.items())))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

@app.route('/player-info', methods=['GET'])
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    requested_region = request.args.get('region')

    if not uid:
        return jsonify({"error": "Please provide a valid UID."}), 400

    async def execute():
        async with httpx.AsyncClient() as client:
            if requested_region:
                r = requested_region.upper()
                try:
                    data = await fetch_account_info(uid, r, client)
                    uid_region_cache[uid] = r
                    return data
                except Exception:
                    return None

            if uid in uid_region_cache:
                try:
                    return await fetch_account_info(uid, uid_region_cache[uid], client)
                except Exception:
                    pass

            for reg in SUPPORTED_REGIONS:
                try:
                    data = await fetch_account_info(uid, reg, client)
                    uid_region_cache[uid] = reg
                    return data
                except Exception:
                    continue
            return None

    try:
        result = asyncio.run(execute())
        if result:
            return jsonify(result), 200
        return jsonify({"error": "UID not found in any region. Try passing ?region=SG/IND/BD directly."}), 404
    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "Online",
        "usage": "/player-info?uid=YOUR_UID&region=YOUR_REGION"
    }), 200
