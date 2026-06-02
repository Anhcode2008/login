from flask import Flask, request, jsonify
import asyncio
import aiohttp
import ssl
import json
import random
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# ==================== CONSTANTS ====================
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"
FIXED_KEY = b'Yg&tc%DEuh6%Zc^8'
FIXED_IV = b'6oyZDr22E3ychjM%'

# ==================== ENCRYPTION ====================
def encrypt_aes(data: bytes) -> bytes:
    cipher = AES.new(FIXED_KEY, AES.MODE_CBC, FIXED_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt_aes(data: bytes) -> bytes:
    cipher = AES.new(FIXED_KEY, AES.MODE_CBC, FIXED_IV)
    return unpad(cipher.decrypt(data), AES.block_size)

# ==================== PROTOBUF HELPERS ====================
def encode_varint(value: int) -> bytes:
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result) if result else b'\x00'

def read_varint(data: bytes, pos: int) -> tuple:
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    return result, pos

# ==================== BUILD MAJOR LOGIN PAYLOAD ====================
def build_major_login_payload(open_id: str, access_token: str) -> bytes:
    login_data = {
        "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "game_name": "free fire",
        "platform_id": 1,
        "client_version": "1.123.2",
        "system_software": "Android OS 9 / API-28",
        "system_hardware": "Handheld",
        "telecom_operator": "Verizon",
        "network_type": "WIFI",
        "screen_width": 1920,
        "screen_height": 1080,
        "screen_dpi": "280",
        "processor_details": "ARM64 FP ASIMD AES VMH | 2865 | 4",
        "memory": 3003,
        "gpu_renderer": "Adreno (TM) 640",
        "gpu_version": "OpenGL ES 3.1 v1.46",
        "unique_device_id": f"Google|{random.randint(1000000, 9999999)}-{random.randint(1000, 9999)}",
        "client_ip": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
        "language": "en",
        "open_id": str(open_id),
        "open_id_type": "4",
        "device_type": "Handheld",
        "access_token": str(access_token),
        "platform_sdk_id": 1,
        "network_operator_a": "Verizon",
        "network_type_a": "WIFI",
        "client_using_version": "7428b253defc164018c604a1ebbfebdf",
        "external_storage_total": 36235,
        "external_storage_available": 31335,
        "internal_storage_total": 2519,
        "internal_storage_available": 703,
        "game_disk_storage_available": 25010,
        "game_disk_storage_total": 26628,
        "external_sdcard_avail_storage": 32992,
        "external_sdcard_total_storage": 36235,
        "login_by": 3,
        "library_path": "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64",
        "reg_avatar": 1,
        "library_token": "5b892aaabd688e571f688053118a162b",
        "channel_type": 3,
        "cpu_type": 2,
        "cpu_architecture": "64",
        "client_version_code": "2019118695",
        "graphics_api": "OpenGLES2",
        "supported_astc_bitset": 16383,
        "login_open_id_type": 4,
        "analytics_detail": "FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg==",
        "loading_time": 13564,
        "release_channel": "android",
        "extra_info": "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY=",
        "android_engine_init_flag": 110009,
        "if_push": 1,
        "is_vpn": 1,
        "origin_platform_type": "4",
        "primary_platform_type": "4"
    }
    serialized = json.dumps(login_data).encode('utf-8')
    return encrypt_aes(serialized)

# ==================== PARSE MAJOR LOGIN RESPONSE ====================
def parse_major_login_response(data: bytes) -> dict:
    i = 0
    result = {"success": True}
    while i < len(data):
        header = data[i]
        field_num = header >> 3
        wire_type = header & 0x07
        i += 1
        if wire_type == 0:
            val, i = read_varint(data, i)
            if field_num == 1:
                result["account_uid"] = str(val)
        elif wire_type == 2:
            length, i = read_varint(data, i)
            if i + length <= len(data):
                value = data[i:i+length]
                i += length
                if field_num == 2:
                    result["region"] = value.decode()
                elif field_num == 8:
                    result["token"] = value.decode()
                elif field_num == 22:
                    result["key"] = value.hex()
                elif field_num == 23:
                    result["iv"] = value.hex()
    if "key" not in result:
        result["key"] = FIXED_KEY.hex()
    if "iv" not in result:
        result["iv"] = FIXED_IV.hex()
    return result

# ==================== LOGIN FUNCTION ====================
async def login_with_token(open_id: str, access_token: str) -> dict:
    encrypted_payload = build_major_login_payload(open_id, access_token)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(MAJOR_LOGIN_URL, data=encrypted_payload, headers=headers, ssl=ssl_context) as resp:
            if resp.status != 200:
                return {"success": False, "error": f"HTTP {resp.status}"}
            resp_data = await resp.read()
            try:
                decrypted = decrypt_aes(resp_data)
                result = parse_major_login_response(decrypted)
                result["open_id"] = open_id
                return result
            except Exception as e:
                return {"success": False, "error": f"Parse failed: {str(e)}"}

# ==================== API ENDPOINTS ====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        open_id = request.args.get('open_id')
        access_token = request.args.get('access_token')
    else:
        data = request.get_json()
        open_id = data.get('open_id') if data else None
        access_token = data.get('access_token') if data else None
    if not open_id or not access_token:
        return jsonify({"success": False, "error": "Missing open_id or access_token"}), 400
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(login_with_token(open_id, access_token))
    loop.close()
    return jsonify(result)

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "running",
        "service": "FF Login API",
        "endpoint": "/login?open_id=xxx&access_token=xxx"
    })

# ==================== FOR VERCEL ====================
app.debug = False
app.config['PROPAGATE_EXCEPTIONS'] = True

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
