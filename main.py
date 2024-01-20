# Author: Dennis
# Date: 2024/01/20
# Description: 通过ubus接口获取路由器的外网ip
import logging
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import binascii

router_url = 'http://192.168.2.1/ubus'
default_token = "00000000000000000000000000000000"
aes_iv = "poiewjhw49q35j4n"
routerd = "routerd"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def get_key_index_rand_key():
    body = {"jsonrpc": "2.0", "method": "call",
            "params": [default_token, routerd, "get_rand_key", {}]}
    res = requests.post(url=router_url, json=body).json()
    rand_key = res['result'][1]['rand_key']
    key_index = rand_key[0:32]
    rand_key = rand_key[32:64]
    return key_index, rand_key


def _encode(pwd, rand_key, key_index):
    key = bytes.fromhex(rand_key)
    iv = bytes(aes_iv, 'latin1')
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(pwd.encode('utf-8')) + padder.finalize()
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    cipher_text = binascii.hexlify(ciphertext).decode('utf-8')
    return key_index + cipher_text


def login(username, password):
    body = {"jsonrpc": "2.0", "method": "call", "params": [default_token, routerd, "login",
                                                           {"username": username,
                                                            "password": password}]}
    res = requests.post(url=router_url, json=body).json()
    return res["result"][1]["ubus_rpc_session"]


def logout(token_id):
    body = {"jsonrpc": "2.0", "method": "call",
            "params": [token_id, "session", "destroy", {}]}
    requests.post(url=router_url, json=body).json()


def get_token_id(username, password):
    key_index, rand_key = get_key_index_rand_key()
    password = _encode(password, rand_key, key_index)
    return login(username, password)


def get_ip(username, password):
    token_id = get_token_id(username, password)
    body = {"jsonrpc": "2.0", "method": "call", "params": [token_id, "routerd", "router_info", {}]}
    ip = requests.post(url=router_url, json=body).json()['result'][1]['WanInfo']['Ipv4']['Ip']
    # logout(token_id)
    logging.info(f"current ip:{ip}")
    return ip


if __name__ == '__main__':
    # 用户名写死
    username = "useradmin"
    password = "<YOUR_PASSWORD>"
    print(get_ip(username, password))
