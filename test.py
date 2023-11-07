import datetime
import json
import os
from hashlib import sha256

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

key = get_random_bytes(8)
print(key)
# Инициализируйте шифр DES в режиме ECB
cipher = DES.new(key, DES.MODE_ECB)

USERS_FILE = 'users.json'
if not os.path.exists(USERS_FILE):
    initial_data = {
        'username': 'admin',
        'password_hash': sha256("qwerty".encode('utf-8')).hexdigest(),
        'role': 'admin',
        'min_password_length': 4,
        'password_expiration_months': 1,
        'created_at': datetime.datetime.now().isoformat()
    }
    with open(USERS_FILE, 'wb') as json_file:
        encrypted_data = cipher.encrypt(json.dumps(initial_data).encode('utf-8'))
        json_file.write(encrypted_data)
with open(USERS_FILE, 'rb') as file:
    encrypted_data = file.read()
    data = json.loads(cipher.decrypt(encrypted_data).decode('utf-8'))


