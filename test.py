import datetime
import json
import os
import re
from hashlib import sha256

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

key = b'\x01{i\x9e\xc7d\xec\x19'
# Инициализируйте шифр DES в режиме ECB
cipher = DES.new(key, DES.MODE_ECB)

USERS_FILE = 'users.json'
if not os.path.exists(USERS_FILE):
    initial_data = {1: {
        'id': 1,
        'username': 'admin',
        'password_hash': sha256("qwerty".encode('utf-8')).hexdigest(),
        'role': 'admin',
        'min_password_length': 4,
        'password_expiration_months': 1,
        'created_at': datetime.datetime.now().isoformat()
    }}
    with open(USERS_FILE, 'wb') as json_file:
        data = json.dumps(initial_data).encode('utf-8')
        block_size = 8  # Размер блока DES
        padding = block_size - len(data) % block_size
        data += b'\x00' * padding
        encrypted_data = cipher.encrypt(data)
        json_file.write(encrypted_data)
with open(USERS_FILE, 'rb') as file:
    encrypted_data = file.read()
    data = cipher.decrypt(encrypted_data).rstrip(b'\x00').decode('utf-8')
    data = json.loads(data)


class User:
    def __init__(self, user_id, username, password, role, min_password_length, password_expiration_months):
        self.id = user_id
        self.username = username
        self.password_hash = self._hash_password(password)
        self.role = role
        self.min_password_length = min_password_length
        self.password_expiration_months = password_expiration_months
        self.created_at = datetime.datetime.now()

    @staticmethod
    def _hash_password(password):
        return sha256(password.encode('utf-8')).hexdigest()

    def save(self, user_id=len(data) + 1):
        data[user_id] = {
            'id': self.id,
            'username': self.username,
            'password_hash': self.password_hash,
            'role': self.role,
            'min_password_length': self.min_password_length,
            'password_expiration_months': self.password_expiration_months,
            'created_at': self.created_at.isoformat()
        }

    def change_password(self, password):
        self.password_hash = self._hash_password(password)
        self.save(self.id)

    @classmethod
    def find_by_username(cls, username):
        users = data
        for user_id in users:
            if users[user_id]['username'] == username:
                return cls(
                    user_id=users[user_id]['id'],
                    username=users[user_id]['username'],
                    password='',
                    role=users[user_id]['role'],
                    min_password_length=users[user_id]['min_password_length'],
                    password_expiration_months=users[user_id]['password_expiration_months']
                )

    @classmethod
    def find_by_id(cls, user_id):
        user = data[user_id]
        return cls(
            user_id=user['id'],
            username=user['username'],
            password='',
            role=user['role'],
            min_password_length=user['min_password_length'],
            password_expiration_months=user['password_expiration_months']
        )

    def verify_password(self, password):
        return self._hash_password(password) == self.password_hash

    def is_password_expired(self):
        if self.password_expiration_months:
            expiration_date = self.created_at + datetime.timedelta(days=30 * self.password_expiration_months)
            return datetime.datetime.now() > expiration_date
        return False

    def is_password_length_valid(self, password):
        return len(password) >= self.min_password_length

    @staticmethod
    def _get_all_users():
        return data.values()


def check_password(password):
    if re.search(r"[0-9]", password) and re.search(r"[.,;:!?]", password) and re.search(r"[+\-*/]", password):
        return True
    return False


print(check_password('qwerty1-.'))
