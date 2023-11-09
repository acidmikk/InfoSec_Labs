import os
import re

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from random import randint
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import json
from hashlib import md5
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
USERS_FILE = 'users.json'
data = {}
# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, user_id, username, password, role, min_password_length, password_expiration_months):
        self.id = user_id
        self.username = username
        self.password_hash = password
        self.role = role
        self.min_password_length = min_password_length
        self.password_expiration_months = password_expiration_months
        self.created_at = datetime.datetime.now()

    @staticmethod
    def _hash_password(password):
        return md5(password.encode('utf-8')).hexdigest()

    def save(self, user_id=None):
        if user_id is None:
            user_id = str(len(data) + 1)
        if data.get(user_id):
            data[user_id] = {
                'id': self.id,
                'username': self.username,
                'password_hash': self.password_hash,
                'role': self.role,
                'min_password_length': self.min_password_length,
                'password_expiration_months': self.password_expiration_months,
                'created_at': self.created_at.isoformat()
            }
        else:
            data[user_id] = {
                'id': self.id,
                'username': self.username,
                'password_hash': self._hash_password(self.password_hash),
                'role': self.role,
                'min_password_length': self.min_password_length,
                'password_expiration_months': self.password_expiration_months,
                'created_at': datetime.datetime.now().isoformat()
            }

    def change_password(self, password):
        self.password_hash = self._hash_password(password)
        self.save(str(self.id))

    @classmethod
    def find_by_username(cls, username):
        for user_id in data:
            if data[user_id]['username'] == username:
                return cls(
                    user_id=data[user_id]['id'],
                    username=data[user_id]['username'],
                    password=data[user_id]['password_hash'],
                    role=data[user_id]['role'],
                    min_password_length=data[user_id]['min_password_length'],
                    password_expiration_months=data[user_id]['password_expiration_months']
                )

    @classmethod
    def find_by_id(cls, user_id=str):
        user = data[user_id]
        return cls(
            user_id=user['id'],
            username=user['username'],
            password=user['password_hash'],
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

    def password_length_valid(self):
        return len(self.password_hash) >= int(self.min_password_length)

    @staticmethod
    def _get_all_users():
        return data.values()


key = b''
cipher = DES.new(key, DES.MODE_ECB)


# @app.before_first_request
# def init_app():
#     if not os.path.exists(USERS_FILE):
#         initial_data = {1: {
#             'id': 1,
#             'username': 'admin',
#             'password_hash': sha256("qwerty".encode('utf-8')).hexdigest(),
#             'role': 'admin',
#             'min_password_length': 4,
#             'password_expiration_months': 1,
#             'created_at': datetime.datetime.now().isoformat()
#         }}
#         write_in_json(initial_data)
#     with open(USERS_FILE, 'rb') as file:
#         encrypted_data = file.read()
#         data = json.loads(cipher.decrypt(encrypted_data).rstrip(b'\x00').decode('utf-8'))


@app.route('/write_in_json')
def write_in_json(init_data=None):
    if init_data is None:
        init_data = data
    with open(USERS_FILE, 'wb') as json_file:
        write_data = json.dumps(init_data).encode('utf-8')
        block_size = 8  # Размер блока DES
        padding = block_size - len(write_data) % block_size
        write_data += b'\x00' * padding
        encrypted_data = cipher.encrypt(write_data)
        json_file.write(encrypted_data)
    return redirect(request.referrer)


@login_manager.user_loader
def load_user(user_id):
    return User.find_by_id(user_id)


def check_password(password):
    if re.search(r"[0-9]", password) and re.search(r"[.,;:!?]", password) and re.search(r"[+\-*/]", password):
        return True
    return False


@app.route('/user/register', methods=['GET', 'POST'])
@login_required
def user_register():
    if session['role'] == 'admin':
        min_pass_length = randint(4, 10)
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = 'user'  # Устанавливаем роль "user" для обычного пользователя
            min_password_length = request.form['min_password_length']
            password_expiration_months = request.form['password_expiration_months']
            user_id = str(int(list(data.keys())[-1]) + 1)
            user = User(user_id=user_id, username=username, password=password, role=role,
                        min_password_length=min_password_length, password_expiration_months=password_expiration_months)
            if not (check_password(password) and user.password_length_valid()):
                flash('Пароль должен содержать хотя бы одну цифру, знак препинания и знак арифметической операций '
                      'и быть не короче указанной длины', 'danger')
                return redirect(request.referrer)
            user.save(user_id=user_id)
            flash('Пользователь зарегистрирован успешно', 'success')
            return redirect(url_for('dashboard'))

        return render_template('user_register.html', min_password_length=min_pass_length)
    else:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('login'))


@app.route('/')
def index():
    if not os.path.exists(USERS_FILE):
        initial_data = {1: {
            'id': 1,
            'username': 'admin',
            'password_hash': md5('qwerty'.encode('utf-8')).hexdigest(),
            'role': 'admin',
            'min_password_length': 0,
            'password_expiration_months': 1,
            'created_at': datetime.datetime.now().isoformat()
        }}
        write_in_json(initial_data)
    if not os.path.exists('key.txt'):
        with open('key.txt', 'wb') as file:
            file.write(b't\x83^\x02\xa4 J' + get_random_bytes(1))
    with open('key.txt', 'rb') as file:
        global key
        key = file.read()
    if not current_user:
        return render_template('login.html')
    return render_template("index.html", username=session['username'], user_id=session['user_id'],
                           user_role=session['role'])


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/lab_2')
def lab_2():
    return render_template('lab_2.html')


@app.route('/reset_data')
@login_required
def reset_data():
    global data
    if not os.path.exists(USERS_FILE):
        initial_data = {1: {
            'id': 1,
            'username': 'admin',
            'password_hash': md5('qwerty'.encode('utf-8')).hexdigest(),
            'role': 'admin',
            'min_password_length': 0,
            'password_expiration_months': 1,
            'created_at': datetime.datetime.now().isoformat()
        }}
        write_in_json(initial_data)
    with open(USERS_FILE, 'rb') as file:
        encrypted_data = file.read()
        data = json.loads(cipher.decrypt(encrypted_data).rstrip(b'\x00').decode('utf-8'))
    return data


@app.route('/show_data')
def show_data():
    return data


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.find_by_username(username=username)
        if user and user.verify_password(password) and not user.is_password_expired():
            session['username'] = user.username
            session['role'] = user.role
            login_user(user)
            return redirect(url_for('dashboard'))  # Редирект на страницу после входа
        else:
            flash('Неправильное имя пользователя или пароль', 'danger')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = data.values()
        return render_template('user_panel.html', users=users, username=session['username'], user_id=session['user_id'])
    else:
        return render_template('user_panel.html', username=session['username'], user_id=session['user_id'])


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    logout_user()
    flash('Выход выполнен успешно', 'success')
    return redirect(url_for('login'))


@app.route('/change_user/<string:user_id>')
@login_required
def change_user(user_id):
    return render_template('user_panel_custom.html', username=session['username'],  user_id=user_id,
                           customuser=User.find_by_id(user_id).username)


# Маршрут для смены пароля
@app.route('/change_password/<string:user_id>', methods=['POST'])
@login_required
def change_password(user_id):
    user = User.find_by_id(user_id)
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    if user.verify_password(old_password):
        if new_password == confirm_password:
            if user.is_password_length_valid(new_password):
                user.change_password(new_password)
                flash('Пароль изменен успешно', 'success')
                if session['role'] != 'admin':
                    logout_user()
                    return redirect(url_for('login'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash(f'Пароль не удовлетворяет условиям длины: {user.min_password_length}', 'danger')
                return redirect(request.referrer)
        else:
            flash('Пароли не совпадают', 'danger')
            return redirect(request.referrer)
    else:
        flash('Неверный старый пароль', 'danger')
        return redirect(request.referrer)


if __name__ == '__main__':
    app.run(debug=True)
