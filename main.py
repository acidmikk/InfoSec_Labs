import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from random import randint
from cryptography.fernet import Fernet
import json
from hashlib import sha256
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
USERS_FILE = 'users.encrypt'
data = ''


class User:
    def __init__(self, username, password, role, min_password_length, password_expiration_months):
        self.username = username
        self.password_hash = self._hash_password(password)
        self.role = role
        self.min_password_length = min_password_length
        self.password_expiration_months = password_expiration_months
        self.created_at = datetime.datetime.now()

    @classmethod
    def _hash_password(cls, password):
        return sha256(password.encode('utf-8')).hexdigest()

    def save(self):
        users = self._get_all_users()
        users.append({
            'username': self.username,
            'password_hash': self.password_hash,
            'role': self.role,
            'min_password_length': self.min_password_length,
            'password_expiration_months': self.password_expiration_months,
            'created_at': self.created_at.isoformat()
        })
        self._write_users(users)

    @classmethod
    def find_by_username(cls, username):
        users = cls._get_all_users()
        for user in users:
            if user['username'] == username:
                return cls(
                    username=user['username'],
                    password='',
                    role=user['role'],
                    min_password_length=user['min_password_length'],
                    password_expiration_months=user['password_expiration_months']
                )

    @classmethod
    def find_by_id(cls, id):
        users = cls._get_all_users()
        for user in users:
            if user['id'] == id:
                return cls(
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

    @classmethod
    def _get_all_users(cls):
        try:
            with open(USERS_FILE, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    @classmethod
    def _write_users(cls, users):
        with open(USERS_FILE, 'w') as file:
            json.dump(users, file, indent=2)

    @classmethod
    def load_users_from_json(cls):
        with open(USERS_FILE, 'r') as file:
            users_data = json.load(file)
        return [User(**user_data) for user_data in users_data]


key = '3p2sa-kHxKtOBeUAIeTDJ97MZ8wqBL2lSRprrfApHpc='.encode('utf-8')
fernet = Fernet(key)


@app.before_first_request
def before_first_request():
    if not os.path.exists(USERS_FILE):
        initial_data = {
            'username': 'admin',
            'password_hash': sha256("qwerty".encode('utf-8')).hexdigest(),
            'role': 'admin',
            'min_password_length': 4,
            'password_expiration_months': 1,
            'created_at': datetime.datetime.now()
        }
        with open(USERS_FILE, 'wb') as json_file:
            json.dump(fernet.encrypt(str(initial_data).encode('utf-8')), json_file)
    with open(USERS_FILE, 'rb') as file:
        encrypted_data = json.load(file)
        return fernet.decrypt(encrypted_data).decode('utf-8')


@app.teardown_appcontext
def teardown_appcontext(exception=None):
    encrypted_data = fernet.encrypt(data.encode('utf-8'))
    with open(USERS_FILE, 'w') as file:
        json.dump(encrypted_data, file, indent=2)


@app.route('/user/register', methods=['GET', 'POST'])
@login_required
def user_register():
    if current_user.role == 'admin':
        min_pass_length = randint(4, 10)
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = 'user'  # Устанавливаем роль "user" для обычного пользователя
            min_password_length = request.form['min_password_length']
            password_expiration_months = request.form['password_expiration_months']

            user = User(username=username, password=password, role=role,
                        min_password_length=min_password_length, password_expiration_months=password_expiration_months)
            user.save()
            flash('Пользователь зарегистрирован успешно', 'success')
            return redirect(url_for('dashboard'))

        return render_template('user_register.html', min_password_length=min_pass_length)
    else:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('login'))


@app.route('/')
def index():
    return data


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not User._get_all_users():
        # Если в таблице нет записей, добавляем новую запись
        new_user = User(username='admin', password='Qwerty', role='admin',
                        min_password_length=4, password_expiration_months=1)
        new_user.save()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.find_by_username(username=username)
        if user and user.verify_password(password) and not user.is_password_expired():
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))  # Редирект на страницу после входа
        else:
            flash('Неправильное имя пользователя или пароль', 'danger')

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.filter_by(role='user').all()
        return render_template('user_panel.html', users=users, username=session['username'], user_id=session['user_id'])
    else:
        return render_template('user_panel.html', username=session['username'], user_id=session['user_id'])


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Выход выполнен успешно', 'success')
    return redirect(url_for('login'))


@app.route('/change_user/<int:user_id>')
@login_required
def change_user(user_id):
    return render_template('user_panel_custom.html', username=session['username'],  user_id=user_id,
                           customuser=User.find_by_id(user_id).username)


# Маршрут для смены пароля
@app.route('/change_password/<int:user_id>', methods=['POST'])
@login_required
def change_password(user_id):
    user = User.find_by_id(user_id)
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    if user.verify_password(new_password):
        if new_password == confirm_password:
            if len(new_password) > user.min_password_length:
                user.password = user._hash_password(new_password)
                user.verified = True
                flash('Пароль изменен успешно', 'success')
                if session['role'] != 'admin':
                    logout_user()
                    return redirect(url_for('login'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash(f'Пароль не удовлетворяет условиям длины: {user.min_password_length}', 'danger')
        else:
            flash('Пароли не совпадают', 'danger')
    else:
        flash('Неверный старый пароль', 'danger')


if __name__ == '__main__':
    app.run(debug=True)
