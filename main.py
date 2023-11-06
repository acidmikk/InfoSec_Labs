import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from random import randint
from sqlalchemy.exc import IntegrityError
from cryptography.fernet import Fernet
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Используйте SQLite

db = SQLAlchemy(app)
database_url = 'sqlite:///database.db'
engine = create_engine(database_url)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    min_password_length = db.Column(db.Integer, default=0)
    password_expiration_months = db.Column(db.Integer, default=0)


login_manager = LoginManager()
login_manager.init_app(app)
key = '3p2sa-kHxKtOBeUAIeTDJ97MZ8wqBL2lSRprrfApHpc='.encode('utf-8')
fernet = Fernet(key)


def encrypt_data(data):
    encrypted_data = fernet.encrypt(data.encode('utf-8'))
    return encrypted_data


def decrypt_data(encrypted_data):
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/user/register', methods=['GET', 'POST'])
@login_required
def user_register():
    if current_user.role == 'admin':
        min_pass_length = randint(4, 10)
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = 'user'  # Устанавливаем роль "user" для обычного пользователя
            min_password_length = min_pass_length
            password_expiration_months = request.form['password_expiration_months']

            user = User(username=username, password=encrypt_data(password), role=role,
                        min_password_length=min_password_length, password_expiration_months=password_expiration_months)

            db.session.add(user)
            db.session.commit()
            flash('Пользователь зарегистрирован успешно', 'success')
            return redirect(url_for('dashboard'))

        return render_template('user_register.html', min_password_length=min_pass_length)
    else:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('login'))


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if not User.query.first():
        # Если в таблице нет записей, добавляем новую запись
        new_user = User(username='admin', password=encrypt_data('Qwerty'), role='admin',
                        min_password_length=4, password_expiration_months=1)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        session['username'] = user.username
        session['role'] = user.role
        session['user_id'] = user.id

        if user and decrypt_data(user.password) == password:
            login_user(user)
            flash('Вход успешно выполнен!', 'success')
            return redirect(url_for('dashboard'))  # Замените 'dashboard' на ваш маршрут для пользователей

        flash('Неправильное имя пользователя или пароль', 'danger')

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.filter_by(role='user').all()
        return render_template('user_panel.html', users=users, username=session['username'])
    else:
        return render_template('user_panel.html', username=session['username'])


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Выход выполнен успешно', 'success')
    session.clear()
    return redirect(url_for('login'))


@app.route('/change_user/<user_id>', methods=['POST'])
@login_required
def change_user(user_id):
    return render_template('user_panel_custom.html', username=session['username'],  user_id=user_id,
                           customuser=db.get_or_404(User, user_id).username)


# Маршрут для смены пароля
@app.route('/change_password/', methods=['POST'])
@app.route('/change_password/<user_id>', methods=['POST'])
@login_required
def change_password(user_id=''):
    if user_id == '':
        user_id = session['user_id']
    user = db.get_or_404(User, user_id)
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    if old_password == decrypt_data(user.password):
        if new_password == confirm_password:
            if len(new_password) > user.min_password_length:
                user.password = encrypt_data(new_password)
                user.verified = True
                db.session.commit()
                flash('Пароль изменен успешно', 'success')
                logout_user()
                return redirect(url_for('login'))
            else:
                flash(f'Пароль не удовлетворяет условиям длины: {user.min_password_length}', 'danger')
        else:
            flash('Пароли не совпадают', 'danger')
    else:
        flash('Неверный старый пароль', 'danger')


with app.app_context():
    db.create_all()
if __name__ == '__main__':
    app.run(debug=True)
