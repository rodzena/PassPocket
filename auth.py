from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash  
from .model import User
from . import db
from flask_login import login_user, logout_user, login_required
import time 

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    #login code
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        flash('Login failed. Try again.')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)    
    # time.sleep(3) --commented out for now, it's annoying

    return redirect(url_for('main.dashboard'))

@auth.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out successfully.')
    return redirect(url_for('main.index'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    #validate and add user
    email = request.form.get('email')
    login = request.form.get('login')
    password = request.form.get('password')

    user = User.query.filter_by(email = email).first()
    if user:
        flash('Email already registered')
        return redirect(url_for('auth.signup'))

    #add entropy check here #TODO
    if len(password) < 8:
        flash('Password too weak. Try using a more secure password.')
        return redirect(url_for('auth.signup'))

    new_user = User(email=email, login=login, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))