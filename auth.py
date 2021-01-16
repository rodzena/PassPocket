from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash  
from .model import User
from . import db
from flask_login import login_user, logout_user, login_required
from datetime import timedelta
import time 
# from .__init__ import limiter

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
# @limiter.limit("1/second", error_message='chill!')
def login_post():
    #login code
    # if 'new' not in session:
    #     login_attempt = 0
    #     session['new'] = False
    # session['attempt'] += 1
    # if 'attempts' not in session:
    #     session['attempts'] = 5
    # session['attempts'] += 1
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    prohibited = ['<', '>','/','-','=','#',  ]

    # any_email = any()
    # session['attempts'] = 0
    # session['attempts'] = 5
    session['is_master'] = False
    session['show'] = False

    user = User.query.filter_by(email=email).first()
    

    # if not user:
        
    
    if user:
        print('jest! user!')
        # if check_password_hash(user.password, password):
        #     print('jest! dobrze!')
        #     user.incorrect_attempts = 0
        #     db.session.commit()
        #     login_user(user=user, remember=remember)
        if user.incorrect_attempts >= 5:
            flash('You\'ve exceeded the loggin attempt limit of 5. Your account has been blocked.') 
            return redirect(url_for('auth.login'))
        elif not check_password_hash(user.password, password): #niepoprawne hasło
            user.incorrect_attempts += 1
            db.session.commit()
            flash('Login failed. Try again.')
            return redirect(url_for('auth.login'))     
        # elif user.incorrect_attempts >= 5:  #może i poprawne hasło ale za dużo prób logowania było.
        #     flash('You\'ve exceeded the loggin attempt limit of 5. Your account has been blocked.') 
        #     return redirect(url_for('auth.login'))
        else:
            print('jest! dobrze!')
            user.incorrect_attempts = 0
            db.session.commit()
            login_user(user=user, remember=remember)
            return redirect(url_for('main.index'))
    
    flash('Login failed. Try again.')
    return redirect(url_for('auth.login'))

@auth.route('/logout')
def logout():
    # session['master']=False
    session['attempts'] = 5
    session['is_master']=False
    session['master_pass'] = None
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