from flask import Blueprint, render_template, request, flash, redirect, url_for
from . import db
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from .model import Data
import sys





main = Blueprint('main', __name__)

@main.route('/')
@login_required
def index():
    # return render_template('index2.html')
    return redirect(url_for('main.dashboard'))

@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)

@main.route('/dashboard')
@login_required
def dashboard():
    data = Data.query.filter_by(user = current_user.login)

    return render_template('dashboard.html', login=current_user.login, data=data )

@main.route('/add')
@login_required
def add_password():
    return render_template('add.html')

@main.route('/add', methods=['POST'])
@login_required
def post_add_password():
    
    site_name = request.form.get('site_name')
    username = request.form.get('username')
    password = request.form.get('password')
    user = current_user.login

    data = Data.query.filter_by(site_name=site_name, username=username, user=user).first()
    
    if data:
        flash('The username ' + username + ' has already been added for the site '+site_name)
        return redirect(url_for('main.add_password'))
    
    else:
        
        new_data='encrypted password' #TODO
        db.session.add(new_data)
        db.session.commit()

        return redirect(url_for('main.dashboard'))

@main.route('/remind')
def remind():
    return render_template('remind.html')

@main.route('/remind', methods=['POST'])
def post_remind():
    email = request.form.get('email')

    #TODO

    print('Wysłałabym maila na adres '+ email +' z adresem linku resetującego.', file=sys.stderr)
    return render_template('remind.html')


@app.route('/dashboard/pass/<id>', methods=["GET"])
@login_required
def dashboard_reveal(passed_id):
    if current_user is not None:
        data = Data.query.filter_by(id=passed_id)
        #dectrypt the password #TODO
        password = 'decrypted password should appear here'
    return password




        