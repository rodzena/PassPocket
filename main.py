from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from . import db
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from .model import Data
import sys





main = Blueprint('main', __name__)

@main.route('/',methods=['POST','GET'])
@login_required
def index():
    data = Data.query.filter_by(user = current_user.login)

    if request.method == 'POST' and session['master'] == True:
#     and request.form['submit'] == 'submit_add':
#  :
        # if request.form['submit'] == 'Ok':
        #     print("hej!")
        #     return render_template('dashboard.html', show = True, login="master tak!", data=data)

        #TUTAJ TRZEBA ZROBIĆ TAK, ŻEBY JAK PO ODKRYCIU PODAM NOWE MASTER TO SIĘ NIE WYKRZACZAŁO 
            

            id = request.form.get("id","")
            print("Halko!"+id)
            session['show'] = True

            pas_hashed = Data.query.filter_by(id=id).first().password
            
            #decode it here

            pass_unhashed = pas_hashed


            return render_template('dashboard.html', id=id, master=session['master'],show=session['show'], login=current_user.login, data=data, pass_unhashed=pass_unhashed)
    # return render_template('index2.html')

    return render_template('dashboard.html', login=current_user.login, data=data, master =session['master'], show=session['show'] )

# @main.route('/show', methods=['POST'])
# @login_required
# def show():
#     id = request.form.get("id","")
#     session['show'] = True
#     session['id'] = id
#     return redirect(url_for('main.index'))


@main.route('/master', methods=['POST'])
@login_required
def master():
    if current_user is not None and request.form.get('master_password') is not None:
        session['master']=True
        print("ELOELO")
    return redirect(url_for('main.index'))

# @main.route('/profile')
# @login_required
# def profile():
#     return render_template('profile.html', name=current_user.name)

# @main.route('/dashboard')
# @login_required
# def dashboard():
#     data = Data.query.filter_by(user = current_user.login)

#     return render_template('dashboard.html', login=current_user.login, data=data )

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
        
        new_data=Data(site_name=site_name, username=username,password = 'encrypted password',user = user) #TODO
        db.session.add(new_data)
        db.session.commit()

        return redirect(url_for('main.index'))

@main.route('/remind')
def remind():
    return render_template('remind.html')

@main.route('/remind', methods=['POST'])
def post_remind():
    email = request.form.get('email')
    #TODO
    print('Wysłałabym maila na adres '+ email +' z adresem linku resetującego.', file=sys.stderr)
    return render_template('remind.html')





@main.route('/dashboard/pass/<id>', methods=["GET"])
@login_required
def dashboard_reveal(passed_id):
    if current_user is not None:
        data = Data.query.filter_by(id=passed_id)
        #dectrypt the password #TODO
        password = 'decrypted password should appear here'
    return password

# @main.route('/show', methods=["POST"])
# def show():
#     id = request.form.get("id","")
#     return render_template('dashboard.html', id=id, show = True,login=current_user.login, data=data)
