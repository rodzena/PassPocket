from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from . import db
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from .model import Data
import sys, os
import bcrypt
import Crypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


main = Blueprint('main', __name__)

@main.route('/',methods=['POST','GET'])
@login_required
def index():
    session['show'] = False
    data = Data.query.filter_by(user = current_user.login)

    if request.method == 'POST' and session['is_master'] == True and session['master_pass'] != '':
        #TUTAJ TRZEBA ZROBIĆ TAK, ŻEBY JAK PO ODKRYCIU PODAM NOWE MASTER TO SIĘ NIE WYKRZACZAŁO 
            print("WESZŁAM TU TERAZ HEHE")
            id = request.form.get("id","")
            print("Halko!"+id)
            session['show'] = True

            password = Data.query.filter_by(id=id).first().password
            hash = Data.query.filter_by(id=id).first().hash

            #decode it here
            # def decrypt(hashed, master, encrypted):
            pass_decoded = decrypt(hash, session['master_pass'], password)

            return render_template('dashboard.html', id=id, is_master=session['is_master'],show=session['show'], login=current_user.login, data=data, pass_unhashed=pass_decoded)
    # return render_template('index2.html')

    return render_template('dashboard.html', login=current_user.login, data=data, is_master=session['is_master'], show=session['show'] )

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
    session['show'] = False
    # session['is_master'] = False
    if current_user is not None and request.form.get('master_password') is not None:
        is_master=session['is_master']=True
        session['master_pass'] = request.form.get('master_password')
        print('master pass dodany do session jako' + session['master_pass'])
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
    session['show'] = False 
    site_name = request.form.get('site_name')
    username = request.form.get('username')
    password = request.form.get('password')
    master_password = request.form.get('master_password')
    user = current_user.login

    # print(site_name)
    # print(username)
    # print(password)
    # print(master_password)

    data = Data.query.filter_by(site_name=site_name, username=username, user=user).first()
    
    if site_name == '' or username == '' or password == '' or master_password =='':
        flash('Fill in all the inputs!')
        return redirect(url_for('main.add_password'))

    if data:
        flash('The username ' + username + ' has already been added for the site '+site_name)
        return redirect(url_for('main.add_password'))
    
    else:
        encrypted, hashed = encrypt(password, master_password)
        print('zahaszowane z master password ' +master_password)
        new_data=Data(site_name=site_name, username=username,password = encrypted, user = user, hash = hashed) #TODO
        db.session.add(new_data)
        db.session.commit()

        return redirect(url_for('main.index'))




def encrypt(password, master):
    master = fix_size(master)
    password = password.encode('utf-8')
    iv = master.encode('utf-8')
    salt = bcrypt.gensalt()

    hashed = bcrypt.hashpw(password, salt)
    key = hashed[:16]
    # .encode('utf-8')
    # key = key.encode('utf-8')
    
    aes = AES.new(key, AES.MODE_CFB, iv)
    encrypted = aes.encrypt(password)
    return encrypted, hashed

def decrypt(hashed, master, encrypted):
    iv = fix_size(master).encode('utf-8')
    key = hashed[:16]
    # .encode('utf-8')

    aes = AES.new(key, AES.MODE_CFB, iv)

    decrypted = aes.decrypt(encrypted)
    # decrypted = decrypted[2:-1]
    try:
        decrypted = decrypted.decode('utf-8')
    except:
        decrypted = "Your masterpass \nseems to be wrong."
        
    # .decode('utf-8')
    return decrypted

def fix_size(master):
    if len(master) < 16:
        i = 0
        x = len(master)
        while len(master) < 16:
            master += master[i]
            i += 1 
            if i == x:
                i = 0
    elif len(master) > 16:
        master = master[:16]
    
    return master


    # salt = bcrypt.gensalat(rounds=7)
    # hashed = bcrypt.hashpw(password, salt)

    # iv = get_random_bytes(16) 
    # aes = AES.new(hashed, AES.MODE_CFB, iv)

    # des = DES.new("key12345") 







@main.route('/remind')
def remind():
    return render_template('remind.html')

@main.route('/remind', methods=['POST'])
def post_remind():
    email = request.form.get('email')
    #TODO
    print('Wysłałabym maila na adres '+ email +' z adresem linku resetującego.', file=sys.stderr)
    return render_template('remind.html')





# @main.route('/dashboard/pass/<id>', methods=["GET"])
# @login_required
# def dashboard_reveal(passed_id):
#     if current_user is not None:
#         data = Data.query.filter_by(id=passed_id)
#         #dectrypt the password #TODO
#         password = 'decrypted password should appear here'
#     return password

# # @main.route('/show', methods=["POST"])
# # def show():
# #     id = request.form.get("id","")
# #     return render_template('dashboard.html', id=id, show = True,login=current_user.login, data=data)

