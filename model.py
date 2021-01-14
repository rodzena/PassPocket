from . import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(100), unique = True)
    login = db.Column(db.String(1000), unique = True)
    password = db.Column(db.String(100))
    

class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    user = db.Column(db.String(100))

