from flask import Flask, request, redirect, url_for, session, render_template, flash, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, UserMixin
import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# Edit this line with your username and password
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
login = LoginManager()
login.init_app(app)
login.login_view = "login"

def encrypt(key, source, encode=True):
    key = key.encode("utf-8")
    source = source.encode("utf-8")
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(key, source, decode=True):
    key = key.encode("utf-8")
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])

    padding = data[-1]
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")
    return data[:-padding].decode("utf-8")

def numlist_to_str(numlist):
    return ",".join([str(i) for i in numlist])

def str_to_numlist(numlist):
    return [int(i) for i in numlist.split(",") if i != ""]

class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('login')

class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    password_verify = PasswordField('verify password', validators=[DataRequired()])
    submit = SubmitField('login')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(64))
    content = db.Column(db.String(32767))
    read = db.Column(db.String(32767), default="")

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/')
def index():
    session.pop("_flashes", None)
    return redirect(url_for("login"))

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if current_user.is_authenticated:
        return redirect(url_for("chat"))

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash("ERROR: Invalid login")
            return redirect(url_for("login"))

        login_user(user)
        next_page = request.args.get("next")
        if not next_page or url_parse(next_page).netloc != "":
            next_page = url_for("chat")

        return redirect(next_page)

    return render_template("login.html", form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    
    if current_user.is_authenticated:
        return redirect(url_for("chat"))
    
    if form.validate_on_submit():
        chk = User.query.filter_by(username=form.username.data).first()
        
        if chk is not None:
            flash("ERROR: User already registered")
            return redirect(url_for("register"))
        
        if form.password.data != form.password_verify.data:
            flash("ERROR: Passwords do not match")
            return redirect(url_for("register"))
        
        newuser = User(username=form.username.data)
        newuser.set_password(form.password.data)
        db.session.add(newuser)
        db.session.commit()
        
        return render_template("register_complete.html")
    
    return render_template("register.html", form=form)

@app.route('/chat')
@login_required
def chat():
    return render_template("chat.html")

@app.route('/chatview')
@login_required
def chatview():
    read = [x for x in Message.query.all() if current_user.id in str_to_numlist(x.read)]
    messages = []

    for m in read:
        author = User.query.filter_by(username=m.author).first()
        decrypted_content = decrypt(author.password_hash, m.content)
        messages.append({"author": author.username, "content": decrypted_content})

    return render_template("chatview.html", messages=messages)

@app.route("/message", methods=["POST"])
@login_required
def message():
    message = request.form.get("message")
    message = encrypt(current_user.password_hash, message)
    m = Message(author=current_user.username, content=message)
    db.session.add(m)
    db.session.commit()
    return "sent"

@app.route("/newmsg")
@login_required
def newmsg():
    new_msgs = [x for x in Message.query.all() if current_user.id not in str_to_numlist(x.read)]
    new_msgs_json = []

    for m in new_msgs:
        author = User.query.filter_by(username=m.author).first()
        decrypted_content = decrypt(author.password_hash, m.content)
        new_msgs_json.append({"author": author.username, "content": decrypted_content})
        new_read = str_to_numlist(m.read)
        new_read.append(current_user.id)
        m.read = numlist_to_str(new_read)

    db.session.commit()
    return Response(json.dumps(new_msgs_json), mimetype="application/json")

def send_msg(username, message):
    password_hash = User.query.filter_by(username=username).first().password_hash
    message = encrypt(password_hash, message)
    m = Message(author=username, content=message)
    db.session.add(m)
    db.session.commit()



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))
