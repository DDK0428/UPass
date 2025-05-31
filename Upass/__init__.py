from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_qrcode import QRcode
from Upass.config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
QRcode(app)
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'

from Upass.User.routes import users
from Upass.Passwords.routes import passwords
from Upass.Main.routes import main
from Crypto.Cipher import AES

app.register_blueprint(users)
app.register_blueprint(passwords)
app.register_blueprint(main)


def password_decryption(de_key_f, nonce_f, tag_f, ciphertext_f):
    cipher = AES.new(de_key_f, AES.MODE_EAX, nonce=nonce_f)
    plaintext_f = cipher.decrypt(ciphertext_f)
    try:
        cipher.verify(tag_f)
        return str(plaintext_f, 'utf-8')
    except ValueError:
        raise ValueError


app.jinja_env.globals.update(password_decryption=password_decryption)
