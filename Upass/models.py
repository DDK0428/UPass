from Upass import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    en_key = db.Column(db.String, nullable=False)
    key_nonce = db.Column(db.String, nullable=False)
    key_tag = db.Column(db.String, nullable=False)
    en_otp = db.Column(db.String, nullable=False)
    otp_nonce = db.Column(db.String, nullable=False)
    otp_tag = db.Column(db.String, nullable=False)
    rel = db.relationship('Passwords', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.email, self.en_key, self.key_nonce, self.key_tag, self.en_otp, self.otp_nonce, self.otp_tag}')"


class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appname = db.Column(db.String, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String, nullable=False)
    nonce = db.Column(db.String, nullable=False)
    tag = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Passwords('{self.id, self.appname, self.email, self.password, self.nonce, self.tag}')"
