from flask import render_template, url_for, request, redirect, flash, Blueprint
from Upass import app, db, bcrypt
from Upass.User.forms import RegistrationForm, LoginForm
from Upass.models import User
from Upass.rules import key_creation, pad, encryption, decryption
from flask_login import login_user, current_user, logout_user, login_required
import pyotp


users = Blueprint('users', __name__)


@users.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            padded_password = pad(bytes(form.password.data, 'utf-8'))
            otp_secret = str(decryption(padded_password, user.otp_nonce, user.otp_tag, user.en_otp), 'utf-8')
            if bcrypt.check_password_hash(user.password, form.password.data):
                if pyotp.TOTP(otp_secret).verify(int(form.otp.data)):
                    login_user(user, remember=False)
                    next_page = request.args.get('next')
                    return redirect(next_page) if next_page else redirect(url_for('main.home'))
                else:
                    flash('Entered OTP is invalid! Login unsuccessful', 'danger')
            else:
                flash('Entered password is invalid! Login unsuccessful', 'danger')
        else:
            flash('Entered email is invalid! Login unsuccessful', 'danger')
    return render_template('login.html', form=form)


@users.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        padded_password = pad(bytes(form.password.data, 'utf-8'))
        key = key_creation()
        key_nonce, key_tag, encrypted_key = encryption(padded_password, key)
        otp_secret = pyotp.random_base32()
        totp_auth = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=form.f_name.data, issuer_name='Upass')
        b_otp_secret = bytes(otp_secret, 'utf-8')
        otp_nonce, otp_tag, encrypted_otp = encryption(padded_password, b_otp_secret)
        del key, padded_password
        user = User(first_name=form.f_name.data, last_name=form.l_name.data, email=form.email.data,
                    password=hashed_password, en_key=encrypted_key, key_nonce=key_nonce, key_tag=key_tag,
                    en_otp=encrypted_otp, otp_nonce=otp_nonce, otp_tag=otp_tag)
        with app.app_context():
            db.session.add(user)
            db.session.commit()
        flash('Your account created successfully! Set up 2FA and log back in', 'success')
        return render_template('register_2fa.html', otp_secret=otp_secret, totp_auth=totp_auth)
    return render_template('register.html', form=form)


@users.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))


@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        if request.form.get('add_password') == 'Add Password':
            return redirect(url_for('passwords.new_password'))
        elif request.form.get('generate_password') == 'Generate a Password':
            return redirect(url_for('passwords.gen_password'))
        elif request.form.get('access_database') == 'Access the Database':
            return redirect(url_for('main.database'))
        elif request.form.get('logout') == 'Log Out':
            return redirect(url_for('users.logout'))
        else:
            return redirect('account')
    if request.method == 'GET':
        return render_template('account.html')
