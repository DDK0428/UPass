from flask import render_template, url_for, request, redirect, flash, Blueprint
from Upass import bcrypt
from Upass.Main.forms import DatabaseForm
from Upass.models import User, Passwords
from Upass.rules import pad, decryption
from flask_login import current_user, login_required

main = Blueprint('main', __name__)


@main.route("/", methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if request.form.get('login') == 'Log In':
            return redirect(url_for('users.login'))
        elif request.form.get('register') == 'Register':
            return redirect(url_for('users.register'))
        elif request.form.get('logout') == 'Log Out':
            return redirect(url_for('users.logout'))
        elif request.form.get('get_started') == 'Get Started >':
            return redirect(url_for('users.register'))
        elif request.form.get('account') == 'Go to Account':
            return redirect('account')
        else:
            return redirect(url_for('main.home'))
    elif request.method == 'GET':
        return render_template('home.html')


@main.route('/password/database', methods=['GET', 'POST'])
@login_required
def database():
    form = DatabaseForm()
    user = User.query.filter_by(email=current_user.email).first()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(user.password, form.master_password.data):
            passwords = Passwords.query.filter_by(user_id=current_user.id).all()
            padded_password = pad(bytes(form.master_password.data, 'utf-8'))
            en_key = user.en_key
            nonce = user.key_nonce
            tag = user.key_tag
            key = decryption(padded_password, nonce, tag, en_key)
            return render_template('user.html', key=key, nonce=nonce, passwords=passwords)
        else:
            flash('Your master password is wrong! try again', 'danger')
    return render_template('database_access.html', form=form)
