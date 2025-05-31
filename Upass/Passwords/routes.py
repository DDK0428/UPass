from flask import render_template, url_for, request, redirect, flash, abort, Blueprint
from Upass import app, db, bcrypt
from Upass.Passwords.forms import AddPassword
from Upass.Main.forms import DatabaseForm
from Upass.models import User, Passwords
from Upass.rules import pad, encryption, decryption
from Upass.Password_Generation import password_generator
from flask_login import current_user, login_required

passwords = Blueprint('passwords', __name__)


@passwords.route("/password/new", methods=['GET', 'POST'])
@login_required
def new_password():
    form = AddPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=current_user.email).first()
        if bcrypt.check_password_hash(user.password, form.master_password.data):
            padded_password = pad(bytes(form.master_password.data, 'utf-8'))
            en_key = user.en_key
            nonce = user.key_nonce
            tag = user.key_tag
            key = decryption(padded_password, nonce, tag, en_key)
            en_passwd_nonce, en_passwd_tag, encrypted_password = encryption(key, bytes(form.password.data, 'utf-8'))
            password = Passwords(appname=form.appname.data, email=form.uname.data, password=encrypted_password,
                                 nonce=en_passwd_nonce, tag=en_passwd_tag, user_id=current_user.id)
            with app.app_context():
                db.session.add(password)
                db.session.commit()
            flash('Your password is added', 'success')
            return redirect(url_for('users.account'))
        else:
            flash('Your master password is not matched. Please try again', 'danger')
            return redirect(url_for('passwords.new_password'))
    return render_template('add_passwd.html', form=form)


@passwords.route("/password/generate", methods=['GET', 'POST'])
def gen_password():
    generated_password = password_generator()
    if request.method == 'POST':
        if request.form.get('re_password') == 'Reload New':
            return redirect(url_for('passwords.gen_password'))
    elif request.method == 'GET':
        return render_template('password_generator.html', generated_password=generated_password)


@passwords.route('/password/<int:password_id>/update', methods=['GET', 'POST'])
@login_required
def update_password(password_id):
    user = User.query.filter_by(email=current_user.email).first()
    form_0 = DatabaseForm()
    if form_0.validate_on_submit():
        if bcrypt.check_password_hash(user.password, form_0.master_password.data):
            password_update = Passwords.query.get_or_404(password_id)
            if password_update.user_id != current_user.id:
                abort(403)
            form = AddPassword()
            if form.validate_on_submit():
                if bcrypt.check_password_hash(user.password, form.master_password.data):
                    password_update.appname = form.appname.data
                    password_update.email = form.uname.data
                    padded_password = pad(bytes(form.master_password.data, 'utf-8'))
                    en_key = user.en_key
                    nonce = user.key_nonce
                    tag = user.key_tag
                    key = decryption(padded_password, nonce, tag, en_key)
                    en_passwd_nonce, en_passwd_tag, encrypted_password = encryption(key, bytes(form.password.data, 'utf-8'))
                    password_update.nonce = en_passwd_nonce
                    password_update.tag = en_passwd_tag
                    password_update.password = encrypted_password
                    db.session.commit()
                    flash('Your password updated successfully', 'success')
                    return redirect(url_for('users.account'))
                else:
                    flash('Your master password is wrong! try again', 'danger')
            form.appname.data = password_update.appname
            form.uname.data = password_update.email
            return render_template('add_passwd.html', form=form)
        else:
            flash('Your master password is wrong! try again', 'danger')
    return render_template('database_access.html', form=form_0)


@passwords.route('/password/<int:password_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_password(password_id):
    user = User.query.filter_by(email=current_user.email).first()
    form_0 = DatabaseForm()
    if form_0.validate_on_submit():
        if bcrypt.check_password_hash(user.password, form_0.master_password.data):
            password_delete = Passwords.query.get_or_404(password_id)
            if password_delete.user_id != current_user.id:
                abort(403)
            db.session.delete(password_delete)
            db.session.commit()
            flash('Your password has been deleted successfully', 'success')
            return redirect(url_for('users.account'))
        else:
            flash('Your master password is wrong! try again', 'danger')
    return render_template('database_access.html', form=form_0)
