from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from Upass import app
from Upass.models import User


class RegistrationForm(FlaskForm):
    f_name = StringField('First Name', validators=[DataRequired(), Length(4, 20)])
    l_name = StringField('Last Name', validators=[DataRequired(), Length(4, 20)])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=8), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        with app.app_context():
            user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is exists.')


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    otp = PasswordField('OTP', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Log In')
