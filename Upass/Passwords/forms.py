from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired


class AddPassword(FlaskForm):
    appname = StringField(validators=[DataRequired()])
    uname = StringField(validators=[DataRequired()])
    password = PasswordField(id="password", validators=[DataRequired()])
    master_password = PasswordField(validators=[DataRequired()])
    submit = SubmitField('Add Password')
