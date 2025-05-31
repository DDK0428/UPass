from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired


class DatabaseForm(FlaskForm):
    master_password = PasswordField(validators=[DataRequired()])
    submit = SubmitField('Continue')
