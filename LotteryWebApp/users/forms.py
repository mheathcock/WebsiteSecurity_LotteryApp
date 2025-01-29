from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, ValidationError, Length, EqualTo
import re

from flask_wtf import RecaptchaField


class RegisterForm(FlaskForm):
    def validate_password(self, field):  # a validate password function
        pcheck = re.compile(
            "(?=.*\d)(?=.*[A-Z])(?=.*[a-z])")  # a regex of the must include characters: a lowercase, an uppercase,
        # a number and a special character
        if not pcheck.match(field.data):  # if any of these included characters are not in the password show an error
            raise ValidationError(
                "Password must contain at least one digit, one lowercase, one uppercase and a special character")

    def character_check(self, field):  # a character check function to ensure excluded characters aren't inputted
        # excluded characters
        excluded_char = "* ? ! ' ^ + % & / ( ) = } ] [ { $ # @ < >"
        # for loop that goes through each character in the field input
        # and checks if that char is also in the excluded chars
        for char in field.data:
            if char in excluded_char:
                raise ValidationError(f"Character {char} is not allowed.")

    def validate_phoneNum(self, phone):  # a function to validate the inputted phone number is in the correct format

        p = re.compile(
            "\d{4}[-]??\d{3}[-]??\d{4}")  # a regex statement that says the phone number must be in the format of
        # XXXX-XXX-XXXX
        if not p.match(phone.data):
            raise ValidationError("phone number doesnt match XXXX-XXX-XXXX")

    # Fields and their included validators
    email = StringField('Email', validators=[Email(), DataRequired()])
    firstname = StringField(validators=[DataRequired(), character_check])
    lastname = StringField(validators=[DataRequired(), character_check])
    phone = StringField(validators=[DataRequired(), validate_phoneNum])
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), validate_password])

    confirm_password = PasswordField(validators=[DataRequired(), Length(min=6, max=12),
                                                 EqualTo('password', message='Both password fields must be equal!')])

    submit = SubmitField()


class LoginForm(FlaskForm):
    # Fields and their included validators
    recaptcha = RecaptchaField()
    username = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired()])
    submit = SubmitField()
