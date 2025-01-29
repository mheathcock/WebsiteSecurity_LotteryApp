# IMPORTS
import logging
from datetime import datetime
from functools import wraps
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, request
from markupsafe import Markup
from app import db
from models import User
from users.forms import RegisterForm, LoginForm
import bcrypt
from flask import session
from flask_login import login_user, logout_user, current_user

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')

#REQUIRES ROLES wrapper function
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.is_authenticated: #Catches error if user isn't logged in and therefore has no role
                if current_user.role not in roles: ##if users role is not in the permitted role
                    logging.warning('SECURITY INVALID ACCESS ATTEMPT [%s, %s, %s, %s]', current_user.id, current_user.email, current_user.role,
                                    request.url) ##sends warning to log
                    return render_template('errors/403.html')
                return f(*args, **kwargs)
            else: ##if the user is anonymous it will send them straight back to the homepage
                return redirect(url_for('index'))
        return wrapped
    return wrapper


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user'
                        )

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        logging.warning('SECURITY USER REGISTRATION [%s, %s]', form.email.data, request.remote_addr) ##sends info to log file
        # sends user to login page
        return redirect(url_for('users.login'))#redirects user to login
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    form = LoginForm()
    if form.validate_on_submit():

        user = User.query.filter_by(email=form.username.data).first() #gets info from database about inputted username

        if not user or not bcrypt.checkpw(form.password.data.encode('utf-8'), user.password) or not pyotp.TOTP(  #If input of the password or the pin doesnt match
                user.pinkey).verify(form.pin.data):
            logging.warning('SECURITY INVALID LOGIN [%s, %s]', form.username.data, request.remote_addr) #log the attempt
            session['authentication_attempts'] += 1 #and increase the amount of attempts by 1
            loginattemptsremaining = 3 - session.get('authentication_attempts') #- 1 from the attempts remaining
            if session.get('authentication_attempts') >= 3:
                flash(Markup(
                    'Number of incorrect login attempts exceeded. Please click <a href=/reset>Reset</a>'))#if they try too many times and fail their account is locked
                return render_template('users/login.html')
            flash('Please check your login details and try again,{} attempts remaining'.format(loginattemptsremaining))#tells user that their login details are wrong
            return render_template('users/login.html', form=form)
        else:
            login_user(user)#if login passes then the user is logged in and relevant info is stored in the database

            user_role = current_user.role
            user.last_login = user.current_login
            user.current_login = datetime.now()
            user.last_login = user.current_login
            db.session.add(user)
            db.session.commit()
            logging.warning('SECURITY USER LOGIN [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)#info sent to the log

        if user_role == 'admin':
            return redirect(url_for('admin.admin'))
        else:
            return redirect(url_for('users.profile'))
    return render_template('users/login.html', form=form)


# view user profile


@users_blueprint.route('/profile')
@requires_roles('user')
def profile():
    return render_template('users/profile.html', name=current_user.firstname)


# view user account
@users_blueprint.route('/account')
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)


@users_blueprint.route('/reset')

def reset():#a reset function that unlocks users account by setting the authentication attempts back to 0
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


@users_blueprint.route('/logout')
def logout():
    logging.warning('SECURITY USER LOGOUT [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)#sends info to log
    logout_user()

    return redirect(url_for('index'))
