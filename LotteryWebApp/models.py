import logging
from datetime import datetime

import pyotp
from flask_login import UserMixin
from app import db, app
import bcrypt
from cryptography.fernet import Fernet

# Logging info
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('lottery.log', 'a')  # says which file is the log file
file_handler.setLevel(logging.WARNING)


# Filter for log
class SecurityFilter(logging.Filter):
    def filter(self, record):
        return 'SECURITY' in record.getMessage()


file_handler.addFilter(SecurityFilter())
formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


# function to encrypt data
def encrypt(data, secret_key):
    data_b = bytes(data, "utf-8")
    return Fernet(secret_key).encrypt(data_b)


# function to decrypt data
def decrypt(data, secret_key):
    return Fernet(secret_key).decrypt(data).decode("utf-8")


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')
    secret_key = db.Column(db.BLOB)
    pinkey = db.Column(db.String(100), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    current_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    # Define the relationship to Draw
    draws = db.relationship('Draw')

    # init function
    def __init__(self, email, firstname, lastname, phone, password, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.role = role
        self.pinkey = pyotp.random_base32()
        self.secret_key = Fernet.generate_key()
        self.registered_on = datetime.now()
        self.current_login = None
        self.last_login = None


class Draw(db.Model):
    __tablename__ = 'draws'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)
    # Secret key used to view draws and create draws
    secret_key = db.Column(db.BLOB)

    # function that decrypts the lottery numbers using the users secret_key
    def view_numbers(self, secret_key):
        self.numbers = decrypt(self.numbers, secret_key)

    def __init__(self, user_id, numbers, master_draw, lottery_round, secret_key):
        self.user_id = user_id
        self.numbers = encrypt(numbers, secret_key)
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round


# initalises Database
def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin')

        db.session.add(admin)
        db.session.commit()
