import jwt
import datetime
from project.server import app, db, bcrypt

class User(db.Model):
    """ untuk mendeskripsikan tabel user """ 
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()

    def encode_auth_token(self, user_id):
        """ untuk menggenerate token """

        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=20, seconds=20),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='H256'
            )
        except Exception as err:
            return err

    @staticmethod
    def decode_auth_token(auth_token):
        """ untuk memvalidasi token """

        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token Blacklisted, please log in again'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired'
        except jwt.InvalidTokenError:
            return 'Invalid token'

class BlacklistToken(db.Model):
    """ ini untuk menyimpan token yang sudah terbacklist """
    __tablename__  = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False

class Product(db.Model):
    """ ini untuk mendeskripsikan table products """
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False)

    def __init__(self, name, price, image_url, created_at, updated_at):
        self.name = name
        self.price = price
        self.image_url = image_url
        self.created_at = datetime.datetime.now()
        self.updated_at = datetime.datetime.now()





