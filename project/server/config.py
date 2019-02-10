import os
basedir = os.path.abspath(os.path.dirname(__file__))
postgres_set = 'postgresql://anda:12@localhost'
database = 'dataanda'

class BaseConfig:
    """ Konfigurasi dasar """
    SECRET_KEY = os.getenv('SECRET_KEY', 'blablabla')
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(BaseConfig):
    """ mode development """
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_set + database

class TestingConfig(BaseConfig):
    """ mode testing """
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_set + database
    PRESERVE_CONTEXT_ON_EXCEPTION = False

class ProductionConfig(BaseConfig):
    """ mode production """
    SECRET_KEY = 'my_pricious'
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = postgres_set + database