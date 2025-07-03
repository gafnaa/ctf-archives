from application.util import generate

class Config(object):
    SECRET_KEY = generate(32)
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'syulit'
    MYSQL_PASSWORD = 'syulit'
    MYSQL_DB = 'caffeine'
    FLAG = open('/flag.txt').read()

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True