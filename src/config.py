from os import urandom
class Config(object):
    '''
    Each environment will be a class that inherits from the main class config

    Configurations that will be the same across all environment will go into config,
    while configuration that are specific to an environment will go into the relevant environment below
    '''
    SECRET_KEY = urandom(32)


class Production(Config):
    DEBUG = False
    FLASK_ENV = 'production'
    PRODUCTION = True


class Testing(Config):
    DEBUG = False
    FLASK_ENV = 'testing'
    TESTING = True


class Development(Config):
    FLASK_ENV = 'development'
    DEBUG = True
