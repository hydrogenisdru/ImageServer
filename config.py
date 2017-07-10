import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    FS_BACKEND = 'grids'
    MONGO_URI = 'mongodb://localhost:27017/fire2'
    IMAGES_FS_MONGO_URL = 'mongodb://localhost:27017/'
    IMAGES_FS_MONGO_DB = 'fire2'
    PORN_DETECT_URL = 'http://service.image.myqcloud.com/detection/porn_detect'
    UPLOAD_URL = 'http://sh.file.myqcloud.com/files/v2'
    PORN_DETECT_HOST = 'service.image.myqcloud.com'
    UPLOAD_HOST = 'sh.file.myqcloud.com'
    UPLOAD_FOLDER = '/pic/'
    REGION_INFO = "sh"
    APP_ID = 1252726230
    BUCKET = u'biubiubiu'
    SECRET_ID = u'AKIDTp0znOY01wfCYjhVDmBHGIE1c1EFuf7N'
    SECRET_KEY = u'BAxhFblkX8WjjXBcrxrZ5PWTFpDSWN6f'


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True


class ProductionConfig(Config):
    pass


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
