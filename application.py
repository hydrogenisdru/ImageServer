from flask import Flask
from flask_pymongo import PyMongo
from config import config
from qcloud_cos import CosClient

# import flask_fs as fs

config_name = 'default'
app = Flask(__name__)
app.config.from_object(config[config_name])
mongo = PyMongo()
mongo.init_app(app)
cos_client = CosClient(app.config['APP_ID'], app.config['SECRET_ID'], app.config['SECRET_KEY'],
                       region=app.config['REGION_INFO'])
# image_storage = fs.Storage('images', fs.IMAGES)
# fs.init_app(app, image_storage)

from route import *

if __name__ == '__main__':
    app.run(port=5001)
