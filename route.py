from application import app, mongo, cos_client
from qcloud_cos import UploadFileRequest, cos_auth
from flask import Flask, request, render_template, redirect, send_file, Response, abort
from werkzeug.utils import secure_filename
from model import uploadfile, ALLOWED_EXTENSIONS
import urllib, hashlib
import demjson
import cStringIO
# from PIL import Image
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
import time


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def hello_world():
    return 'hello world'


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        files = request.files['file']

        if files:
            filename = secure_filename(files.filename)
            mime_type = files.content_type
            uuid, file_extension = filename.split('.')
            if not allowed_file(filename):
                result = uploadfile(uuid=uuid, name=filename, code=-2, file_type=mime_type,
                                    msg="file type not allowed")
            else:
                auth = cos_auth.Auth(cos_client.get_cred())
                expired = int(time.time()) + 999
                cos_path = app.config['UPLOAD_FOLDER'] + filename
                sign = auth.sign_more(app.config['BUCKET'], urllib.quote(cos_path.encode('utf8'), '~/'), expired)

                m = MultipartEncoder(
                    fields={
                        'appid': str(app.config['APP_ID']),
                        'bucket': app.config['BUCKET'],
                        'image': (filename, files.stream, mime_type)
                    })

                headers = {'Content-Type': m.content_type, 'Authorization': sign,
                           'Host': app.config['PORN_DETECT_HOST'], 'Content-Length': m.len}

                r = requests.post(app.config['PORN_DETECT_URL'], data=m, headers=headers)

                if r.status_code == 200:
                    result_list = demjson.decode(r.text)
                    data = result_list['result_list'][0]['data']
                    if data['result'] != 0 or data['porn_score'] >= 50:
                        result = uploadfile(uuid=uuid, name=filename, code=-4, file_type=mime_type, msg='porn detected')
                    else:
                        request_url = build_url(app.config['UPLOAD_URL'], cos_client.get_cred().get_appid(),
                                                app.config['BUCKET'], cos_path)
                        m = MultipartEncoder(
                            fields={
                                'op': 'upload',
                                'filecontent': (filename, files.stream, mime_type),
                                'sha': get_sha(files.stream.read()),
                                'biz_attr': '',
                                'insertOnly': '0'
                            })

                        headers = {'Content-Type': m.content_type, 'Authorization': sign,
                                   'Host': app.config['UPLOAD_HOST'], 'Content-Length': m.len}

                        upload_resp = requests.post(request_url, data=m, headers=headers)

                        if upload_resp.status_code == 200:
                            result = demjson.decode(upload_resp.text)
                            if result['code'] == 0:
                                data = result['data']
                                save_image_info_to_mongo(uuid, data)
                                result = uploadfile(uuid=uuid, name=filename, code=0, file_type=mime_type,
                                                    access_url=data['access_url'], msg='success')
                        else:
                            result = uploadfile(uuid=uuid, name=filename, code=-5, file_type=mime_type,
                                                msg='upload failed')

                else:
                    result = uploadfile(uuid=uuid, name=filename, code=-3, file_type=mime_type,
                                        msg='post to detection failed')
        else:
            result = uploadfile(uuid='', name='', code=-1, msg='no files to upload')

    return demjson.encode(result.get_file())


@app.route('/i/<uuid>', methods=['GET'])
def get_image(uuid):
    try:
        info = get_image_info(uuid)
        if info:
            return info['access_url']
        else:
            abort(404)
    except:
        abort(404)


@app.route('/check/<uuid>', methods=['GET'])
def check_image(uuid):
    try:
        info = get_image_info(uuid)
        if info:
            return info['access_url']
        else:
            return ''
    # try:
    #     if image_storage.__contains__(uuid):
    #         return "true"
    #     else:
    #         return "false"
    except:
        abort(404)


# @app.route('/delete/<uuid>', methods=['GET'])
# def delete_image(uuid):
#     try:
#         history = get_image_info(uuid)
#         if history:
#             delete_resp = tc_image.delete(app.config['BUCKET'], history['fileId'])
#             if delete_resp['httpcode'] == 200 or delete_resp['code'] == 0:
#                 delete_image_info(uuid)
#                 return 'success'
#             else:
#                 error_msg = "delete history error"
#                 return error_msg
#     except:
#         abort(404)
#         # image_storage.delete(uuid)
#         # return 'success'


def save_image_info_to_mongo(uuid, data):
    if mongo.db.imageInfo.find_one({'playerId': uuid}):
        mongo.db.imageInfo.update_one({'playerId': uuid}, {
            '$set': {
                'access_url': data['access_url'],
                'source_url': data['source_url'],
                'resource_path': data['resource_path'],
                'url': data['url'],
                'vid': data['vid']
            }})
    else:
        mongo.db.imageInfo.insert_one({
            'playerId': uuid,
            'access_url': data['access_url'],
            'source_url': data['source_url'],
            'resource_path': data['resource_path'],
            'url': data['url'],
            'vid': data['vid']
        })


def get_image_info(uuid):
    return mongo.db.imageInfo.find_one({'playerId': uuid})


def delete_image_info(uuid):
    mongo.db.gm_users.delete_one({'playerId': uuid})


def build_url(base_url, appid, bucket, cos_path):
    bucket = bucket.encode('utf8')
    end_point = base_url.encode('utf8')
    cos_path = urllib.quote(cos_path.encode('utf8'), '~/')
    url = '%s/%s/%s%s' % (end_point, appid, bucket, cos_path)
    return url


def get_sha(content):
    sha1_obj = hashlib.sha1()
    sha1_obj.update(content)
    return sha1_obj.hexdigest()

# resp = tc_image.upload('/tmp/slime.jpeg', app.config['BUCKET'], uuid);
# upload_resp = tc_image.upload_binary(files.stream, app.config['BUCKET'])
# m = MultipartEncoder(
#     fields={
#         'appid': str(app.config['APP_ID']),
#         'bucket': app.config['BUCKET'],
#         'image': (filename, files.stream, mime_type)
#     })
# headers = {'Content-Type': m.content_type, 'Authorization': sign,
#            'Host': app.config['PORN_DETECT_HOST'], 'Content-Length': m.len}
# r = requests.post(app.config['PORN_DETECT_URL'], data=m, headers=headers)
# if r.status_code == 200:
#     result_list = demjson.decode(r.text)
#     data = result_list['result_list'][0]['data']
#     if data['result'] == 0:
