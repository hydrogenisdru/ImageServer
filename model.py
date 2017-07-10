import os

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'bmp'])


class uploadfile():
    def __init__(self, uuid, name, code, file_type='', access_url='', msg=''):
        self.uuid = uuid
        self.name = name
        self.type = file_type
        self.access_url = access_url
        self.msg = msg
        self.code = code

    def is_image(self):
        if self.type in ALLOWED_EXTENSIONS:
            return True

        return False

    def get_file(self):
        return {
            "code": self.code,
            "message": self.msg,
            "uuid": self.uuid,
            "name": self.name,
            "downloadUrl": self.access_url,
            "type": self.type
        }
