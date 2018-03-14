import jwt


def generate_token():
    service = 'admin'
    encode_data = {
        'userid': 1, 'name': 'Admin (superuser)', 'groups': [1], 'iat':
            1517339633, 'exp': 1517340053, 'email': 'admin@noemail.com', 'profile':
            'admin', 'iss': 'eGfIBvOLxz5aQxA92lFk5OExZmBMZDDh', 'service': service,
        'jti': '7e3086317df2c299cef280932da856e5', 'username': 'admin'
    }

    jwt_token = jwt.encode(encode_data, 'secret', algorithm='HS256').decode()

    # Substitute Authorization with actual token
    auth = 'Bearer ' + jwt_token
    return auth
