import re
import jsonschema
from werkzeug.security import check_password_hash, generate_password_hash

from config import db, limiter
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User


EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z]{2,63})+"
)
DUMMY_PASSWORD_HASH = generate_password_hash(
    "not-a-real-password", method='pbkdf2:sha256'
)


def error_message_helper(msg):
    if isinstance(msg, dict):
        return '{ "status": "fail", "message": "' + msg['error'] + '"}'
    else:
        return '{ "status": "fail", "message": "' + msg + '"}'


def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def debug():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Only Admins may use the debug endpoint!"), 403,
                        mimetype="application/json")
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value

def me():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        responseObject = {
            'status': 'success',
            'data': {
                'username': user.username,
                'email': user.email,
                'admin': user.admin
            }
        }
        return Response(json.dumps(responseObject), 200, mimetype="application/json")
        

def get_by_username(username):
    user = User.get_user(username)
    if user:
        return jsonify(user.json())
    else:
        return Response(error_message_helper("User not found"), 404, mimetype="application/json")


def register_user():
    request_data = request.get_json(silent=True)
    try:
        jsonschema.validate(request_data, register_user_schema)
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper("Please provide a proper JSON body."), 400,
                        mimetype="application/json")

    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
    if not user:
        user = User(username=request_data['username'], password=request_data['password'],
                    email=request_data['email'])
        db.session.add(user)
        db.session.commit()

        responseObject = {
            'status': 'success',
            'message': 'Successfully registered. Login to receive an auth token.'
        }

        return Response(json.dumps(responseObject), 200, mimetype="application/json")
    else:
        return Response(error_message_helper("User already exists. Please Log in."), 200, mimetype="application/json")


def login_rate_limit_key():
    request_data = request.get_json(silent=True) or {}
    username = str(request_data.get('username', '')).strip().lower()
    return f"{request.remote_addr}:{username}"


@limiter.limit("10 per minute", key_func=login_rate_limit_key)
def login_user():
    request_data = request.get_json(silent=True)

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        password_is_valid = user.check_password(request_data.get('password')) if user else False
        if not user:
            # Perform equivalent password-hash work so unknown usernames do not
            # create a useful timing oracle.
            check_password_hash(DUMMY_PASSWORD_HASH, request_data.get('password'))
        if user and password_is_valid:
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        return Response(error_message_helper("Username or Password Incorrect!"), 200,
                        mimetype="application/json")
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper("Please provide valid login credentials."), 400,
                        mimetype="application/json")
    except:
        return Response(error_message_helper("An error occurred!"), 200, mimetype="application/json")


def token_validator(auth_header):
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except:
            auth_token = ""
    else:
        auth_token = ""
    if auth_token:
        # if auth_token is valid we get back the username of the user
        return User.decode_auth_token(auth_token)
    else:
        return {'error': 'Invalid token. Please log in again.'}


def update_email(username):
    request_data = request.get_json(silent=True)
    try:
        jsonschema.validate(request_data, update_email_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if username != resp['sub']:
            return Response(error_message_helper("You may only update your own email."), 403,
                            mimetype="application/json")
        user = User.query.filter_by(username=resp['sub']).first()
        email = request_data.get('email')
        if EMAIL_PATTERN.fullmatch(email):
            user.email = email
            db.session.commit()
            responseObject = {
                'status': 'success',
                'data': {
                    'username': user.username,
                    'email': user.email
                }
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")
        else:
            return Response(error_message_helper("Please Provide a valid email address."), 400,
                            mimetype="application/json")


def update_password(username):
    request_data = request.get_json(silent=True)
    try:
        jsonschema.validate(request_data, update_password_schema)
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper("Malformed Data"), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if username != resp['sub']:
            return Response(error_message_helper("You may only update your own password."), 403,
                            mimetype="application/json")
        user = User.query.filter_by(username=resp['sub']).first()
        user.set_password(request_data.get('password'))
        db.session.commit()
        responseObject = {
            'status': 'success',
            'Password': 'Updated.'
        }
        return Response(json.dumps(responseObject), 204, mimetype="application/json")


def delete_user(username):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        if user.admin:
            if bool(User.delete_user(username)):
                responseObject = {
                    'status': 'success',
                    'message': 'User deleted.'
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("User not found!"), 404, mimetype="application/json")
        else:
            return Response(error_message_helper("Only Admins may delete users!"), 401, mimetype="application/json")
