import os
import secrets
import connexion
from flask import jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from connexion.exceptions import ProblemException

vuln_app = connexion.App(__name__, specification_dir='./openapi_specs')

SQLALCHEMY_DATABASE_URI = os.getenv(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(vuln_app.app.root_path, 'database/database.db')
)
vuln_app.app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
vuln_app.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
vuln_app.app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

vuln_app.app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or secrets.token_urlsafe(48)
# start the db
db = SQLAlchemy(vuln_app.app)
limiter = Limiter(
    key_func=get_remote_address,
    app=vuln_app.app,
    default_limits=["60 per minute"],
    storage_uri="memory://",
)

def custom_problem_handler(error):
    # Custom error handler for clarity in structure
    response = jsonify({
        "status": "fail",
        "message": getattr(error, "detail", "An error occurred"),
    })
    response.status_code = error.status
    return response
vuln_app.add_error_handler(ProblemException, custom_problem_handler)


@vuln_app.app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    return response


vuln_app.add_api('openapi3.yml')
