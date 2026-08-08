register_user_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 128},
        "password": {"type": "string", "minLength": 1, "maxLength": 128},
        "email": {"type": "string", "minLength": 3, "maxLength": 254}
    },
    "required": ["username", "password", "email"],
    "additionalProperties": False
}

login_user_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 128},
        "password": {"type": "string", "minLength": 1, "maxLength": 128}
    },
    "required": ["username", "password"],
    "additionalProperties": False
}

update_email_schema = {
    "type": "object",
    "properties": {
        "email": {"type": "string", "minLength": 3, "maxLength": 254}
    },
    "required": ["email"],
    "additionalProperties": False
}

update_password_schema = {
    "type": "object",
    "properties": {
        "password": {"type": "string", "minLength": 1, "maxLength": 128}
    },
    "required": ["password"],
    "additionalProperties": False
}

add_book_schema = {
    "type": "object",
    "properties": {
        "book_title": {"type": "string", "minLength": 1, "maxLength": 128},
        "secret": {"type": "string", "minLength": 1, "maxLength": 128}
    },
    "required": ["book_title", "secret"],
    "additionalProperties": False
}
