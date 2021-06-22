import os
import jwt
import uuid
import datetime
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask import Flask, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash

# Local Import
import config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///api_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config.from_object('config.Production')

db = SQLAlchemy(app)
api = Api(app)
app.logger.setLevel(10)

# TODO - Add Docstring
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(60))
    name = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(60), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self) -> str:
        return f'User - {self.name}'

# TODO - Add spotify API Feature
class Songs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    song_name = db.Column(db.String(50), nullable=False)
    singer = db.Column(db.String(50), nullable=False)
    album = db.Column(db.String(50), nullable=False)
    release_Date = db.Column(db.String(50), nullable=False)


if not os.path.isfile('api_data.db'):
    db.create_all()


def token_required(func):
    """Used as custom decorator for token validation"""
    @wraps(func)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            app.logger.info(f'Token Recieved - {token}')

        if not token:
            return jsonify(
                {
                    "message": "A valid Token is missing."
                }
            )
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
            app.logger.debug(f'Decoded Token - {data}')
            current_user = Users.query.filter_by(
                public_id=data['public_id']).first()
        except Exception as err:
            return jsonify(
                {
                    "message": str(err)
                }
            )
        return func(current_user, *args, **kwargs)
    return decorator

# TODO - Add Admin Feature
class ShowUsers(Resource):
    def get(self):
        """Shows all registerd users from the database"""
        result = list()
        try:
            for user in Users.query.all():
                data = {}
                data['public_id'] = user.public_id
                data['name'] = user.name
                data['email'] = user.email
                data['password'] = user.password
                result.append(data)
            return jsonify(
                {"Users": result}, 200
            )
        except Exception as err:
            app.logger.error(err)
            return jsonify(
                {
                    "error message": str(err)
                }
            )


# TODO - Check if data exists, if yes don't let the register agian
class Register(Resource):

    def post(self):
        data = request.get_json()
        username = email = password = None

        try:
            username = data.get('username', None)
            email = data.get('email', None)
            password = data.get('password', None)
        except AttributeError:
            return jsonify(
                {"error message": "username or email or password is missing"}
            )

        if None in (username, password, email):
            return jsonify(
                {
                    "message": "username or password or email is Invalid"
                }
            )

        if username == password:
            return jsonify(
                {"error message": "username and password cannot be same"}
            )

        app.logger.debug(f"User Data - {data}")
        hashed_password = generate_password_hash(
            data['password'], method='sha256'
        )
        app.logger.info(f"Hashed Password - {hashed_password}")
        new_user = Users(
            public_id=str(uuid.uuid4()),
            name=username,
            email=email,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()
        app.logger.debug('User Registration Complete.')
        return jsonify(
            {
                "message": "User Registration Complete."
            }
        )


class Login(Resource):
    def post(self):
        auth = request.authorization
        if len(auth['username']) == 0 or len(auth['password']) == 0:
            return make_response(
                'Could Not Verify', 401,
                {
                    'Authentication': 'Invalid Data format'
                }
            )
        app.logger.info(f"Auth Recieved - {auth}")
        if '@' in auth.username:
            user = Users.query.filter_by(email=auth.username).first()
        else:
            user = Users.query.filter_by(name=auth.username).first()
        app.logger.debug(f'User - {user}')
        if check_password_hash(user.password, auth.password):
            token = jwt.encode(
                {
                    'public_id': user.public_id,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            app.logger.debug(
                f'Token Generated for - {auth.username}, {auth.password} -> {token}')
            return jsonify(
                {
                    'token': token.decode("utf-8")
                }
            )
        return make_response(
            'Could Not verify', 401,
            {
                'Authentication': "Login Required"
            }
        )


class SongsList(Resource):
    method_decorators = [token_required]

    # @token_required
    def get(self, current_user):
        songs = Songs.query.filter_by(user_id=current_user.id).all()
        result = list()
        for song in songs:
            data = {}
            data['song_name'] = song.song_name,
            data['singer'] = song.singer
            data['album'] = song.album,
            data['release_Date'] = song.release_Date
            result.append(data)
        return jsonify(
            {
                'SongsList': result
            }
        )

    # @token_required
    def post(self, current_user):
        data = request.get_json()
        app.logger.debug(f'Data Recieved - {data}')
        new_song_record = Songs(
            user_id=current_user.id,
            song_name=data['song_name'],
            singer=data['singer'],
            album=data['album'],
            release_Date=data['release_Date']
        )
        db.session.add(new_song_record)
        db.session.commit()
        app.logger.debug('Song Data Registered')
        return jsonify(
            {
                'message': 'New Song Entry Created'
            }
        )


if __name__ == '__main__':
    api.add_resource(
        ShowUsers,
        "/api/v1.0/users",
        "/api/v1.0/all_users"
    )
    api.add_resource(
        Register,
        "/api/v1.0/register",
        "/api/v1.0/signup"
    )
    api.add_resource(
        Login,
        "/api/v1.0/login",
        "/api/v1.0/signin"
    )
    api.add_resource(
        SongsList,
        "/api/v1.0/songs",
        "/api/v1.0/all_songs"
    )
    app.run()
