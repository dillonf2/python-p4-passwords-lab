#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api, bcrypt
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.get(user_id)
            return user.to_dict(), 200
        else:
            return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        if 'username' not in json or 'password' not in json:
            return {'error': 'Both username and password are required'}, 400

        existing_user = User.query.filter_by(username=json['username']).first()
        if existing_user:
            return {'error': 'Username already exists'}, 400

        hashed_password = bcrypt.generate_password_hash(json['password']).decode('utf-8')
        user = User(
            username=json['username'], 
            _password_hash=hashed_password 
        )
        db.session.add(user)
        db.session.commit()

        return {
            'username': user.username,
            'id': user.id
            }, 201


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.get(user_id)
            return {
                'username': user.username,
                'id': user.id
            }, 200
        else:
            return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        if 'username' not in json or 'password' not in json:
            return {'error': 'Both username and password are required'}, 400

        user = User.query.filter_by(username=json['username']).first()

        if user and user.authenticate(json['password']):
            session['user_id'] = user.id
            return {
                'username': user.username,
                'id': user.id
            }, 200
        else:
            return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id', None)
        if 'user_id' in session:
            session.pop('user_id')
        return {"user_id": user_id}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout') 

if __name__ == '__main__':
    app.run(port=5555, debug=True)
