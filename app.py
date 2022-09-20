import re
import base64
import datetime
from sqlalchemy.sql import text
from flask import Flask, jsonify, request, make_response, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_user import current_user, login_required, roles_required, UserManager, UserMixin, user_manager
from flask_cors import CORS
import os
import random
from bs4 import BeautifulSoup as bs
import secrets
from utils import Utils
import subprocess
import pickle

class ConfigClass(object):
    SECRET_KEY = "tkeysupersecretkeysupersecretkey" 
    SQLALCHEMY_DATABASE_URI = 'sqlite:///apisec.sqlite'    # File-based SQL database
    SQLALCHEMY_TRACK_MODIFICATIONS = False    # Avoids SQLAlchemy warning

    USER_APP_NAME = "fAilPI"      # Shown in and email templates and page footers
    USER_ENABLE_EMAIL = False





def create_app():
    app = Flask(__name__)
    app.config.from_object(__name__+'.ConfigClass')
    def check_token(token):
        session_found = Sessions.query.filter_by(session = token).first()
        if session_found is not None:
            return session_found.suser
        else:
            return False

    def isAdmin(sid):
        user = Users.query.filter_by(id = sid).first()
        return user.isAdmin

    """ Flask application factory """
    
    # Create Flask app load app.config
    app = Flask(__name__)
    app.config.from_object(__name__+'.ConfigClass')
    # Initialize Flask-SQLAlchemy
    db = SQLAlchemy(app)

    #Might not be needed
    class Sessions(db.Model):
        __tablename__ = 'sessions'
        sid = db.Column( db.Integer, primary_key=True)
        #timeouts are hard.  
        expired = db.Column(db.DateTime)
        session = db.Column(db.Text)
        suser = db.Column(db.Integer)

        def __init__( self, **kwargs ):
            super( Sessions, self ).__init__( **kwargs )
            if 'sid' in kwargs:
                self.sid = kwargs[ 'sid' ]
            if 'expired' in kwargs:
                self.expired = kwargs[ 'expired' ]
            if 'session' in kwargs:
                self.session = kwargs[ 'session' ]
            if 'suser' in kwargs:
                self.suser = kwargs[ 'suser' ]
    
        def __repr__( self ):
            return '<Session %s>' % self.session

    class Users(db.Model, UserMixin):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(255, collation='NOCASE'), nullable=False)
        email = db.Column(db.String(255, collation='NOCASE'), nullable=False, unique=True)
        password = db.Column(db.String(255), nullable=False, server_default='')
        notes = db.Column(db.String(255), nullable=True, server_default='')
        isAdmin = db.Column(db.Boolean, default=False, nullable=False)
    
    class Widgets(db.Model):
        __tablename__ = 'widgets'
        id = db.Column(db.Integer, primary_key=True)
        wname = db.Column(db.String(255), nullable=False)
        wdesc = db.Column(db.String(255), nullable=False)
        wprice = db.Column(db.Numeric(), nullable=False)
    
    class Docs(db.Model):
        __tablename__ = 'reviews'
        id = db.Column(db.Integer, primary_key=True)
        did = db.Column(db.Integer, nullable=False)
        uid = db.Column(db.Integer, nullable=False)
        rcontent = db.Column(db.String(255), nullable=False)
    
    user_manager = UserManager(app, db, Users)

    db.create_all()

    # If we don't have entries in the database create them

    # Create new users
    if not Users.query.filter_by(email = 'admin@apictf.com').first():
        user = Users(
            email = 'admin@apictf.com',
            name = 'admin',
            password = Utils.gen_pass(),
            notes = 'flag1_be36d730520b209a9a4789be0a5cb66711df2ae64be5034603af852b5d69938b',
            isAdmin = True
        )
        db.session.add(user)
        db.session.commit()

    if not Users.query.filter_by(email = 'generic.user@apictf.com').first():
        user = Users(
            email='generic.user@apictf.com',
            name='Generic User',
            password= Utils.gen_pass(),
            notes='This is just a generic user.  Blah blah blah',
            isAdmin = False
        )
        db.session.add(user)
        db.session.commit()

    if not Users.query.filter_by(email = 'john.dough@apictf.com').first():
        user = Users(
            email='john.dough@apictf.com',
            name='John Dough',
            password= Utils.gen_pass(),
            notes='John likes his privacy. As we all should.',
            isAdmin = False
        )
        db.session.add(user)
        db.session.commit()

    # Populate the Docs table
    if not Docs.query.filter_by(did=1035).first():
        doc = Docs(
            did=1035,
            uid=3,
            rcontent='flag2_57c45a5211d8327ad201489fff9c4efa889f8bfedc3d7158222ed1575748b73d'
        )
        db.session.add(doc)
        
    
    if not Docs.query.filter_by(did=1037).first():
        doc = Docs(
            did=1037,
            uid=2,
            rcontent='Some random document here'
        )
        db.session.add(doc)

    if not Docs.query.filter_by(did=1039).first():
        doc = Docs(
            did=1040,
            uid=2,
            rcontent='blah balh balh blah blah'
        )
        db.session.add(doc)

    db.session.commit()
    
    ##########################################
    # Endpoint Definitions
    ##########################################

    #Nothing to see here
    @app.route('/')
    def home_page():
        page = """
        <html><head><title>api ctf</title></head><body><p>Hi there, this is a CTF!</p>
        <p>Current list of endpoints:<br>
        <ul><br><b>Endpoints that do not require authorization:</b><br>
        <li>POST /v2/user/register  -create new user<br> 
        Request data:  {"email":[string],"password":[string],"name":[string]}<br>
        <li>POST /v2/login  -login<br>
        Request data:  {"email":[string],"password":[string]}<br>
        <br>
        <b>Endpoints requiring authorization:</b><br>
        <li>GET /v2/user/[int]  -retrieves information for user specified by int<br>
        View user information<br>
        <li>PUT /v2/user/[int]  -updates information for user specified by int<br>
        Request data: {"email":[string],"password":[string],"isAdmin":[bool]}
        </ul></p>
        </body></html>"""
        return make_response(page,200)
    
    @app.route('/v2/pickle', methods=['POST'])
    def serialize():
        if not request.json:
            abort(400)
        bad_input = base64.urlsafe_b64decode(request.json['input'])
        deserialized_data = pickle.loads(bad_input)
        return make_response(jsonify({'message':deserialized_data}),200)


    @app.route('/v2/domain', methods=['POST'])
    def domain():
        if not request.json:
            abort(400)
        domain = request.json['domain']
        subprocess.run(["nslookup",domain], shell=True)
        return make_response(jsonify({'message':'lookup_done'}),200)

    #User Registration
    @app.route('/v2/user/register', methods=['POST'])
    def register():
        if not request.json:
            abort(400)
        email = request.json['email']
        password = request.json['password']
        name = request.json['name']
        if not request.json['isAdmin']:
            isAdmin = False
        else:
            isAdmin = request.json['isAdmin']
        if None in [email, password, name]:
            return make_response(jsonify({'message':'Missing required email, password, or name'}),400)
        if Users.query.filter_by(email = email).first() is not None:
            return make_response(jsonify({'message':'Email already in use.'}),400)
        user = Users(
            name = name,
            email = email,
            password = password,
            isAdmin = isAdmin
        )
        try:
            db.session.add(user)
            db.session.commit()
            return make_response(jsonify({'message':'User created successfully'}),200)
        except Exception as e:
            return make_response(jsonify({'error':str(e)}),500)

    #User login API8:2019 Injection
    # Solution: SQL injection in the email field
    @app.route('/v2/user/login', methods=['POST'])
    def login():
        if request.method != 'POST':
            abort(400, 'Method not allowed')
        if not request.json or 'email' not in request.json or 'password' not in request.json:
            abort(400, 'Missing things')
        username = request.json['email']
        username = username.replace('%40','@')
        pword = request.json['password']
        #hopefully this will allow for SQL injection
        q = text("SELECT * FROM users WHERE email='{0}' AND password='{1}'".format(username,pword))
        result = db.engine.execute(q).first()
        if result is not None:
            token = base64.b64encode(secrets.token_bytes(32)).decode()
            sess = Sessions(
                expired = datetime.datetime.now() + datetime.timedelta(minutes = 30),
                suser = result.id,
                session = token
            )
            try:
                db.session.add(sess)
                db.session.commit()
                return make_response(jsonify({'message':'Success','Authorization-Token':token,'User':result.name,'isAdmin':str(result.isAdmin),'Notes':result.notes}),200)
            except Exception as e:
                return make_response(jsonify({'error':str(e)}),500)
        else:
            return make_response(jsonify({'error':'nothing returned'}))

    @app.route('/v2/user/<int:id>', methods=['GET','PUT'])
    def users(id):
        if 'Authorization-Token' not in request.headers:
            return make_response(jsonify({'Error':'Authorization-Token header is not set'}),403)
        
        token = request.headers.get('Authorization-Token')
        sid = check_token(token)
        
        #if we don't have a valid session send 403
        if not sid:
            return make_response(jsonify({'Error':'Token check failed: {0}'.format(sid)}))
        try:
            user = Users.query.filter_by(id=id).first()
        except Exception as e:
            return make_response(jsonify({'error':str(e)}),500)
        
        #
        if request.method == 'GET':
            if not isAdmin(sid) and sid != id:
                return make_response(jsonify({'Error':'You are not an admin.  You can only look at yourself.'}),403)
            return make_response(jsonify({'id':str(user.id),'name':user.name,'email':user.email,'isAdmin':str(user.isAdmin)}),200)
        
        #API6:2019 Mass Assignment
        # Solution 1: include the isAdmin:True element in the request JSON
        #API1:2019 Broken Object Level Authorization
        # Solution 2: Make the id in the path the admin's id in the database and change the password.
        if request.method == 'PUT':
            if not request.json:
                abort(400)
            user = Users.query.filter_by(id=id).first()
            for item in request.json:
                setattr(user,item,request.json[item])
            try:
                db.session.commit()
                return make_response(jsonify({'message':'User updated successfully'}),200)
            except Exception as e:
                return make_response(jsonify({'error':str(e)}),500)
            
    #Widgets endpoint       
        
        
    return app


        
if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', port=5000, debug=True)





    
