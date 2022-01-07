import re
import base64
import datetime
from sqlalchemy import text
from flask import Flask, jsonify, request, make_response, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_user import current_user, login_required, roles_required, UserManager, UserMixin, user_manager
from flask_cors import CORS
import os
import random
from bs4 import BeautifulSoup as bs
import secrets

app = Flask(__name__)


class ConfigClass(object):
    SECRET_KEY = "supersecretkey"
    SQLALCHEMY_DATABASE_URI = 'sqlite:///apisec.sqlite'    # File-based SQL database
    SQLALCHEMY_TRACK_MODIFICATIONS = False    # Avoids SQLAlchemy warning

    USER_APP_NAME = "fAilPI"      # Shown in and email templates and page footers
    USER_ENABLE_EMAIL = False

#generates a session token to be used when calling protected endpoints
def auth_token():
    return base64.b64encode(secrets.token_bytes(32)).decode()

def gen_pass():
    characters = 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+_)(*&^%$#@!~=-?/.>,<][}{'
    return ''.join(random.choice(characters) for i in range(30))

def create_app():

    def check_token(token):
        session_found = Sessions.query.filter_by(session = token).first()
        if session_found is not None:
            return session_found.suser
        else:
            return False

    def isAdmin(sid):
        return Users.query.filter_by(id = sid).first()

    """ Flask application factory """
    
    # Create Flask app load app.config
    app = Flask(__name__)
    app.config.from_object(__name__+'.ConfigClass')
    # Initialize Flask-SQLAlchemy
    db = SQLAlchemy(app)

    #Might not be needed
    class Sessions(db.Model):
        __tablename__ = 'sessions'
        sid = db.Column( db.String(255), primary_key=True)
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
                self.session = kwargs[ 'suser' ]
    
        def __repr__( self ):
            return '<Session %s>' % self.session

    class Users(db.Model, UserMixin):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(255, collation='NOCASE'), nullable=False)
        email = db.Column(db.String(255, collation='NOCASE'), nullable=False, unique=True)
        password = db.Column(db.String(255), nullable=False, server_default='')
        notes = db.Column(db.String(255),nullable=True, server_default='')
        isAdmin = db.Column('is_admin', db.Boolean(), server_default=False)
    
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
    
    user_manager = UserManager(app,db, Users)

    db.create_all()

    # If we don't have entries in the database create them

    # Create new users
    if not Users.query.filter(Users.email == 'admin@apictf.com').first():
        user = Users(
            email = 'admin@apictf.com',
            name = 'admin',
            password = gen_pass(),
            notes = 'flag1_be36d730520b209a9a4789be0a5cb66711df2ae64be5034603af852b5d69938b',
            isAdmin = True
        )
        db.session.add(user)
        db.session.commit()

    if not Users.query.filter(Users.email == 'generic.user@apictf.com').first():
        user = Users(
            email='generic.user@apictf.com',
            name='Generic User',
            password=gen_pass(),
            notes='This is just a generic user.  Blah blah blah',
            isAdmin = False
        )
        db.session.add(user)
        db.session.commit()

    if not Users.query.filter(Users.email == 'john.dough@apictf.com').first():
        user = Users(
            email='john.dough@apictf.com',
            name='John Dough',
            password=gen_pass(),
            notes='John likes his privacy. As we all should.',
            isAdmin = False
        )
        db.session.add(user)
        db.session.commit()

    # Populate the Docs table
    if not Docs.query.filter(did=1035).first():
        doc = Docs(
            did=1035,
            uid=3,
            rcontent='flag2_57c45a5211d8327ad201489fff9c4efa889f8bfedc3d7158222ed1575748b73d'
        )
        db.session.add(doc)
        
    
    if not Docs.query.filter(did=1037).first():
        doc = Docs(
            did=1037,
            uid=2,
            rcontent='Some random document here'
        )
        db.session.add(doc)

    if not Docs.query.filter(did=1039).first():
        doc = Docs(
            did=1040,
            uid=2,
            rcontent='blah balh balh blah blah'
        )
        db.session.add(doc)

    db.session.commit()
    

    #Utility functions mostly boring shit here just don't want to have to write the same code over and over again

    
    

    ##########################################
    # Endpoint Definitions
    ##########################################

    #Nothing to see here
    @app.route('/')
    def home_page():
        abort(404)
    
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
        password = request.json['password']
        username = username.replace('%40','@')
        #hopefully this will allow for SQL injection
        q = text("SELECT * FROM users WHERE email={0} AND password={1}".format(username,password))
        result = db.Query(Users).from_statement(q).first()
        if result is not None:
            token = auth_token()
            sess = Sessions(
                suser = result.id,
                session = token
            )
            try:
                db.session.add(sess)
                db.session.commit()
                return make_response(jsonify({'message':'Success','Authorization-Token':token,'User':result.name,'isAdmin':str(result.isAdmin),'Notes':result.notes}),200)
            except Exception as e:
                return make_response(jsonify({'error':str(e)}),500)

    @app.route('/v2/user/<int:id>', methods=['GET','PUT'])
    def users(id):
        if 'Authorization-Token' not in request.headers:
            return make_response(jsonify({'Error':'Authorization-Token header is not set'}),403)
        
        token = request.headers.get('Authorization-Token')
        sid = check_token(token)
        
        #if we don't have a valid session send 403
        if not sid:
            abort(403)
        try:
            user = Users.Query.filter_by(id = id).first()
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
            user = Users.Query.filter_by(id=id).first()
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
    CORS(app)
    app.run(host='127.0.0.1', port=5000, debug=True)





    
