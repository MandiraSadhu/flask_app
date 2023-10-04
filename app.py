
from flask import Flask,request,jsonify
from flask_bcrypt import Bcrypt
from flask_restful import Resource, Api
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, jwt_required, create_access_token,get_jwt_identity
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from bson import ObjectId

uri = "mongodb+srv://mandirasadhu:K24wKc8lmDzJ6EBT@cluster0.y5expcz.mongodb.net/Users_data?retryWrites=true&w=majority"

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

app = Flask(__name__)
app.config['MONGO_URI'] = uri
app.config['JWT_SECRET_KEY'] = 'your-secret-key-here'

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
bcrypt = Bcrypt(app)
mongo = PyMongo(app)
api = Api(app)
jwt = JWTManager(app)

class Register(Resource):
    def post(self):
        data = request.get_json()
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = bcrypt.generate_password_hash(data.get("password")).decode('utf-8')

        # Check if the user already exists in the database (you should add more checks here)
        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            return {'message': 'User already exists'}, 400

        # Insert the new user into the database (you should hash the password)
        user_id = mongo.db.users.insert_one({'first_name': first_name, 'last_name': last_name, 'email': email, 'password': password})

        return {'message': 'User registered successfully', 'user_id': str(user_id)}, 201

class Login(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        # Find the user by email in the database
        user = mongo.db.users.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            # Password matches, create an access token (you may need Flask-JWT-Extended)
            access_token = create_access_token(identity=email)
            return {'message': 'Login successful', 'access_token': access_token}, 200
        else:
            return {'message': 'Invalid email or password'}, 401

class create_template(Resource):
    @jwt_required()
    def post(self):
        try:
            current_user = get_jwt_identity()
            print("mandira = ",current_user)
            data = request.get_json()
            template_name = data.get('template_name')
            subject = data.get('subject')
            body = data.get('body')

            template = mongo.db.template.insert_one({'template_name':template_name,'subject':subject,'body':body})
            return {'message': 'Template created successfully', 'template_id': str(template.inserted_id)}, 201
        except e:
            print(e)  # Log the error for debugging purposes
            return {'message': 'An error occurred while creating the template'}, 500

    @jwt_required()
    def get(self):
        templates = mongo.db.template.find()
        template_list = []
        for template in templates:
            template['_id'] = str(template['_id'])
            template_list.append(template)
        return {'templates': template_list}, 200

class SingleTemplateResource(Resource):
    @jwt_required()
    def get(self, template_id):
        template = mongo.db.template.find_one({'_id': ObjectId(template_id)})
        if template:
            template['_id'] = str(template['_id'])
            return {'template': template}, 200
        else:
            return {'message': 'Template not found'}, 404

    @jwt_required()
    def put(self, template_id):
        data = request.get_json()
        template_name = data.get('template_name')
        subject = data.get('subject')
        body = data.get('body')

        result = mongo.db.template.update_one({'_id': ObjectId(template_id)},
                                              {'$set': {'template_name': template_name, 'subject': subject, 'body': body}})
        if result.modified_count > 0:
            return {'message': 'Template updated successfully'}, 200
        else:
            return {'message': 'Template not found'}, 404

    @jwt_required()
    def delete(self, template_id):
        result = mongo.db.template.delete_one({'_id': ObjectId(template_id)})
        if result.deleted_count > 0:
            return {'message': 'Template deleted successfully'}, 200
        else:
            return {'message': 'Template not found'}, 404



api.add_resource(Register, '/register')
api.add_resource(Login,'/login')
api.add_resource(create_template,'/insert')
api.add_resource(SingleTemplateResource, '/template/<string:template_id>')




if __name__ == '__main__':
    app.run(debug=True)


