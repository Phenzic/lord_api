from flask import Blueprint, Flask, request, jsonify
from flask_jwt_extended import  JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from mongo_app import user_uri, vault_uri
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import os
import binascii
import hmac
import hashlib
from cryptography.fernet import Fernet

 
user_client = MongoClient(user_uri)
vault_client = MongoClient(vault_uri)

sandbox_db = vault_client.db.api_vault
api_data = user_client.client

app = Flask(__name__)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)


sandbox_api = Blueprint('sandbox', __name__)
live_api = Blueprint('live', __name__)
# api = Blueprint('api', __name__)





class HMACHelper:
    def __init__(self, secret_key):
        self.secret_key = secret_key.encode()

    def generate_key(self):
        # Generate a random key
        key = binascii.hexlify(os.urandom(24)).decode()
        # Create a HMAC signature for the key
        signature = hmac.new(self.secret_key, key.encode(), hashlib.sha256).hexdigest()
        return key, signature

    def verify_key(self, key, signature):
        # Recreate the HMAC signature with the provided key
        expected_signature = hmac.new(self.secret_key, key.encode(), hashlib.sha256).hexdigest()
        # Compare the provided signature with the expected one
        return hmac.compare_digest(expected_signature, signature)

@sandbox_api.route('/create_sandbox_key')
@jwt_required()
def create_sandbox_key():
    creator = get_jwt_identity()
    key = os.getenv("API_SANDBOX_KEY")
    hmac_helper = HMACHelper(key)

    # Generate a new API key and its signature
    api_key, api_signature = hmac_helper.generate_key()

    # Generate a new secret key and its signature
    secret_key, secret_signature = hmac_helper.generate_key()

    # print(api_key, api_signature, secret_key, secret_signature)

    # Assuming the creator is the user's id in the MongoDB database
    user_id = creator
    user = api_data.client_app.find_one({'_id': user_id})
    if user:
    # If the user already has an array of API keys, append the new key
        # if 'api_keys' in user:
        api_data.client_app.update_one({'_id': user_id}, {'$push': {'sandbox_api': {'key': api_key, 'secret': secret_key}}})
    # If the user doesn't have an array of API keys, create a new one
    # else:
    #     api_data.client_app.update_one({'_id': user_id}, {'$set': {'sandbox_api': [{'key': api_key, 'secret': secret_key}]}})

    # Repeat the same process for the sandbox collection
        api_user = sandbox_db.find_one({'id': user_id})
        if api_user:
            sandbox_db.update_one({'id': user_id}, {'$push': {'sandbox_keys': {'key': api_key, 'secret': secret_key}}})
        else:
            sandbox_db.insert_one({'id': user_id, 'sandbox_keys': [{'key': api_key, 'secret': secret_key}]})

        return jsonify({'status': 'API key and secret key created and stored successfully', "api_key": api_key, "secret_key": secret_key}), 201

    return jsonify({'status': 'User not found'}), 404

@live_api.route('/create_live_key')
@jwt_required()
def create_live_key():
    creator = get_jwt_identity()
    key = os.getenv("API_LIVE_KEY")
    hmac_helper = HMACHelper(key)

    # Generate a new API key and its signature
    api_key, api_signature = hmac_helper.generate_key()

    # Generate a new secret key and its signature
    secret_key, secret_signature = hmac_helper.generate_key()

    # print(api_key, api_signature, secret_key, secret_signature)

    # Assuming the creator is the user's id in the MongoDB database
    user_id = creator
    user = api_data.client_app.find_one({'_id': user_id})
    if user:
    # If the user already has an array of API keys, append the new key
        # if 'api_keys' in user:
        api_data.client_app.update_one({'_id': user_id}, {'$push': {'live_api': {'key': api_key, 'secret': secret_key}}})
    # If the user doesn't have an array of API keys, create a new one
    # else:
    #     api_data.client_app.update_one({'_id': user_id}, {'$set': {'sandbox_api': [{'key': api_key, 'secret': secret_key}]}})

    # Repeat the same process for the sandbox collection
        api_user = sandbox_db.find_one({'id': user_id})
        # print(api_user)
        if api_user:
            sandbox_db.update_one({'id': user_id}, {'$push': {'live_keys': {'key': api_key, 'secret': secret_key}}})
        else:
            sandbox_db.insert_one({'id': user_id, 'live_keys': [{'key': api_key, 'secret': secret_key}]})

        return jsonify({'status': 'API key and secret key created and stored successfully', "api_key": api_key, "secret_key": secret_key}), 201

    return jsonify({'status': 'User not found'}), 404


@sandbox_api.route("/delete_sandbox_api", methods=["POST"])
@jwt_required()
def delete_sandbox_key():
    creator = get_jwt_identity()
    # Get the API key and secret key from the request payload
    payload = request.get_json()
    api_key = payload.get('api_key')
    secret_key = payload.get('secret_key')

    # Assuming the creator is the user's id in the MongoDB database
    user_id = creator
    user = sandbox_db.find_one({'id': user_id})
    print(user)
    if user:
        # user.update_one({'id': user_id}, {'$pull': {'sandbox_keys': {'key': api_key, 'secret': secret_key},}}})
        # Check if the key pair exists in the user's document
        if any(key_pair for key_pair in user['sandbox_keys'] if {key_pair['key'] == api_key, key_pair['secret'] == secret_key}): #or \
        # any(key_pair for key_pair in user['live_keys'] if key_pair['key'] == api_key and key_pair['secret'] == secret_key):
            # Remove the API key and secret key from the user's document

            result = sandbox_db.update_one({'id': user_id}, {'$pull': {'sandbox_keys': {'key': api_key, 'secret': secret_key}}})
            if result.modified_count > 0:
                return jsonify({'status': 'API key and secret key deleted successfully'}), 200
            else:
                return jsonify({'status': 'No keys were deleted'}), 400
        else:
            return jsonify({'status': 'Key pair not found'}), 404
    else:
        return jsonify({'status': 'User not found'}),



@sandbox_api.route("/delete_live_api", methods=["POST"])
@jwt_required()
def delete_api_key():
    creator = get_jwt_identity()
    # Get the API key and secret key from the request payload
    payload = request.get_json()
    api_key = payload.get('api_key')
    secret_key = payload.get('secret_key')

    # Assuming the creator is the user's id in the MongoDB database
    user_id = creator
    user = sandbox_db.find_one({'id': user_id})
    user_id = creator
    user = sandbox_db.find_one({'id': user_id})

    if user:
        # Check if the key pair exists in the user's document
        if any(key_pair for key_pair in user['live_keys'] if key_pair['key'] == api_key and key_pair['secret'] == secret_key):
            # Remove the API key and secret key from the user's document
            sandbox_db.update_one({'id': user_id}, {'$pull': {'api_keys': {'key': api_key, 'secret': secret_key}}})
            return jsonify({'status': 'API key and secret key deleted successfully'}), 200
        else:
            return jsonify({'status': 'Key pair not found'}), 404
    else:
        return jsonify({'status': 'User not found'}), 404
    




# @sandbox_api.route('/delete_live_key', methods=['POST'])
# @jwt_required()
# def create_api_key():
#     creator = get_jwt_identity()



@sandbox_api.route('/')
def index():
    """
    Default endpoint.
    """
    return 'Welcome to the API server!'



@sandbox_api.route('/bvn_verification', methods = ["POST"])
@jwt_required()
def sb_bvn_verification():
    creator = get_jwt_identity()
    bvn = request.json["bvn"]
    print(bvn)
    if bvn == "1111111111":
        response_data =  True
    elif bvn == "0000000000":
        response_data = False
    return jsonify(response_data)






# @app.route('/api/data', methods=['GET', 'POST'])
# def handle_data():
#     if request.method == 'POST':
#         data.append(request.json)
#         return jsonify({'status': 'Data added'}), 201
#     else:
#         return jsonify(data)



app.register_blueprint(sandbox_api, url_prefix='/sandbox/api/v1')
app.register_blueprint(live_api, url_prefix='/api/v1')
# app.register_blueprint(api, url_prefix='/api/v1')


if __name__ == '__main__':
    app.run(debug=True)

