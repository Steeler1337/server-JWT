from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps
import base64

photo_string = ''

with open("my_photo.jpg", "rb") as img_file:
    photo_string = base64.b64encode(img_file.read())
    photo_string=photo_string.decode('utf-8')
    #print(my_string)


app = Flask(__name__)

app.config['SECRET_KEY'] = 'fedyaissecretkey'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') # http://127.0.0.1:5000/route?token=dasddsdasdasda
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401
        return f(*args, **kwargs)
    return decorated

def log_in(k):
    @wraps(k)
    def decorated_1(*args, **kwargs):
        username = request.args.get('username') # http://127.0.0.1:5000/login_iphone?username=dasddsdasdasda&password=dsdadasd
        password = request.args.get('password')
        print(password)
        if password != 'password' or username != 'fedya':
            return jsonify({'message' : 'Wrong password!'}), 401
        else:
            try:
                token = jwt.encode({'user' : username,  
                                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=50)}, 
                                app.config['SECRET_KEY'])
                return jsonify({'token' : token.decode('UTF-8')})
            except:
                return jsonify({'message' : 'Error'}), 401
            #return f(*args, **kwargs)
    return decorated_1

@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'Anyone can view this!'})

@app.route('/protected', methods=['POST', 'GET'])
@token_required
def protected():
    return jsonify({'message' : 'Congrats! Only people with valid token can see it.',
                    'server_time': str(datetime.datetime.now().time()),
                    'imageBase64' : photo_string
                    })

@app.route('/login')
def login():
    auth = request.authorization

    if auth and auth.password == 'password':
        token = jwt.encode({'user' : auth.username,  
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=50)}, 
                            app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    return make_response("Can't verify!", 401, {'WWW-Authenticate': 'Basic realm ="Login required!"'})

@app.route('/login_iphone', methods=['POST'])
@log_in
def login_iphone():
    return()
    # if auth and auth.password == 'password':
    #     token = jwt.encode({'user' : auth.username,  
    #                         'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=50)}, 
    #                         app.config['SECRET_KEY'])
    #     return jsonify({'token' : token.decode('UTF-8')})
    # return make_response("Can't verify!", 401, {'WWW-Authenticate': 'Basic realm ="Login required!"'})

if __name__=='__main__':
    app.run(debug=True)

