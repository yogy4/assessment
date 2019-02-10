from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User, BlacklistToken, Product

auth_blueprint = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    """
    Ini berisi method untuk registrasi
    """

    def post(self):
        post_data = request.get_json()
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    name=post_data.get('name'),
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )
                db.session.add(user)
                db.session.commit()
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202


class LoginAPI(MethodView):
    """
    Ini berisi method untuk login user
    """
    def post(self):
        post_data = request.get_json()
        try:
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode()
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


class UserAPI(MethodView):
    """
    Ini berisi method untuk objek user
    """
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'nama': user.nama
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class LogoutAPI(MethodView):
    """
    Ini berisi method untuk logout
    """
    def post(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class ProductAPI(MethodView):
    """
    Ini berisi method untuk objek product dan untuk mengakses perlu login terlebih dahulu
    """
    def post(self):
        auth_header = request.headers.get('Authorization')
        post_data = request.get_json()
        product = Product.query.filter_by(name=post_data.get('name')).first()

        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token and not product:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
            
                try:
                    # masukan inputan ke dalam tabel products
                    product = Product(
                    name=post_data.get('name'),
                    price=post_data.get('price'),
                    image_url=post_data.get('image_url'),
                    created_at=post_data.get('created_at'),
                    updated_at=post_data.get('updated_at')
                )
                    db.session.add(product)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully insert.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 401
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403

    def get(self):
        auth_header = request.headers.get('Authorization')
        isi = []
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
                resp = User.decode_auth_token(auth_token)
                if not isinstance(resp, str):
           
                    p = Product.query.all()
                    
                    for tampil in p:
                        responseObject = {
                            'status': 'success',
                            'data': {
                                'id': tampil.id,
                                'name': tampil.name,
                                'price': tampil.price,
                                'image_url': tampil.image_url,
                                'created_at': tampil.created_at,
                                'updated_at': tampil.updated_at,
                            }
                        }
                        isi.append(responseObject)
                   

                    return make_response(jsonify(isi)), 200
                   
                responseObject = {
                    'status': 'fatal',
                    'message': resp
                }
                isi.append(responseObject)
            
                return make_response(jsonify(responseObject)), 401
                

            
           
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
           
            return make_response(jsonify(responseObject)), 401
    
    def put(self):
        auth_header = request.headers.get('Authorization')
        post_data = request.get_json()
        product = Product.query.filter_by(id=post_data.get('id')).first()

        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token and not product:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                try:
                    name = str(request.data.get('name', ''))
                    product.name = name 
                    db.session.add(product)
                    db.session.commit()
                    responOb = {
                        'id': product.id,
                        'name': product.name,
                        'price': product.price,
                        'image_url': product.image_url,
                        'created_at': product.created_at,
                        'updated_at': product.updated_at
                    }
                    return make_response(jsonify(responOb)), 200
                except Exception as e:
                    responOb = {
                        'status': 'fail',
                        'message': e 
                    }
                    return make_response(jsonify(responOb)), 401
            else:
                responOb = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responOb)), 401
        else:
            responOb = {
                'status': 'fail',
                'message': 'Provide a valid auth token'
            }
            return make_response(jsonify(responOb)), 403
    
    def delete(self):
        auth_header = request.headers.get('Authorization')
        post_data = request.get_json()
        product = Product.query.filter_by(id=post_data.get('id')).first()

        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token and not product:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                try:
                    db.session.delete(product)
                    db.session.commit()
                    return {
                        "message": "Product {} deleted".format(product.id)
                    }, 200
                except Exception as e:
                    responOb = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responOb)), 401
            else:
                responOb = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responOb)), 401
        else: 
            responOb = {
                'status': 'fail',
                'message': 'Provide a valid auth token'
            }
            return make_response(jsonify(responOb)), 403




# mendefinisikan api
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')
product_view = ProductAPI.as_view('product_view')

# membuat endpoint untuk api
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/v1/products',
    view_func=product_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/v1/products',
    view_func=product_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/v1/products/<int:id>',
    view_func=product_view,
    methods=['PUT']
)
auth_blueprint.add_url_rule(
    '/v1/products/<int:id>',
    view_func=product_view,
    methods=['DELETE']
)
