from application.database import *
from flask import Blueprint, redirect, render_template, request, session, current_app
from application.util import response, isAuthenticated, generateToken, isFromLocalhost, downloadManual
import sys

web = Blueprint('web', __name__)
service = Blueprint('service', __name__)

@web.route('/', methods=['GET'])
def loginView():
    return render_template('login.html')

@web.route('/register', methods=['GET'])
def registerView():
    return render_template('register.html')

@web.route('/home', methods=['GET'])
@isAuthenticated
def homeView(user):
    return render_template('index.html', user=user, flag=current_app.config['FLAG'])

@web.route('/product', methods=['GET'])
@isAuthenticated
def productView(user):
    return render_template('product.html', user=user)

@web.route('/logout')
def logout():
    session['token'] = None
    return redirect('/')

@service.route('/login', methods=['POST'])
def service_login():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = loginUserDb(username, password)
    
    if user:
        token = generateToken(user.get('username'), user.get('role'))
        session['token'] = token
        return response('Success'), 200
        
    return response('Invalid credentials!'), 403

@service.route('/register', methods=['POST'])
def service_register():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('Formulir tidak lengkap'), 401
    
    user = registerUserDb(username, password, 'user')
    
    if user:
        return response('Terdaftar! silahkan login'), 200
        
    return response('User sudah terdaftar'), 403

@service.route('/product', methods=['POST'])
@isAuthenticated
def sellProduct(user):
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()
    name = data.get('name', '')
    price = data.get('price', '')
    description = data.get('description', '')
    manualUrl = data.get('manual', '')

    if not name or not price or not description or not manualUrl:
        return response('Isi semua formulir'), 401

    manualPath = downloadManual(manualUrl)
    if (manualPath):
        addProduct(name, description, price)
        return response('Produk tersubmit. Silahkan menunggu verifikasi administrator kami')
    return response('URL Tidak Valid!'), 400


@service.route('/administratorAdd', methods=['GET'])
@isFromLocalhost
def administratorAdd():
    username = request.args.get('username')
    
    if not username:
        return response('Invalid username'), 400
    
    result = addAdmin(username)

    if result:
        return response('User updated!')
    return response('Invalid username'), 400