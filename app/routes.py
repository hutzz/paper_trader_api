from index import app, db
from flask import request, jsonify
from app.models import User, Stock
from app.prices import get_hist_data
import yfinance as yf
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import uuid
import jwt
import datetime
import re

def require_token(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        token = None 
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Missing token.'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Invalid token.'}), 401
        return function(current_user, *args, **kwargs)
    return decorator

def require_refresh_token(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        token = None 
        if 'x-refresh-token' in request.headers:
            token = request.headers['x-refresh-token']
        if not token:
            return jsonify({'message': 'Missing refresh token.'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Invalid refresh token.'}), 401
        return function(current_user, *args, **kwargs)
    return decorator

@app.route('/user')
@require_token
def get_users(current_user):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        users = User.query.all()
        if not users:
            return jsonify({'message': 'No users found.'}), 404
        user_list = []
        for user in users:
            data = {}
            data['public_id'] = user.public_id
            data['email'] = user.email
            data['username'] = user.username
            data['password'] = user.password
            data['balance'] = user.balance
            data['admin'] = user.admin
            user_list.append(data)
        return jsonify({'users: ': user_list})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/user/<public_id>')
@require_token
def get_user(current_user, public_id):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        data = {}
        data['public_id'] = user.public_id
        data['username'] = user.username 
        data['password'] = user.password 
        data['balance'] = user.balance
        data['admin'] = user.admin 
        return jsonify(data)
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
    
@app.route('/me')
@require_token
def get_current_user(current_user):
    data = {}
    data['public_id'] = current_user.public_id
    data['username'] = current_user.username 
    data['balance'] = current_user.balance
    data['admin'] = current_user.admin
    return jsonify(data) 

@app.route('/user', methods=['POST'])
@require_token
def create_user(current_user):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        data = request.get_json()
        hashed_pw = generate_password_hash(data['password'], method='sha256')
        user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_pw, admin=data['admin'])
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User created.'})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/user/<public_id>', methods=['DELETE'])
@require_token
def delete_user(current_user, public_id):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted.'})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/login')
def login():
    try:
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return jsonify({'message': 'Invalid or missing credentials.'}), 401
        user = User.query.filter_by(username=auth.username).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm='HS256')
            refresh = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=15)}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token, 'refresh': refresh})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
    return jsonify({'message': 'Invalid or missing credentials.'}), 401

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not re.search(r".+@.+\..+", data['email']) or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data['email']) or len(data['email']) > 128 or not data['email'].isascii():
            return jsonify({'message': 'Invalid email. Check for any special characters that may be present, and ensure that the entered email address is formatted correctly.'}), 401
        if not data['username'] or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data['username']) or len(data['username']) > 32 or not data['username'].isascii():
            return jsonify({'message': 'Invalid username. Check for any special characters that may be present.'}), 401
        if not data['password'] or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data['password']) or len(data["password"]) < 8 or not data['password'].isascii():
            return jsonify({'message': 'Invalid password. Check for any special characters that may be present.'}), 401
        hashed_pw = generate_password_hash(data['password'], method='sha256')
        user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=hashed_pw, balance=10000.00, admin=False)
        db.session.add(user)
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
    try:
        db.session.commit()
    except:
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({'message': 'User created.'})

@app.route('/refresh')
@require_refresh_token
def refresh_token(current_user):
    try:
        refresh_token = request.headers['x-refresh-token']
        if not refresh_token:
            return jsonify({'message': 'Missing refresh token.'}), 401
        try:
            jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Invalid refresh token.'}), 401
        if not current_user:
            return jsonify({'message': 'User not found.'}), 404
        return jsonify({'token': jwt.encode({'public_id': current_user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm='HS256'), 'refresh': jwt.encode({'public_id': current_user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=15)}, app.config['SECRET_KEY'], algorithm='HS256')})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/stock/<symbol>', methods=['POST'])
def get_stock_data(symbol):
    try:
        ticker = yf.Ticker(symbol.upper())
        data = request.get_json()
        interval = data['interval']
        period = data['period']
        try:
            hist_data = get_hist_data(ticker, interval, period)
        except:
            return jsonify({'message': 'Invalid input.'}), 403
        return jsonify(hist_data)
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/stock/get')
@require_token 
def get_user_stocks(current_user):
    try:
        stocks = Stock.query.filter_by(user_id=User.query.filter_by(public_id=current_user.public_id).first().id).all()
        if not stocks:
            return jsonify({'message': 'User has no stocks!'}), 400
        stock_list = []
        for stock in stocks:
            data = {}
            data['symbol'] = stock.symbol
            data['price'] = round(get_hist_data(yf.Ticker(stock.symbol.upper()), interval="1d", period="1d")['Close'][-1], 2)
            data['quantity'] = stock.quantity
            stock_list.append(data)
        return jsonify(stock_list)
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/stock/buy', methods=['POST'])
@require_token
def buy_stock(current_user):
    data = request.get_json()
    try:
        if data['quantity'] < 1:
            return jsonify({'message': 'Quantity must be at least 1.'}), 400
        if not str(data['quantity']).isdigit():
            return jsonify({'message': 'Quantity must be an integer.'}), 400
        ticker = yf.Ticker(data['symbol'].upper())
        current_price = round(get_hist_data(ticker, interval="1d", period="1d")['Close'][-1], 2)
    except:
        return jsonify({'message': 'Invalid input.'}), 403
    try:
        data['quantity'] = int(data['quantity'])
        stock = Stock(user_id=User.query.filter_by(public_id=current_user.public_id).first().id, symbol=data['symbol'].upper(), price_at_purchase=current_price, quantity=data['quantity'])
        current_stock = Stock.query.filter_by(user_id=User.query.filter_by(public_id=current_user.public_id).first().id, symbol=data['symbol'].upper()).first()
        if current_stock:
            current_stock.quantity += data['quantity']
        else:
            db.session.add(stock)
        current_user.balance -= current_price * data['quantity']
        current_user.balance = round(current_user.balance, 2) # correcting potential floating point imprecision 
        if current_user.balance < 0:
            return jsonify({'message': 'Insufficient funds!'})
        db.session.commit()
    except:
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({'message': f'Successfully purchased {data["quantity"]} {data["symbol"].upper()}.'})

@app.route('/stock/sell', methods=['POST'])
@require_token
def sell_stock(current_user):
    data = request.get_json()
    try:
        if data['quantity'] < 1:
            return jsonify({'message': 'Quantity must be at least 1.'}), 400
        if not str(data['quantity']).isdigit():
            return jsonify({'message': 'Quantity must be an integer.'}), 400
        ticker = yf.Ticker(data['symbol'].upper())
        current_price = round(get_hist_data(ticker, interval="1d", period="1d")['Close'][-1], 2)
    except:
        return jsonify({'message': 'Invalid input.'}), 403
    try:
        stock = Stock.query.filter_by(user_id=User.query.filter_by(public_id=current_user.public_id).first().id, symbol=data['symbol'].upper()).first()
        if not stock:
            return jsonify({'message': 'Stock not found!'}), 404
        if stock.quantity < data['quantity']:
            return jsonify({'message': f'You have less than {data["quantity"]} of that stock!'}), 400
        stock.quantity -= data['quantity'] 
        if stock.quantity == 0: 
            db.session.delete(stock)
        current_user.balance += current_price * data['quantity']
        current_user.balance = round(current_user.balance, 2) # correcting potential floating point imprecision 
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({'message': f'Successfully sold {data["quantity"]} {data["symbol"].upper()}.'})

@app.route('/expiry', methods=['POST'])
def get_expiry_time():
    data = request.get_json()
    token = data['token']
    print(token)
    if not token:
        return jsonify({'error': 'Token is missing'}), 400
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_signature": False},)
        expiry_time = decoded_token['exp']
        return jsonify({'expiry_time': expiry_time})
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401
        
@app.route('/stock/reset')
@require_token 
def reset_self(current_user):
    try:
        stocks = Stock.query.filter_by(user_id=User.query.filter_by(public_id=current_user.public_id).first().id).all()
        if not stocks:
            return jsonify({'message': 'User has no stocks!'}), 400
        current_user.balance = 10000.00
        for stock in stocks:
            db.session.delete(stock)
        db.session.commit()
        return jsonify({'message': 'Successfully reset your stock purchases and account balance.'})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
