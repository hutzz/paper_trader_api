from index import db

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(256))
    username = db.Column(db.String(256))
    password = db.Column(db.String(256))
    balance = db.Column(db.Float)
    admin = db.Column(db.Boolean)

class Stock(db.Model):
    __tablename__ = 'stock'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    symbol = db.Column(db.String(8))
    price_at_purchase = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    