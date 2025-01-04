from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Email, Length
from wtforms import StringField, PasswordField, SubmitField, SelectField
from sqlalchemy.exc import IntegrityError
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
import os
from flask import g
from functools import wraps
from requests.auth import HTTPBasicAuth
import requests
import base64
from datetime import datetime
import json
from flask import Flask, jsonify, request
# Add these imports at the top of your app.py
import os
from urllib.parse import urljoin







UPLOAD_FOLDER = 'static/uploads'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
# Add this configuration after your other app configs
NGROK_URL = None  # This will be updated when you start your application

db = SQLAlchemy(app)


# Models
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    orders = db.relationship('Order', backref='user', lazy=True)


class ProductImage(db.Model):
    __tablename__ = 'product_images'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    image_url = db.Column(db.String(200), nullable=False)


class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    price = db.Column(db.Float, nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False)
    order_items = db.relationship('OrderItem', backref='product', lazy=True)
    images = db.relationship('ProductImage', backref='product', lazy=True)


class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Pending')
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    order_items = db.relationship('OrderItem', backref='order', lazy=True)
    payment = db.relationship('Payment', backref='order', uselist=False)


class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_at_time = db.Column(db.Float, nullable=False)


class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False, default="MPESA")
    payment_status = db.Column(db.String(50), nullable=False)
    mpesa_transaction_id = db.Column(db.String(100), nullable=True)
    checkout_request_id = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(15), nullable=True)

# Forms
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class EditUserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    role = SelectField('Role', coerce=int, choices=[])
    submit = SubmitField('Update')


class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    price = StringField('Price', validators=[DataRequired()])
    stock_quantity = StringField('Stock Quantity', validators=[DataRequired()])
    images = FileField('Images', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Submit')


from flask import Flask, jsonify, request
import requests
from requests.auth import HTTPBasicAuth
import base64
from datetime import datetime
import json


class MpesaC2bCredential:
    consumer_key = 'vbxsneeZ9IMFoyKKIgOIQQZFlawAADnP'
    consumer_secret = 'WAzDhQVhitIXwiTc'
    api_URL = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'


class MpesaAccessToken:
    @staticmethod
    def validated_mpesa_access_token():
        try:
            consumer_key = MpesaC2bCredential.consumer_key
            consumer_secret = MpesaC2bCredential.consumer_secret
            api_URL = MpesaC2bCredential.api_URL

            r = requests.get(api_URL, auth=HTTPBasicAuth(consumer_key, consumer_secret))
            r.raise_for_status()  # Raise an exception for bad status codes
            mpesa_access_token = json.loads(r.text)
            return mpesa_access_token['access_token']
        except requests.exceptions.RequestException as e:
            print(f"Error getting access token: {str(e)}")
            raise Exception("Failed to get M-Pesa access token")


class LipaNaMpesaOnline:
    def __init__(self):
        self.timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        self.business_shortcode = "174379"
        self.passkey = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'

    def encode_password(self):
        data_to_encode = self.business_shortcode + self.passkey + self.timestamp
        return base64.b64encode(data_to_encode.encode()).decode('utf-8')

    def initiate_stk_push(self, phone_number, amount, callback_url):
        try:
            access_token = MpesaAccessToken.validated_mpesa_access_token()
            api_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"

            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            payload = {
                "BusinessShortCode": self.business_shortcode,
                "Password": self.encode_password(),
                "Timestamp": self.timestamp,
                "TransactionType": "CustomerPayBillOnline",
                "Amount": int(amount),  # Ensure amount is an integer
                "PartyA": int(phone_number),  # Convert phone number to integer
                "PartyB": self.business_shortcode,
                "PhoneNumber": int(phone_number),  # Convert phone number to integer
                "CallBackURL": callback_url,
                "AccountReference": "LevisStore",
                "TransactionDesc": "Payment for order"
            }

            response = requests.post(api_url, json=payload, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"Error in STK push: {str(e)}")
            if hasattr(e.response, 'text'):
                print(f"M-Pesa API response: {e.response.text}")
            raise Exception("Failed to initiate M-Pesa payment")




# Admin Required Decorator
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id') or session.get('user_role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user_role = Role.query.filter_by(
            name='admin' if form.email.data == 'admin@levisstore.com' else 'customer').first()

        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password_hash=hashed_password,
            phone_number=form.phone_number.data,
            role_id=user_role.id
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already exists.', 'danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role.name
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/products')
def products():
    products = Product.query.all()
    return render_template('products.html', products=products)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)

    existing_order_item = None
    if 'user_id' in session:
        order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
        if order:
            existing_order_item = OrderItem.query.filter_by(order_id=order.id, product_id=product_id).first()

    return render_template('product_detail.html', product=product, existing_order_item=existing_order_item)


@app.route('/admin/add_product', methods=['GET', 'POST'])
@admin_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            description=form.description.data,
            price=float(form.price.data),
            stock_quantity=int(form.stock_quantity.data)
        )
        db.session.add(product)
        db.session.commit()

        if form.images.data:
            for image in request.files.getlist('images'):
                filename = secure_filename(image.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(image_path), exist_ok=True)
                image.save(image_path)

                product_image = ProductImage(
                    product_id=product.id,
                    image_url=filename  # Store just the filename
                )
                db.session.add(product_image)

            db.session.commit()

        flash('Product added successfully!', 'success')
        return redirect(url_for('manage_products'))

    return render_template('add_product.html', form=form)

@app.route('/product/<int:product_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)

    if form.validate_on_submit():
        product.name = form.name.data
        product.description = form.description.data
        product.price = float(form.price.data)
        product.stock_quantity = int(form.stock_quantity.data)

        if 'delete_images' in request.form:
            for image_id in request.form.getlist('delete_images'):
                image = ProductImage.query.get(int(image_id))
                if image:
                    try:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], image.image_url)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        db.session.delete(image)
                    except Exception as e:
                        print(f"Error deleting image: {e}")

        if form.images.data:
            for image in request.files.getlist('images'):
                if image.filename:
                    filename = secure_filename(image.filename)
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    os.makedirs(os.path.dirname(image_path), exist_ok=True)
                    image.save(image_path)

                    product_image = ProductImage(
                        product_id=product.id,
                        image_url=filename  # Store just the filename
                    )
                    db.session.add(product_image)

        try:
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('manage_products'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating product.', 'danger')
            print(f"Database error: {e}")

    return render_template('edit_product.html', form=form, product=product)



@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    # Delete associated images
    for image in product.images:
        try:
            file_path = os.path.join(app.root_path, image.image_url)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error deleting image file: {e}")

    try:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting product.', 'danger')
        print(f"Database error: {e}")

    return redirect(url_for('manage_products'))


@app.route('/cart')
def view_cart():
    if 'user_id' not in session:
        flash('Please login to view your cart.', 'info')
        return redirect(url_for('login'))

    order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
    if not order:
        return render_template('cart.html', order_items=None, total_price=0)

    order_items = OrderItem.query.filter_by(order_id=order.id).all()
    total_price = sum(item.quantity * item.price_at_time for item in order_items)

    return render_template('cart.html', order_items=order_items, total_price=total_price)


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash('Please login to add items to cart.', 'info')
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)
    quantity = int(request.form.get('quantity', 1))

    if quantity > product.stock_quantity:
        flash('Not enough stock available.', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))

    order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
    if not order:
        order = Order(user_id=session['user_id'], total_price=0, status="Pending")
        db.session.add(order)
        db.session.commit()

    order_item = OrderItem.query.filter_by(order_id=order.id, product_id=product_id).first()
    if order_item:
        order_item.quantity += quantity
    else:
        order_item = OrderItem(
            order_id=order.id,
            product_id=product_id,
            quantity=quantity,
            price_at_time=product.price
        )
        db.session.add(order_item)

    product.stock_quantity -= quantity
    order.total_price = sum(item.quantity * item.price_at_time for item in order.order_items)

    try:
        db.session.commit()
        flash('Item added to cart!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error adding item to cart.', 'danger')
        print(f"Database error: {e}")

    return redirect(url_for('view_cart'))


@app.route('/remove_from_cart/<int:order_item_id>', methods=['POST'])
def remove_from_cart(order_item_id):
    order_item = OrderItem.query.get_or_404(order_item_id)

    # Return stock quantity
    product = Product.query.get(order_item.product_id)
    product.stock_quantity += order_item.quantity

    # Update order total price
    order = Order.query.get(order_item.order_id)
    order.total_price -= order_item.quantity * order_item.price_at_time

    # Delete order item
    db.session.delete(order_item)

    try:
        db.session.commit()
        flash('Item removed from cart.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error removing item from cart.', 'danger')
        print(f"Database error: {e}")

    return redirect(url_for('view_cart'))




@app.route('/order_confirmation/<int:order_id>')
def order_confirmation(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != session.get('user_id'):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))
    return render_template('order_confirmation.html', order=order)


@app.route('/admin/manage_products')
@admin_required
def manage_products():
    products = Product.query.all()
    return render_template('manage_products.html', products=products)


@app.route('/admin/manage_users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)



@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)
    form.role.choices = [(role.id, role.name) for role in Role.query.all()]

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        user.phone_number = form.phone_number.data
        user.role_id = form.role.data

        try:
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('manage_users'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already exists.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash('Error updating user.', 'danger')
            print(f"Database error: {e}")

    return render_template('edit_user.html', form=form, user=user)

@app.route('/my_orders')
def my_orders():
    if 'user_id' not in session:
        flash('Please log in to view your orders.', 'info')
        return redirect(url_for('login'))

    user_orders = Order.query.filter_by(user_id=session['user_id']).order_by(Order.created_at.desc()).all()
    return render_template('my_orders.html', orders=user_orders)


# Add to your existing imports
from datetime import datetime


# Add new route before the checkout route
@app.route('/checkout_page')
def checkout_page():
    if 'user_id' not in session:
        flash('Please login to checkout.', 'warning')
        return redirect(url_for('login'))

    order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
    if not order:
        flash('Your cart is empty.', 'info')
        return redirect(url_for('view_cart'))

    return render_template('checkout.html', order=order)


# Modify existing checkout route
@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        flash('Please login to checkout.', 'warning')
        return redirect(url_for('login'))

    order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
    if not order:
        flash('Your cart is empty.', 'info')
        return redirect(url_for('view_cart'))

    mpesa_transaction_id = request.form.get('mpesa_transaction_id')

    if not mpesa_transaction_id:
        flash('Please provide MPESA transaction ID.', 'danger')
        return redirect(url_for('checkout_page'))

    payment = Payment(
        order_id=order.id,
        payment_method="MPESA",
        payment_status="Completed",
        mpesa_transaction_id=mpesa_transaction_id
    )
    db.session.add(payment)
    order.status = "Processing"

    try:
        db.session.commit()
        flash('Order placed successfully!', 'success')
        return redirect(url_for('order_confirmation', order_id=order.id))
    except Exception as e:
        db.session.rollback()
        flash('Error processing order.', 'danger')
        return redirect(url_for('checkout_page'))

# Add to routes

@app.route('/admin/manage_orders', methods=['GET'])
@admin_required
def manage_orders():
    # Get filter parameters
    status = request.args.get('status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Build query
    query = Order.query

    # Apply filters
    if status:
        query = query.filter(Order.status == status)
    if start_date:
        query = query.filter(Order.created_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(Order.created_at <= datetime.strptime(end_date, '%Y-%m-%d'))

    # Fetch filtered orders
    orders = query.order_by(Order.created_at.desc()).all()

    return render_template('manage_orders.html', orders=orders)



@app.route('/admin/update_order_status/<int:order_id>', methods=['POST'])
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    if new_status in ['Processing', 'Shipped', 'Delivered', 'Cancelled']:
        order.status = new_status
        db.session.commit()
        flash('Order status updated successfully!', 'success')
    return redirect(url_for('manage_orders'))

def get_cart_unique_items():
    if 'user_id' in session:
        order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
        if order:
            return OrderItem.query.filter_by(order_id=order.id).count()
    return 0

@app.context_processor
def inject_cart_count():
    return dict(cart_count=get_cart_unique_items())



def check_mpesa_status(checkout_request_id):
    """Check the status of an M-Pesa transaction"""
    try:
        access_token = MpesaAccessToken.validated_mpesa_access_token()
        api_url = "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query"

        mpesa = LipaNaMpesaOnline()

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "BusinessShortCode": mpesa.business_shortcode,
            "Password": mpesa.encode_password(),
            "Timestamp": mpesa.timestamp,
            "CheckoutRequestID": checkout_request_id
        }

        response = requests.post(api_url, json=payload, headers=headers)
        return response.json()

    except Exception as e:
        print(f"Error querying M-Pesa status: {str(e)}")
        return {"ResultCode": -1, "ResultDesc": "Error querying status"}


@app.route('/mpesa_callback', methods=['POST'])
def mpesa_callback():
    try:
        callback_data = request.get_json()
        print("M-Pesa Callback Data:", callback_data)  # Debug log

        # Extract the STK callback data
        stk_callback = callback_data.get('Body', {}).get('stkCallback', {})
        checkout_request_id = stk_callback.get('CheckoutRequestID')
        result_code = stk_callback.get('ResultCode')

        # Find the payment record
        payment = Payment.query.filter_by(checkout_request_id=checkout_request_id).first()
        if not payment:
            print(f"Payment not found for CheckoutRequestID: {checkout_request_id}")
            return jsonify({'error': 'Payment not found'}), 404

        # Handle successful payment
        if result_code == 0:
            try:
                # Extract payment details from callback metadata
                callback_metadata = stk_callback.get('CallbackMetadata', {}).get('Item', [])
                mpesa_receipt_number = None
                amount = None
                transaction_date = None
                phone_number = None

                # Extract specific fields from metadata
                for item in callback_metadata:
                    if item.get('Name') == 'MpesaReceiptNumber':
                        mpesa_receipt_number = str(item.get('Value'))
                    elif item.get('Name') == 'Amount':
                        amount = item.get('Value')
                    elif item.get('Name') == 'TransactionDate':
                        transaction_date = str(item.get('Value'))
                    elif item.get('Name') == 'PhoneNumber':
                        phone_number = str(item.get('Value'))

                print(f"Extracted M-Pesa Receipt Number: {mpesa_receipt_number}")  # Debug log

                if mpesa_receipt_number:
                    # Update payment record with transaction details
                    payment.payment_status = "Completed"
                    payment.mpesa_transaction_id = mpesa_receipt_number

                    # Update order status
                    order = Order.query.get(payment.order_id)
                    if order:
                        order.status = "Processing"

                    # Commit the transaction
                    db.session.commit()
                    print(f"Payment completed successfully. Order ID: {payment.order_id}, "
                          f"Transaction ID: {payment.mpesa_transaction_id}")
                else:
                    print("Warning: No M-Pesa receipt number found in callback data")

            except Exception as e:
                db.session.rollback()
                print(f"Error updating payment record: {str(e)}")
                raise

        # Handle failed payment
        elif result_code not in [None, "", "Pending"]:
            payment.payment_status = "Failed"
            db.session.commit()
            print(f"Payment failed with ResultCode: {result_code}")

        return jsonify({'success': True}), 200

    except Exception as e:
        print(f"Error processing M-Pesa callback: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/check_payment_status/<checkout_request_id>')
def check_payment_status(checkout_request_id):
    try:
        # Find payment record
        payment = Payment.query.filter_by(checkout_request_id=checkout_request_id).first()
        if not payment:
            return jsonify({
                'status': 'Failed',
                'message': 'Payment not found'
            }), 404

        # If payment is already completed
        if payment.payment_status == "Completed" and payment.mpesa_transaction_id:
            try:
                # Ensure order status is updated
                order = Order.query.get(payment.order_id)
                if order and order.status == "Pending":
                    order.status = "Processing"
                    db.session.commit()

                return jsonify({
                    'status': 'Completed',
                    'order_id': payment.order_id,
                    'transaction_id': payment.mpesa_transaction_id
                })
            except Exception as e:
                db.session.rollback()
                print(f"Error updating order status: {str(e)}")
                raise

        elif payment.payment_status == "Failed":
            return jsonify({
                'status': 'Failed',
                'message': 'Payment failed. Please try again.'
            })

        # Check M-Pesa status for pending payments
        mpesa_status = check_mpesa_status(checkout_request_id)
        if not mpesa_status:
            return jsonify({
                'status': 'Pending',
                'message': 'Payment is being processed'
            })

        result_code = mpesa_status.get('ResultCode')
        if isinstance(result_code, str):
            try:
                result_code = int(result_code)
            except (ValueError, TypeError):
                result_code = None

        # Process M-Pesa status response
        if result_code == 0:
            # Extract transaction ID from status check if available
            transaction_id = mpesa_status.get('MpesaReceiptNumber')
            try:
                payment.payment_status = "Completed"
                if transaction_id:
                    payment.mpesa_transaction_id = transaction_id

                order = Order.query.get(payment.order_id)
                if order:
                    order.status = "Processing"
                db.session.commit()

                return jsonify({
                    'status': 'Completed',
                    'order_id': payment.order_id,
                    'transaction_id': payment.mpesa_transaction_id
                })
            except Exception as e:
                db.session.rollback()
                print(f"Error updating payment status: {str(e)}")
                raise

        elif result_code is not None:
            payment.payment_status = "Failed"
            db.session.commit()
            return jsonify({
                'status': 'Failed',
                'message': 'Payment failed. Please try again.'
            })

        return jsonify({
            'status': 'Pending',
            'message': 'Payment is being processed'
        })

    except Exception as e:
        print(f"Error checking payment status: {str(e)}")
        return jsonify({
            'status': 'Pending',
            'message': 'Payment status check is temporarily unavailable'
        })

# Modify your initiate_payment route
@app.route('/initiate_payment', methods=['POST'])
def initiate_payment():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Please login to checkout'}), 401

        if not NGROK_URL:
            return jsonify({'error': 'Callback URL not configured. Please ensure ngrok is running.'}), 500

        phone_number = request.form.get('phone_number')
        if not phone_number:
            return jsonify({'error': 'Phone number is required'}), 400

        # Clean and format phone number
        phone_number = phone_number.strip()
        if phone_number.startswith('+'):
            phone_number = phone_number[1:]
        elif phone_number.startswith('0'):
            phone_number = '254' + phone_number[1:]
        elif not phone_number.startswith('254'):
            phone_number = '254' + phone_number

        # Validate phone number format
        if not phone_number.isdigit() or len(phone_number) != 12:
            return jsonify({'error': 'Invalid phone number format'}), 400

        order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
        if not order:
            return jsonify({'error': 'No pending order found'}), 404

        amount = int(order.total_price)

        # Create payment record
        payment = Payment(
            order_id=order.id,
            payment_method="MPESA",
            payment_status="Pending",
            phone_number=phone_number
        )
        db.session.add(payment)
        db.session.commit()

        # Initialize STK Push with ngrok callback URL
        mpesa = LipaNaMpesaOnline()
        callback_url = urljoin(NGROK_URL, '/mpesa_callback')
        print(f"Callback URL: {callback_url}")  # For debugging

        response = mpesa.initiate_stk_push(phone_number, amount, callback_url)

        if 'CheckoutRequestID' in response:
            payment.checkout_request_id = response['CheckoutRequestID']
            db.session.commit()
            return jsonify({
                'success': True,
                'message': 'Payment initiated. Please check your phone to complete payment.',
                'checkout_request_id': response['CheckoutRequestID']
            })

        return jsonify({
            'success': False,
            'message': 'Failed to initiate payment. Please try again.'
        }), 500

    except Exception as e:
        print(f"Payment initiation error: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Failed to initiate payment: {str(e)}'
        }), 500


# Add this at the bottom of your file, just before app.run()
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default roles if they don't exist
        if not Role.query.filter_by(name='admin').first():
            db.session.add(Role(name='admin'))
        if not Role.query.filter_by(name='customer').first():
            db.session.add(Role(name='customer'))
        db.session.commit()

    # Check if ngrok is running and get the public URL
    try:
        ngrok_api_response = requests.get('http://localhost:4040/api/tunnels')
        tunnels = ngrok_api_response.json()['tunnels']
        NGROK_URL = [t['public_url'] for t in tunnels if t['public_url'].startswith('https')][0]
        print(f"\nNgrok tunnel established at: {NGROK_URL}")
    except Exception as e:
        print("\nError: Ngrok is not running. Please start ngrok first.")
        print("Follow these steps to set up ngrok:")
        print("1. Download ngrok from https://ngrok.com/download")
        print("2. Extract the downloaded file")
        print("3. Open a new terminal and navigate to the ngrok folder")
        print("4. Run: ngrok http 5000")
        sys.exit(1)

    app.run(debug=True)