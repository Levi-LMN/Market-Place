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
import sys

# Add these imports if not already present
from datetime import datetime, timedelta
import threading
import time

UPLOAD_FOLDER = 'static/uploads'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
SITE_URL = 'https://levishub.pythonanywhere.com'
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



# Update the Order model relationship with Payment
class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Pending')
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    order_items = db.relationship('OrderItem', backref='order', lazy=True)
    # Modified relationship to ensure one-to-one
    payment = db.relationship('Payment', backref='order', uselist=False, cascade="all, delete-orphan")


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
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False, unique=True)  # Added unique constraint
    payment_method = db.Column(db.String(50), nullable=False, default="MPESA")
    payment_status = db.Column(db.String(50), nullable=False)
    mpesa_transaction_id = db.Column(db.String(100), nullable=True, unique=True)  # Added unique constraint
    checkout_request_id = db.Column(db.String(100), nullable=True, unique=True)  # Added unique constraint
    phone_number = db.Column(db.String(15), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())  # Added timestamp
    updated_at = db.Column(db.DateTime, onupdate=db.func.current_timestamp())  # Added update timestamp


# Add the Category model after your existing models
class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(500))
    products = db.relationship('Product', backref='category', lazy=True)


# Update the Product model to include category
class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    price = db.Column(db.Float, nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    order_items = db.relationship('OrderItem', backref='product', lazy=True)
    images = db.relationship('ProductImage', backref='product', lazy=True)


# Add CategoryForm for managing categories
class CategoryForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description')
    submit = SubmitField('Submit')


# Update ProductForm to include category selection
class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    price = StringField('Price', validators=[DataRequired()])
    stock_quantity = StringField('Stock Quantity', validators=[DataRequired()])
    # Using coerce=int to ensure category ID is handled as integer
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    images = FileField('Images', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Submit')

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
    # Get all categories for the browse section
    categories = Category.query.all()

    # Get featured products (for this example, we'll get the 8 most recent products)
    products = Product.query.order_by(Product.id.desc()).limit(8).all()

    # Add flags for new and discounted products
    for product in products:
        # Mark products as new if they have an id in the latest 20% of all products
        total_products = Product.query.count()
        new_threshold = int(total_products * 0.8)  # Latest 20% are considered new
        product.is_new = product.id > new_threshold

        # Check if product has a discount by comparing current price with original price
        # This assumes you add an original_price field to your Product model
        # For now, we'll set discount flag to False as original_price isn't in the model
        product.discount = False

        # If you want to add original_price to your model, add this to your Product class:
        # original_price = db.Column(db.Float, nullable=True)
        # Then you can uncomment this logic:
        # product.discount = product.original_price and product.original_price > product.price

    return render_template('home.html',
                           categories=categories,
                           products=products)



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
    # Get category filter from query parameters
    category_id = request.args.get('category_id', type=int)
    selected_category = None

    # Query products based on category
    if category_id:
        selected_category = Category.query.get_or_404(category_id)
        products = Product.query.filter_by(category_id=category_id).all()
    else:
        products = Product.query.all()

    # Get all categories for the navigation
    categories = Category.query.all()

    return render_template('products.html',
                           products=products,
                           categories=categories,
                           selected_category=selected_category)

# Update the product_detail route to include category information
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)

    existing_order_item = None
    if 'user_id' in session:
        order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
        if order:
            existing_order_item = OrderItem.query.filter_by(order_id=order.id, product_id=product_id).first()

    # Convert product images to a JSON-serializable format
    serialized_images = [{"image_url": image.image_url} for image in product.images]

    return render_template(
        'product_detail.html',
        product=product,
        existing_order_item=existing_order_item,
        images=serialized_images
    )



# Add these new routes for category management
@app.route('/admin/categories')
@admin_required
def manage_categories():
    categories = Category.query.all()
    return render_template('manage_categories.html', categories=categories)


@app.route('/admin/add_category', methods=['GET', 'POST'])
@admin_required
def add_category():
    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(
            name=form.name.data,
            description=form.description.data
        )
        try:
            db.session.add(category)
            db.session.commit()
            flash('Category added successfully!', 'success')
            return redirect(url_for('manage_categories'))
        except IntegrityError:
            db.session.rollback()
            flash('Category name already exists.', 'danger')
    return render_template('add_category.html', form=form)


@app.route('/admin/edit_category/<int:category_id>', methods=['GET', 'POST'])
@admin_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    form = CategoryForm(obj=category)
    if form.validate_on_submit():
        category.name = form.name.data
        category.description = form.description.data
        try:
            db.session.commit()
            flash('Category updated successfully!', 'success')
            return redirect(url_for('manage_categories'))
        except IntegrityError:
            db.session.rollback()
            flash('Category name already exists.', 'danger')
    return render_template('edit_category.html', form=form, category=category)


@app.route('/admin/delete_category/<int:category_id>', methods=['POST'])
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.products:
        flash('Cannot delete category with associated products.', 'danger')
    else:
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted successfully!', 'success')
    return redirect(url_for('manage_categories'))


@app.route('/admin/add_product', methods=['GET', 'POST'])
@admin_required
def add_product():
    form = ProductForm()
    form.category.choices = [(c.id, c.name) for c in Category.query.all()]

    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            description=form.description.data,
            price=float(form.price.data),
            stock_quantity=int(form.stock_quantity.data),
            category_id=form.category.data
        )
        db.session.add(product)
        db.session.commit()

        # Handling multiple images
        if form.images.data:
            for image in request.files.getlist('images'):
                filename = secure_filename(image.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Ensure the directory exists before saving
                os.makedirs(os.path.dirname(image_path), exist_ok=True)

                # Save the image
                image.save(image_path)

                # Create a new ProductImage entry for each image
                product_image = ProductImage(
                    product_id=product.id,
                    image_url=filename
                )
                db.session.add(product_image)

            db.session.commit()

        flash('Product added successfully!', 'success')
        return redirect(url_for('manage_products'))

    return render_template('add_product.html', form=form)


@app.route('/product/<int:product_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    # Get the product and all categories
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()

    # Initialize form
    form = ProductForm()

    # Set the category choices
    form.category.choices = [(cat.id, cat.name) for cat in categories]

    if request.method == 'GET':
        # Pre-populate the form with existing data
        form.name.data = product.name
        form.description.data = product.description
        form.price.data = str(product.price)
        form.stock_quantity.data = str(product.stock_quantity)
        form.category.data = product.category_id

    if form.validate_on_submit():
        try:
            # Update product fields
            product.name = form.name.data
            product.description = form.description.data
            product.price = float(form.price.data)
            product.stock_quantity = int(form.stock_quantity.data)

            # Get the selected category and update the relationship
            selected_category = Category.query.get(form.category.data)
            if selected_category is None:
                flash('Selected category does not exist.', 'danger')
                return redirect(url_for('edit_product', product_id=product_id))

            product.category_id = selected_category.id

            # Handle image deletion
            if 'delete_images' in request.form:
                for image_id in request.form.getlist('delete_images'):
                    image = ProductImage.query.get(int(image_id))
                    if image and image.product_id == product.id:  # Security check
                        try:
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], image.image_url)
                            if os.path.exists(file_path):
                                os.remove(file_path)
                            db.session.delete(image)
                        except Exception as e:
                            print(f"Error deleting image: {e}")

            # Handle new image uploads
            if form.images.data:
                for image in request.files.getlist('images'):
                    if image.filename:
                        filename = secure_filename(image.filename)
                        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        os.makedirs(os.path.dirname(image_path), exist_ok=True)
                        image.save(image_path)

                        product_image = ProductImage(
                            product_id=product.id,
                            image_url=filename
                        )
                        db.session.add(product_image)

            # Commit all changes
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('manage_products'))

        except Exception as e:
            db.session.rollback()
            flash('Error updating product.', 'danger')
            print(f"Database error: {e}")

    # Pass both form and product to template
    return render_template('edit_product.html', form=form, product=product)

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    try:
        product = Product.query.get_or_404(product_id)

        # First delete all associated product images
        for image in product.images:
            try:
                # Delete physical image file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], image.image_url)
                if os.path.exists(file_path):
                    os.remove(file_path)

                # Delete image record from database
                db.session.delete(image)
            except Exception as e:
                print(f"Error deleting image {image.id}: {e}")
                # Continue with other images even if one fails
                continue

        # Delete any order items associated with this product
        OrderItem.query.filter_by(product_id=product_id).delete()

        # Finally delete the product
        db.session.delete(product)
        db.session.commit()

        flash('Product and all associated images deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting product {product_id}: {e}")
        flash('Error deleting product. Please try again.', 'danger')

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

from datetime import datetime


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

    # Apply start date filter if valid
    if start_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Order.created_at >= start_date)
        except ValueError:
            # Invalid date format, handle the error or log it
            flash("Invalid start date format. Please use YYYY-MM-DD.", "danger")

    # Apply end date filter if valid
    if end_date:
        try:
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
            query = query.filter(Order.created_at <= end_date)
        except ValueError:
            # Invalid date format, handle the error or log it
            flash("Invalid end date format. Please use YYYY-MM-DD.", "danger")

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


# Add a new function to continuously check pending payments
def check_pending_payments():
    while True:
        with app.app_context():
            try:
                # Get all pending payments from last 24 hours
                cutoff_time = datetime.now() - timedelta(hours=24)
                pending_payments = Payment.query.filter(
                    Payment.payment_status == "Pending",
                    Payment.created_at >= cutoff_time
                ).all()

                for payment in pending_payments:
                    if payment.checkout_request_id:
                        mpesa_status = check_mpesa_status(payment.checkout_request_id)

                        if mpesa_status.get('ResultCode') == 0:
                            # Payment successful
                            payment.payment_status = "Completed"
                            payment.mpesa_transaction_id = mpesa_status.get('MpesaReceiptNumber')

                            # Update order status
                            order = Order.query.get(payment.order_id)
                            if order:
                                order.status = "Processing"

                            db.session.commit()
                            print(f"Payment {payment.id} completed successfully")

                        elif mpesa_status.get('ResultCode') is not None:
                            # Payment failed
                            payment.payment_status = "Failed"
                            db.session.commit()
                            print(f"Payment {payment.id} failed")

            except Exception as e:
                print(f"Error checking pending payments: {str(e)}")

            # Wait for 30 seconds before next check
            time.sleep(30)


@app.route('/check_payment_status/<checkout_request_id>')
def check_payment_status(checkout_request_id):
    try:
        payment = Payment.query.filter_by(checkout_request_id=checkout_request_id).first()
        if not payment:
            return jsonify({
                'status': 'Failed',
                'message': 'Payment not found'
            }), 404

        if payment.payment_status == "Completed" and payment.mpesa_transaction_id:
            # Clear cart if payment is completed
            order = Order.query.get(payment.order_id)
            if order and order.status == "Pending":
                order.status = "Processing"

                # Create a new empty cart order for the user
                new_cart = Order(
                    user_id=order.user_id,
                    total_price=0,
                    status="Pending"
                )
                db.session.add(new_cart)
                db.session.commit()

            return jsonify({
                'status': 'Completed',
                'order_id': payment.order_id,
                'transaction_id': payment.mpesa_transaction_id
            })

        if payment.payment_status == "Failed":
            return jsonify({
                'status': 'Failed',
                'message': 'Payment failed. Please try again.'
            })

        # For pending payments, check M-Pesa status
        mpesa_status = check_mpesa_status(payment.checkout_request_id)

        if mpesa_status.get('ResultCode') == 0:
            payment.payment_status = "Completed"
            payment.mpesa_transaction_id = mpesa_status.get('MpesaReceiptNumber')

            # Update order status and clear cart
            order = Order.query.get(payment.order_id)
            if order:
                order.status = "Processing"

                # Create a new empty cart order for the user
                new_cart = Order(
                    user_id=order.user_id,
                    total_price=0,
                    status="Pending"
                )
                db.session.add(new_cart)

            db.session.commit()

            return jsonify({
                'status': 'Completed',
                'order_id': payment.order_id,
                'transaction_id': payment.mpesa_transaction_id
            })

        return jsonify({
            'status': 'Pending',
            'message': 'Payment is being processed'
        })

    except Exception as e:
        print(f"Error checking payment status: {str(e)}")
        return jsonify({
            'status': 'Error',
            'message': str(e)
        }), 500


@app.route('/mpesa_callback', methods=['POST'])
def mpesa_callback():
    try:
        callback_data = request.get_json()
        body = callback_data.get('Body', {})
        stk_callback = body.get('stkCallback', {})

        checkout_request_id = stk_callback.get('CheckoutRequestID')
        result_code = stk_callback.get('ResultCode')

        payment = Payment.query.filter_by(checkout_request_id=checkout_request_id).first()
        if not payment:
            print(f"No payment found for checkout_request_id: {checkout_request_id}")
            return jsonify({'error': 'Payment not found'}), 404

        if result_code == 0:
            callback_metadata = stk_callback.get('CallbackMetadata', {})
            items = callback_metadata.get('Item', [])

            mpesa_receipt_number = None
            for item in items:
                if item.get('Name') == 'MpesaReceiptNumber':
                    mpesa_receipt_number = str(item.get('Value'))
                    break

            if mpesa_receipt_number:
                payment.payment_status = "Completed"
                payment.mpesa_transaction_id = mpesa_receipt_number

                # Update order status and clear cart
                order = Order.query.get(payment.order_id)
                if order and order.status == "Pending":
                    order.status = "Processing"

                    # Create a new empty cart order for the user
                    new_cart = Order(
                        user_id=order.user_id,
                        total_price=0,
                        status="Pending"
                    )
                    db.session.add(new_cart)

                db.session.commit()
                print(f"Payment updated with transaction ID: {mpesa_receipt_number}")

        else:
            payment.payment_status = "Failed"
            db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        print(f"Error in callback: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/initiate_payment', methods=['POST'])
def initiate_payment():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Please login to checkout'}), 401

        order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
        if not order:
            return jsonify({'error': 'No pending order found'}), 404

        # Check if payment already exists
        if order.payment:
            if order.payment.payment_status == "Pending":
                return jsonify({
                    'success': True,
                    'message': 'Payment already initiated. Please check your phone.',
                    'checkout_request_id': order.payment.checkout_request_id
                })
            db.session.delete(order.payment)
            db.session.commit()

        phone_number = request.form.get('phone_number', '').strip()
        if not phone_number:
            return jsonify({'error': 'Phone number is required'}), 400

        # Format phone number
        if phone_number.startswith('+'):
            phone_number = phone_number[1:]
        elif phone_number.startswith('0'):
            phone_number = '254' + phone_number[1:]
        elif not phone_number.startswith('254'):
            phone_number = '254' + phone_number

        if not phone_number.isdigit() or len(phone_number) != 12:
            return jsonify({'error': 'Invalid phone number format'}), 400

        amount = int(order.total_price)

        payment = Payment(
            order_id=order.id,
            payment_method="MPESA",
            payment_status="Pending",
            phone_number=phone_number
        )
        db.session.add(payment)
        db.session.commit()

        try:
            mpesa = LipaNaMpesaOnline()
            # Use PythonAnywhere URL for callback
            callback_url = f"{SITE_URL}/mpesa_callback"
            print(f"Initiating payment for order {order.id} with callback URL: {callback_url}")

            response = mpesa.initiate_stk_push(phone_number, amount, callback_url)
            print(f"M-Pesa API Response: {response}")

            if 'CheckoutRequestID' in response:
                payment.checkout_request_id = response['CheckoutRequestID']
                db.session.commit()
                return jsonify({
                    'success': True,
                    'message': 'Payment initiated. Please check your phone.',
                    'checkout_request_id': response['CheckoutRequestID']
                })

            raise Exception("No CheckoutRequestID in M-Pesa response")

        except Exception as e:
            db.session.delete(payment)
            db.session.commit()
            raise

    except Exception as e:
        print(f"Payment initiation error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Payment initiation failed: {str(e)}'
        }), 500



# Add this new route to your Flask application
@app.route('/update_quantity/<int:order_item_id>', methods=['POST'])
def update_quantity(order_item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Please login to update cart'}), 401

    try:
        data = request.get_json()
        new_quantity = int(data.get('quantity', 0))

        if new_quantity < 1:
            return jsonify({'error': 'Invalid quantity'}), 400

        order_item = OrderItem.query.get_or_404(order_item_id)

        # Verify the order belongs to the current user
        if order_item.order.user_id != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403

        # Calculate quantity difference
        quantity_diff = new_quantity - order_item.quantity

        # Check if enough stock is available
        if quantity_diff > 0:
            product = Product.query.get(order_item.product_id)
            if product.stock_quantity < quantity_diff:
                return jsonify({
                    'error': 'Not enough stock available',
                    'available_stock': product.stock_quantity
                }), 400

        # Update product stock
        product = Product.query.get(order_item.product_id)
        product.stock_quantity -= quantity_diff

        # Update order item quantity
        order_item.quantity = new_quantity

        # Update order total price
        order = Order.query.get(order_item.order_id)
        order.total_price = sum(item.quantity * item.price_at_time for item in order.order_items)

        db.session.commit()

        return jsonify({
            'success': True,
            'new_quantity': new_quantity,
            'item_subtotal': order_item.quantity * order_item.price_at_time,
            'cart_total': order.total_price
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Add these new routes to your Flask application

@app.route('/buy_now/<int:product_id>', methods=['POST'])
def buy_now(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Please login to proceed'}), 401

    try:
        quantity = int(request.form.get('quantity', 1))
        product = Product.query.get_or_404(product_id)

        # Check stock availability
        if quantity > product.stock_quantity:
            return jsonify({
                'error': 'Not enough stock available',
                'available_stock': product.stock_quantity
            }), 400

        # Create a new order specifically for buy now
        buy_now_order = Order(
            user_id=session['user_id'],
            total_price=product.price * quantity,
            status="BuyNow"  # Special status to distinguish from cart orders
        )
        db.session.add(buy_now_order)
        db.session.flush()  # Get the order ID without committing

        # Create order item
        order_item = OrderItem(
            order_id=buy_now_order.id,
            product_id=product_id,
            quantity=quantity,
            price_at_time=product.price
        )
        db.session.add(order_item)

        # Temporarily reduce stock
        product.stock_quantity -= quantity

        db.session.commit()

        return jsonify({
            'success': True,
            'redirect_url': url_for('buy_now_checkout', order_id=buy_now_order.id)
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/buy_now_checkout/<int:order_id>')
def buy_now_checkout(order_id):
    if 'user_id' not in session:
        flash('Please login to checkout.', 'warning')
        return redirect(url_for('login'))

    order = Order.query.filter_by(
        id=order_id,
        user_id=session['user_id'],
        status="BuyNow"
    ).first_or_404()

    # Get user's phone number for pre-filling
    user = User.query.get(session['user_id'])

    return render_template(
        'buy_now_checkout.html',
        order=order,
        user_phone=user.phone_number
    )


@app.route('/cancel_buy_now/<int:order_id>', methods=['POST'])
def cancel_buy_now(order_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    order = Order.query.filter_by(
        id=order_id,
        user_id=session['user_id'],
        status="BuyNow"
    ).first_or_404()

    try:
        # Restore product stock
        for item in order.order_items:
            product = Product.query.get(item.product_id)
            product.stock_quantity += item.quantity

        # Delete the order
        db.session.delete(order)
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Start the payment checker in a background thread
        payment_checker = threading.Thread(target=check_pending_payments, daemon=True)
        payment_checker.start()
        # Create default roles if they don't exist
        if not Role.query.filter_by(name='admin').first():
            db.session.add(Role(name='admin'))
        if not Role.query.filter_by(name='customer').first():
            db.session.add(Role(name='customer'))
        db.session.commit()

    app.run(debug=True)  # Set debug to False for production