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

UPLOAD_FOLDER = 'static/uploads'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
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
    return render_template('product_detail.html', product=product)


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


@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        flash('Please login to checkout.', 'warning')
        return redirect(url_for('login'))

    order = Order.query.filter_by(user_id=session['user_id'], status="Pending").first()
    if not order:
        flash('Your cart is empty.', 'info')
        return redirect(url_for('view_cart'))

    # Create payment record
    payment = Payment(
        order_id=order.id,
        payment_method="MPESA",
        payment_status="Pending"
    )
    db.session.add(payment)

    # Update order status
    order.status = "Processing"

    try:
        db.session.commit()
        flash('Order placed successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error processing order.', 'danger')
        print(f"Database error: {e}")

    return redirect(url_for('order_confirmation', order_id=order.id))


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


@app.route('/admin/manage_orders')
@admin_required
def manage_orders():
    orders = Order.query.all()
    return render_template('manage_orders.html', orders=orders)


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


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default roles if they don't exist
        if not Role.query.filter_by(name='admin').first():
            db.session.add(Role(name='admin'))
        if not Role.query.filter_by(name='customer').first():
            db.session.add(Role(name='customer'))
        db.session.commit()

    app.run(debug=True)