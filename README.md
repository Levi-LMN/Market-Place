# LevisStore - E-commerce Platform

LevisStore is a comprehensive e-commerce platform built with Flask, allowing store administrators to manage products, categories, and orders while providing customers with a seamless shopping experience.

## Features

### Customer Features
- **User Authentication**: Register and login to access personalized features
- **Product Browsing**: View products by category with detailed product pages
- **Shopping Cart**: Add items to cart, adjust quantities, and remove items
- **Checkout Process**: Secure checkout with M-PESA integration for payments
- **Order History**: Track order status and view past purchases

### Admin Features
- **Product Management**: Add, edit, and delete products with image uploads
- **Category Management**: Create and manage product categories
- **Order Management**: Process orders with status updates
- **User Management**: Manage user accounts and roles
- **Dashboard**: Overview of sales and inventory (future enhancement)

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy with SQLite
- **Payment Integration**: M-PESA API
- **Frontend**: HTML, CSS, JavaScript
- **Authentication**: Flask-based session management with password hashing

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/levishub.git
   cd levishub
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install flask flask-sqlalchemy flask-wtf werkzeug requests
   ```

4. Create the database:
   ```
   python
   >>> from app import app, db
   >>> with app.app_context():
   >>>     db.create_all()
   >>> exit()
   ```

5. Run the application:
   ```
   python app.py
   ```

6. Access the application in your browser at `http://127.0.0.1:5000`

## Configuration

### M-PESA Integration

Update the M-PESA credentials in the `MpesaC2bCredential` class:
```python
class MpesaC2bCredential:
    consumer_key = 'your_consumer_key'
    consumer_secret = 'your_consumer_secret'
    api_URL = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
```

### Application Configuration

Update the following configuration values in `app.py`:
```python
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'  # or your preferred database
SITE_URL = 'your_site_url'  # For callback URLs
```

## Directory Structure

- `/static`: Static files (CSS, JavaScript, uploaded images)
- `/templates`: HTML templates
- `/static/uploads`: Product image uploads 

## Initial Setup

The application automatically creates 'admin' and 'customer' roles on startup. To create an admin account, register with the email `admin@levisstore.com`.

## Development

### Adding Custom Categories

1. Log in as an admin
2. Navigate to the admin panel
3. Select 'Manage Categories'
4. Add new categories as needed

### Adding Products

1. Log in as an admin
2. Navigate to the admin panel
3. Select 'Manage Products'
4. Add new products, including images and category assignment

## Payment System

The application uses M-PESA for payments with the following workflow:
1. Customer initiates checkout
2. STK push notification is sent to the customer's phone
3. Customer completes payment on their device
4. Payment status is verified via callback or status check
5. Order status is updated upon successful payment

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your branch
5. Create a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask and SQLAlchemy communities
- Safaricom for M-PESA API documentation
