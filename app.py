from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email  # Import the Email validator
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.urls import url_decode
import os
from dotenv import load_dotenv



app = Flask(__name__)
app.app_context().push()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db' 
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

load_dotenv()
PWD= os.getenv('PWD')

# Generate a random secret key
secret_key = os.urandom(24)
app.secret_key = secret_key
PWD = 'poiqwe21'
# Define User and AdminUser models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class AdminUser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Flag to indicate admin status

def create_admin_user():
    # Check if an admin user with the desired username exists
    existing_admin = AdminUser.query.filter_by(username='admin_user').first()
    if not existing_admin:
        # Create a new admin user with the desired username and password
        admin_password = PWD 
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin_user = AdminUser(username='admin_user', password=hashed_password, is_admin=True)
        admin_user = AdminUser(username='admin_user', email='admin@example.com', password=hashed_password, is_admin=True)

        # Add the admin user to the database
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully.")
    else:
        print("Admin user already exists.")

# Call the create_admin_user function to create the admin user (comment this line after running it once)
# create_admin_user()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # Implement a function to load a user by their ID
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    email = StringField(validators=[
        InputRequired(), Email(message='Invalid email'), Length(max=100)], render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email address is already registered. Please use a different one.')

        
class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
    return render_template('user-login.html', form=form, user=current_user)  # Pass 'user' here

@app.route('/logout')
@login_required
def logout():
    logout_user()  # This logs the user out
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))  # Redirect to the home page or another appropriate page

@app.route('/register', methods=['GET', 'POST'])
def register():
  form = RegisterForm()

  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    new_user = User(username=form.username.data, email=form.email.data, password=hashed_password) # Include the email field
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('index', user=current_user))

  return render_template('register.html', form=form)

# Define Product and Order models
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    stock = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship('Product', backref=db.backref('orders', lazy=True))

# Routes

@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products, user=current_user)  # Pass 'user' here
#only admin can add product
@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    if not current_user.is_admin:  # Check if the current user is an admin
        flash('Only admins can add products', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        stock = request.form['stock']
        price = request.form['price']
        product = Product(name=name, description=description, stock=stock, price=price)
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully', 'success')
    return redirect(url_for('index'))

@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    if request.method == 'POST':
        product_id = request.form['product_id']
        quantity = request.form['quantity']
        product = Product.query.get(product_id)

        if product and product.stock >= int(quantity):
            order = Order(product_id=product_id, quantity=quantity)
            db.session.add(order)
            product.stock -= int(quantity)
            db.session.commit()
            flash('Order placed successfully', 'success')
        else:
            flash('Insufficient stock', 'danger')

    return redirect(url_for('index'))

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    # Ensure only authenticated users can place orders
    if not current_user.is_authenticated:
        flash('You must be logged in to place an order.', 'danger')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    # Create an order record in the database
    order = Order(user_id=current_user.id, items=current_user.cart_items)
    db.session.add(order)
    db.session.commit()

    # Process payment (if applicable) - Replace with payment processing code

    # Update product stock levels - Replace with code to adjust stock levels
    for item in current_user.cart_items:
        product = Product.query.get(item.product_id)
        if product:
            # Reduce the stock by the quantity ordered
            product.stock -= item.quantity
            db.session.commit()
    # Send order confirmation email - Replace with email sending code
    if current_user.email:
        mail = Mail(app)  # Initialize Flask-Mail with your app
        msg = Message('Order Confirmation', sender='your_email@example.com', recipients=[current_user.email])
        msg.body = 'Thank you for your order. Your order details: [insert order details here]'
        mail.send(msg)
    # Redirect the user to a success page or order summary
    flash('Order placed successfully', 'success')
    return redirect(url_for('order_summary'))

@app.route('/order_summary')
def order_summary():
    # Render the order summary page
    # Include code to display order details and any necessary information
    return render_template('order_summary.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()  # Use the same LoginForm class
    if form.validate_on_submit():
        admin_user = AdminUser.query.filter_by(username=form.username.data).first()
        if admin_user:
            if bcrypt.check_password_hash(admin_user.password, form.password.data):
                login_user(admin_user)
                return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard
    return render_template('admin-login.html', form=form, user=current_user)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required  # Require authentication for the admin dashboard
def admin_dashboard():
    if not current_user.is_admin:
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('index'))  # Redirect to a suitable page

    if request.method == 'POST':
        # Handle the form submission to add a new product
        name = request.form['name']
        description = request.form['description']
        stock = request.form['stock']
        price = request.form['price']
        product = Product(name=name, description=description, stock=stock, price=price)
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully', 'success')

    # Implement admin dashboard logic here
    # You can render a template or handle admin actions here
    return render_template('admin_dashboard.html')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
