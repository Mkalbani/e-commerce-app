from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv

app = Flask(__name__)
app.app_context().push()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

load_dotenv()
PWD = os.getenv('PWD')
admin_credentials = {
    "admin1": "password1",
    "user_admin": f"{PWD}",
}

# Generate a random secret key
secret_key = os.urandom(24)
app.secret_key = secret_key

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

# Helper function to create an admin user if it doesn't exist
# def create_admin_user():
#     existing_admin = AdminUser.query.filter_by(username='admin_user').first()
#     if not existing_admin:
#         admin_password = PWD
#         hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
#         admin_user = AdminUser(username='admin_user', password=hashed_password, is_admin=True, email='admin@example.com')
#         db.session.add(admin_user)
#         db.session.commit()
#         print("Admin user created successfully.")
#     else:
#         print("Admin user already exists.")

# # Call the create_admin_user function to create the admin user (comment this line after running it once)
# create_admin_user()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user is not None and user.is_admin:
        return user
    else:
        return None


# Define registration form
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

# Define login form
class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class AdminLoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

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


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
    return render_template('user-login.html', form=form, user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index', user=current_user))
    return render_template('register.html', form=form)

# Route: Home Page
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products, user=current_user)

# Route: Add Product (only for admin users)
@app.route('/admin/add_product', methods=['POST'])
@login_required
def add_product():
    if not current_user.is_admin:
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

# Route: Place Order
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

# Route: Checkout
@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if not current_user.is_authenticated:
        flash('You must be logged in to place an order.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'GET':
        # Display the checkout page
        return render_template('order_summary.html')
    else:
        # Process payment and update product stock levels (replace with actual code)
        # Send order confirmation email (replace with actual code)
        flash('Order placed successfully', 'success')
        return redirect(url_for('order_summary.html'))

# Route: Order Summary
@app.route('/order_summary')
def order_summary():
    return render_template('order_summary.html')

# Route: Admin Login
import os

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()

    admin_user = AdminUser.query.filter_by(username=form.username.data).first()

    admin_username = form.username.data
    admin_password = form.password.data

    if admin_username in admin_credentials and admin_password == admin_credentials[admin_username]:
        login_user(admin_user)
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid admin credentials.', 'danger')

    return render_template('admin-login.html', form=form)



# Route: Admin Dashboard (only for admin users)
@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("You do not have permission to access this page.", "danger")
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

    return render_template('admin_dashboard.html')

@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_product(product_id):
    if not current_user.is_admin:
        flash('Only admins can edit products', 'danger')
        return redirect(url_for('index'))

    product = Product.query.get(product_id)
    if product is None:
        flash('Product not found', 'danger')
        return redirect(url_for('admin_products'))

    form = Product(obj=product)
    if form.validate_on_submit():
        product.name = form.name.data
        product.description = form.description.data
        product.stock = form.stock.data
        product.price = form.price.data
        db.session.commit()
        flash('Product updated successfully', 'success')
        return redirect(url_for('admin_products'))

    return render_template('admin-edit-product.html', form=form, product=product)

@app.route('/admin/products/delete/<int:product_id>')
@login_required
def admin_delete_product(product_id):
    if not current_user.is_admin:
        flash('Only admins can delete products', 'danger')
        return redirect(url_for('index'))

    product = Product.query.get(product_id)
    if product is None:
        flash('Product not found', 'danger')
        return redirect(url_for('admin_products'))

    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    app.debug = True
    app.run
