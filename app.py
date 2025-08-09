import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import quote
from datetime import datetime, time, date, timedelta
import socket
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from math import radians, sin, cos, sqrt, atan2
from flask_wtf.file import FileField
from flask_migrate import Migrate
from sqlalchemy import func

# --- 1. CONFIGURAÇÃO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Usa o banco de dados online (PostgreSQL no Render)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace("://", "ql://", 1)
else:
    # Continua usando o banco de dados local (SQLite) para desenvolvimento
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///delivery.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = os.path.join(app.root_path, 'static/uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'customer_login'
login_manager.login_message = "Você precisa fazer login para acessar esta página."
login_manager.login_message_category = "warning"


# --- 2. MODELOS DO BANCO DE DADOS ---

restaurant_tags = db.Table('restaurant_tags',
    db.Column('restaurant_id', db.Integer, db.ForeignKey('restaurant.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

user_favorites = db.Table('user_favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('restaurant_id', db.Integer, db.ForeignKey('restaurant.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='customer')
    restaurant = db.relationship('Restaurant', backref='owner', uselist=False, cascade="all, delete-orphan")
    orders = db.relationship('Order', backref='customer', lazy=True)
    reviews = db.relationship('Review', backref='reviewer', lazy=True)
    favorited_restaurants = db.relationship('Restaurant', secondary=user_favorites, back_populates='favorited_by')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    whatsapp = db.Column(db.String(20), nullable=True)
    deliveryFee = db.Column(db.Float)
    category = db.Column(db.String(50))
    description = db.Column(db.String(200))
    address = db.Column(db.String(250), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    menu_items = db.relationship('MenuItem', backref='restaurant', lazy=True, cascade="all, delete-orphan")
    logo_filename = db.Column(db.String(100), nullable=True)
    banner_filename = db.Column(db.String(100), nullable=True)
    orders = db.relationship('Order', backref='restaurant', lazy=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    is_featured = db.Column(db.Boolean, default=False, nullable=False)
    is_approved = db.Column(db.Boolean, default=True, nullable=False)
    theme = db.Column(db.String(50), default='moderno', nullable=False)
    operating_hours = db.relationship('OperatingHours', backref='restaurant', lazy=True, cascade="all, delete-orphan")
    tags = db.relationship('Tag', secondary=restaurant_tags, lazy=True, backref=db.backref('restaurants', lazy=True))
    reviews = db.relationship('Review', backref='reviewed_restaurant', lazy=True)
    favorited_by = db.relationship('User', secondary=user_favorites, back_populates='favorited_restaurants')
    
    @property
    def average_rating(self):
        avg = db.session.query(func.avg(Review.rating)).filter(Review.restaurant_id == self.id).scalar()
        return round(avg, 1) if avg else 0

    @property
    def review_count(self):
        return Review.query.filter(Review.restaurant_id == self.id).count()

class OperatingHours(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    day_of_week = db.Column(db.Integer, nullable=False)
    open_time = db.Column(db.Time, nullable=True)
    close_time = db.Column(db.Time, nullable=True)
    is_closed = db.Column(db.Boolean, default=False, nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    icon_filename = db.Column(db.String(100), nullable=True)
    def __repr__(self):
        return self.name

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    image_filename = db.Column(db.String(100), nullable=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Pedido enviado')
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)

    def __repr__(self):
        return f'<Review {self.rating}/5 for Restaurant {self.restaurant_id}>'

# --- 3. CONFIGURAÇÃO DO SUPER ADMIN ---
class AdminModelView(ModelView):
    column_labels = {
        'name': 'NOME', 'email': 'E-MAIL', 'role': 'FUNÇÃO', 'price': 'PREÇO',
        'description': 'DESCRIÇÃO', 'category': 'CATEGORIA', 'is_approved': 'APROVADO',
        'is_featured': 'EM DESTAQUE', 'rating': 'NOTA', 'comment': 'COMENTÁRIO',
        'timestamp': 'DATA', 'customer': 'CLIENTE', 'restaurant': 'RESTAURANTE',
        'product_name': 'PRODUTO', 'quantity': 'QTD', 'total_price': 'PREÇO TOTAL',
        'icon_filename': 'ÍCONE', 'logo_filename': 'LOGO', 'banner_filename': 'BANNER',
        'deliveryFee': 'TAXA DE ENTREGA', 'whatsapp': 'WHATSAPP', 'address': 'ENDEREÇO'
    }
    column_exclude_list = ['password_hash',]
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'
    def inaccessible_callback(self, name, **kwargs):
        flash('Você precisa ser um administrador para acessar esta página.', 'danger')
        return redirect(url_for('home'))

class RestaurantAdminView(AdminModelView):
    column_editable_list = ['is_approved', 'is_featured']

class TagAdminView(AdminModelView):
    form_extra_fields = {
        'icon': FileField('Ícone da Categoria (imagem quadrada, ex: 60x60)')
    }
    def on_model_change(self, form, model, is_created):
        file_data = form.icon.data
        if file_data:
            filename = secure_filename(f"tag_{datetime.now().timestamp()}_{file_data.filename}")
            file_data.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            model.icon_filename = filename

admin = Admin(app, name='GERENCIADOR DE DADOS', template_mode='bootstrap4', index_view=AdminIndexView(name='HOME', url='/admin'))
admin.add_view(AdminModelView(User, db.session, name="USUÁRIOS"))
admin.add_view(RestaurantAdminView(Restaurant, db.session, name="RESTAURANTES"))
admin.add_view(AdminModelView(MenuItem, db.session, name="ITENS DO CARDÁPIO"))
admin.add_view(AdminModelView(Order, db.session, name="PEDIDOS"))
admin.add_view(AdminModelView(OrderItem, db.session, name="ITENS DOS PEDIDOS"))
admin.add_view(TagAdminView(Tag, db.session, name="CATEGORIAS"))
admin.add_view(AdminModelView(Review, db.session, name="AVALIAÇÕES"))


# --- 4. FUNÇÕES GERAIS ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dLat = radians(lat2 - lat1)
    dLon = radians(lon2 - lon1)
    lat1, lat2 = radians(lat1), radians(lat2)
    a = sin(dLat / 2)**2 + cos(lat1) * cos(lat2) * sin(dLon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c

def is_restaurant_open(restaurant):
    now = datetime.now()
    weekday, current_time = now.weekday(), now.time()
    hours_today = next((h for h in restaurant.operating_hours if h.day_of_week == weekday), None)
    if not hours_today or hours_today.is_closed or not hours_today.open_time or not hours_today.close_time:
        return False
    if hours_today.open_time > hours_today.close_time:
        return current_time >= hours_today.open_time or current_time <= hours_today.close_time
    return hours_today.open_time <= current_time <= hours_today.close_time

@app.before_request
def setup_session():
    session.setdefault('cart', [])

@app.context_processor
def inject_utility_functions():
    favorited_ids = []
    if current_user.is_authenticated and current_user.role == 'customer':
        favorited_ids = [r.id for r in current_user.favorited_restaurants]
    
    return {
        'is_restaurant_open': is_restaurant_open,
        'cart_count': sum(item['quantity'] for item in session.get('cart', [])),
        'favorited_ids': favorited_ids,
        'now': datetime.utcnow()
    }

# --- 5. ROTAS PÚBLICAS ---
@app.route('/')
def home():
    selected_category_name = request.args.get('category')
    all_categories = Tag.query.order_by(Tag.name).all()
    restaurants_query = Restaurant.query.filter_by(is_approved=True)
    if selected_category_name:
        category = Tag.query.filter_by(name=selected_category_name).first()
        if category:
            restaurants_query = restaurants_query.filter(Restaurant.tags.contains(category))
    featured_restaurants = restaurants_query.filter_by(is_featured=True).all()
    restaurants = restaurants_query.filter_by(is_featured=False).all()
    user_lat, user_lon = request.args.get('lat', type=float), request.args.get('lon', type=float)
    if user_lat and user_lon:
        for r in restaurants:
            r.distance = haversine(user_lat, user_lon, r.latitude, r.longitude) if r.latitude and r.longitude else 99999
        restaurants.sort(key=lambda x: x.distance)
    return render_template('home.html', 
                           featured_restaurants=featured_restaurants, 
                           restaurants=restaurants,
                           all_categories=all_categories,
                           selected_category_name=selected_category_name)

@app.route('/menu/<int:restaurant_id>')
def menu(restaurant_id):
    restaurant = Restaurant.query.filter_by(id=restaurant_id, is_approved=True).first_or_404()
    return render_template('menu.html', restaurant=restaurant)

@app.route('/seja-parceiro')
def partner_landing():
    return render_template('partner_landing.html')

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '')
    if len(query) < 2:
        return jsonify({'restaurants': [], 'items': []})
    search_term = f"%{query}%"
    found_restaurants = Restaurant.query.filter(Restaurant.name.ilike(search_term), Restaurant.is_approved==True).limit(5).all()
    found_items = MenuItem.query.filter(MenuItem.name.ilike(search_term)).join(Restaurant).filter(Restaurant.is_approved==True).limit(10).all()
    restaurants_list = [{'id': r.id, 'name': r.name, 'logo': url_for('static', filename='uploads/' + r.logo_filename if r.logo_filename else 'images/default_logo.png'), 'average_rating': r.average_rating} for r in found_restaurants]
    items_list = [{'id': i.id, 'name': i.name, 'price': "%.2f"|format(i.price|float), 'restaurant_id': i.restaurant.id, 'restaurant_name': i.restaurant.name} for i in found_items]
    return jsonify({'restaurants': restaurants_list, 'items': items_list})


# --- 6. ROTAS DE AUTENTICAÇÃO ---
@app.route('/cliente/cadastro', methods=['GET', 'POST'])
def customer_register():
    if request.method == 'POST':
        email, name, password = request.form.get('email'), request.form.get('name'), request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash('Este e-mail já está cadastrado. Tente fazer login.', 'warning')
            return redirect(url_for('customer_login'))
        new_customer = User(email=email, name=name, role='customer')
        new_customer.set_password(password)
        db.session.add(new_customer)
        db.session.commit()
        login_user(new_customer)
        return redirect(url_for('checkout'))
    return render_template('customer_register.html')

@app.route('/cliente/login', methods=['GET', 'POST'])
def customer_login():
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        user = User.query.filter_by(email=email, role='customer').first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(request.args.get('next') or url_for('home'))
        else:
            flash('E-mail ou senha de cliente inválidos.', 'danger')
    return render_template('customer_login.html')

@app.route('/parceiro/cadastro', methods=['GET', 'POST'])
def owner_register():
    if request.method == 'POST':
        name, email, password, restaurant_name = request.form.get('name'), request.form.get('email'), request.form.get('password'), request.form.get('restaurant_name')
        if User.query.filter_by(email=email).first():
            flash('Este e-mail já está em uso.', 'warning')
            return redirect(url_for('owner_register'))
        new_owner = User(email=email, name=name, role='owner')
        new_owner.set_password(password)
        new_restaurant = Restaurant(name=restaurant_name, owner=new_owner)
        db.session.add(new_owner)
        db.session.add(new_restaurant)
        db.session.commit()
        flash('Parabéns! Seu cadastro foi realizado com sucesso. Faça o login para começar.', 'success')
        return redirect(url_for('owner_login'))
    return render_template('owner_register.html')

@app.route('/parceiro/login', methods=['GET', 'POST'])
def owner_login():
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password) and (user.role in ['owner', 'admin']):
            login_user(user)
            return redirect(url_for('admin_dashboard') if user.role == 'admin' else url_for('dashboard'))
        else:
            flash('E-mail, senha ou permissão de parceiro inválidos.', 'danger')
    return render_template('owner_login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('home'))

@login_manager.unauthorized_handler
def unauthorized():
    if request.endpoint and (request.endpoint.startswith('dashboard') or request.endpoint.startswith('superadmin')):
        return redirect(url_for('owner_login'))
    return redirect(url_for('customer_login', next=request.url))

# --- 7. ROTAS DOS DASHBOARDS E GERENCIAMENTO ---
@app.route('/superadmin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Acesso negado.", "danger")
        return redirect(url_for('home'))
    total_customers = User.query.filter_by(role='customer').count()
    total_owners = User.query.filter_by(role='owner').count()
    total_orders = Order.query.count()
    top_restaurants_query = db.session.query(
        Restaurant.name, 
        db.func.count(Order.id).label('total_orders')
    ).join(Order, Restaurant.id == Order.restaurant_id).group_by(Restaurant.name).order_by(db.desc('total_orders')).limit(5).all()
    chart_labels = [r.name for r in top_restaurants_query]
    chart_data = [r.total_orders for r in top_restaurants_query]
    return render_template('admin/dashboard.html',
                           total_customers=total_customers,
                           total_owners=total_owners,
                           total_orders=total_orders,
                           chart_labels=chart_labels,
                           chart_data=chart_data)

@app.route('/superadmin/users')
@login_required
def admin_user_list():
    if current_user.role != 'admin': return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin/user_list.html', users=users)

@app.route('/superadmin/users/create', methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if current_user.role != 'admin': return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        if User.query.filter_by(email=email).first():
            flash('Este e-mail já está em uso.', 'danger')
        else:
            new_user = User(name=request.form.get('name'), email=email, role=request.form.get('role'))
            password = request.form.get('password')
            if password:
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('Usuário criado com sucesso!', 'success')
                return redirect(url_for('admin_user_list'))
            else:
                flash('Senha é obrigatória para novos usuários.', 'danger')
    return render_template('admin/user_form.html', title="Criar Novo Usuário", user=None)

@app.route('/superadmin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'admin': return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        password = request.form.get('password')
        if password:
            user.set_password(password)
        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('admin_user_list'))
    return render_template('admin/user_form.html', user=user, title="Editar Usuário")

@app.route('/superadmin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin': return redirect(url_for('home'))
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash('Você não pode apagar a si mesmo.', 'danger')
        return redirect(url_for('admin_user_list'))
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('Usuário apagado com sucesso!', 'success')
    return redirect(url_for('admin_user_list'))

@app.route('/superadmin/restaurants')
@login_required
def admin_restaurant_list():
    if current_user.role != 'admin': return redirect(url_for('home'))
    restaurants = Restaurant.query.all()
    return render_template('admin/restaurant_list.html', restaurants=restaurants)

@app.route('/superadmin/restaurants/edit/<int:restaurant_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_restaurant(restaurant_id):
    if current_user.role != 'admin': return redirect(url_for('home'))
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    if request.method == 'POST':
        restaurant.is_featured = 'is_featured' in request.form
        restaurant.is_approved = 'is_approved' in request.form
        db.session.commit()
        flash('Restaurante atualizado com sucesso!', 'success')
        return redirect(url_for('admin_restaurant_list'))
    return render_template('admin/restaurant_form.html', restaurant=restaurant, title="Editar Restaurante")

@app.route('/superadmin/restaurants/delete/<int:restaurant_id>', methods=['POST'])
@login_required
def admin_delete_restaurant(restaurant_id):
    if current_user.role != 'admin': return redirect(url_for('home'))
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    if restaurant.logo_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], restaurant.logo_filename))
        except: pass
    if restaurant.banner_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], restaurant.banner_filename))
        except: pass
    db.session.delete(restaurant)
    db.session.commit()
    flash('Restaurante apagado com sucesso!', 'success')
    return redirect(url_for('admin_restaurant_list'))

@app.route('/superadmin/orders')
@login_required
def admin_order_list():
    if current_user.role != 'admin': return redirect(url_for('home'))
    orders = Order.query.order_by(Order.timestamp.desc()).all()
    return render_template('admin/order_list.html', orders=orders)

@app.route('/superadmin/tags')
@login_required
def admin_tag_list():
    if current_user.role != 'admin': return redirect(url_for('home'))
    tags = Tag.query.order_by(Tag.name).all()
    return render_template('admin/tag_list.html', tags=tags)

@app.route('/superadmin/tags/create', methods=['GET', 'POST'])
@login_required
def admin_create_tag():
    if current_user.role != 'admin': return redirect(url_for('home'))
    if request.method == 'POST':
        new_tag = Tag(name=request.form.get('name'))
        if 'icon' in request.files:
            icon_file = request.files['icon']
            if icon_file and icon_file.filename != '':
                if allowed_file(icon_file.filename):
                    filename = secure_filename(f"tag_{datetime.now().timestamp()}_{icon_file.filename}")
                    icon_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    new_tag.icon_filename = filename
        db.session.add(new_tag)
        db.session.commit()
        flash('Categoria criada com sucesso!', 'success')
        return redirect(url_for('admin_tag_list'))
    return render_template('admin/tag_form.html', tag=None, title="Criar Nova Categoria")

@app.route('/superadmin/tags/edit/<int:tag_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_tag(tag_id):
    if current_user.role != 'admin': return redirect(url_for('home'))
    tag = Tag.query.get_or_404(tag_id)
    if request.method == 'POST':
        tag.name = request.form.get('name')
        if 'icon' in request.files:
            icon_file = request.files['icon']
            if icon_file and icon_file.filename != '':
                if allowed_file(icon_file.filename):
                    filename = secure_filename(f"tag_{datetime.now().timestamp()}_{icon_file.filename}")
                    icon_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    tag.icon_filename = filename
                else:
                    flash('Tipo de arquivo de ícone inválido.', 'danger')
        db.session.commit()
        flash('Categoria atualizada com sucesso!', 'success')
        return redirect(url_for('admin_tag_list'))
    return render_template('admin/tag_form.html', tag=tag, title="Editar Categoria")

@app.route('/superadmin/tags/delete/<int:tag_id>', methods=['POST'])
@login_required
def admin_delete_tag(tag_id):
    if current_user.role != 'admin': return redirect(url_for('home'))
    tag = Tag.query.get_or_404(tag_id)
    db.session.delete(tag)
    db.session.commit()
    flash('Categoria apagada com sucesso!', 'success')
    return redirect(url_for('admin_tag_list'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'owner': return redirect(url_for('home'))
    restaurant = current_user.restaurant
    today = date.today()
    start_of_day = datetime.combine(today, time.min)
    sales_today_query = db.session.query(func.sum(Order.total_price)).filter(Order.restaurant_id == restaurant.id, Order.timestamp >= start_of_day).scalar()
    sales_today = sales_today_query or 0
    orders_today = Order.query.filter(Order.restaurant_id == restaurant.id, Order.timestamp >= start_of_day).count()
    total_sales_query = db.session.query(func.sum(Order.total_price)).filter_by(restaurant_id=restaurant.id).scalar()
    total_sales = total_sales_query or 0
    seven_days_ago = today - timedelta(days=6)
    sales_data = db.session.query(func.date(Order.timestamp), func.sum(Order.total_price)).filter(Order.restaurant_id == restaurant.id, func.date(Order.timestamp) >= seven_days_ago).group_by(func.date(Order.timestamp)).order_by(func.date(Order.timestamp)).all()
    sales_dict = {d: total for d, total in sales_data}
    chart_labels = [(today - timedelta(days=i)).strftime("%d/%m") for i in range(6, -1, -1)]
    chart_data = [0.0] * 7
    for i in range(7):
        current_day = today - timedelta(days=6-i)
        current_day_str = current_day.strftime("%Y-%m-%d")
        if current_day_str in sales_dict:
            chart_data[i] = float(sales_dict[current_day_str])
    return render_template('dashboard.html', restaurant=restaurant, sales_today=sales_today, orders_today=orders_today, total_sales=total_sales, chart_labels=chart_labels, chart_data=chart_data)

@app.route('/dashboard/pedidos')
@login_required
def dashboard_orders():
    if current_user.role != 'owner': return redirect(url_for('home'))
    orders = Order.query.filter_by(restaurant_id=current_user.restaurant.id).order_by(Order.timestamp.desc()).all()
    return render_template('dashboard_orders.html', orders=orders, restaurant_name=current_user.restaurant.name)

@app.route('/dashboard/pedidos/update_status/<int:order_id>', methods=['POST'])
@login_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    if current_user.role != 'owner' or order.restaurant.owner != current_user:
        flash("Acesso negado.", "danger")
        return redirect(url_for('dashboard_orders'))
    order.status = request.form.get('status')
    db.session.commit()
    flash(f'Status do Pedido #{order.id} atualizado.', 'success')
    return redirect(url_for('dashboard_orders'))

@app.route('/dashboard/menu', methods=['GET', 'POST'])
@login_required
def dashboard_menu():
    if current_user.role != 'owner': return redirect(url_for('home'))
    restaurant = current_user.restaurant
    if request.method == 'POST':
        name = request.form.get('name')
        price = float(request.form.get('price'))
        description = request.form.get('description')
        new_item = MenuItem(name=name, price=price, description=description, restaurant=restaurant)
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and image_file.filename != '' and allowed_file(image_file.filename):
                filename = secure_filename(f"item_{restaurant.id}_{datetime.now().timestamp()}_{image_file.filename}")
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_item.image_filename = filename
        db.session.add(new_item)
        db.session.commit()
        flash('Item adicionado ao cardápio!', 'success')
        return redirect(url_for('dashboard_menu'))
    return render_template('dashboard_menu.html', restaurant=restaurant)

@app.route('/dashboard/menu/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_menu_item(item_id):
    if current_user.role != 'owner': return redirect(url_for('home'))
    item = MenuItem.query.get_or_404(item_id)
    if item.restaurant.owner != current_user: return "Acesso negado", 403
    if request.method == 'POST':
        item.name = request.form.get('name')
        item.price = float(request.form.get('price'))
        item.description = request.form.get('description')
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and image_file.filename != '' and allowed_file(image_file.filename):
                filename = secure_filename(f"item_{item.id}_{datetime.now().timestamp()}_{image_file.filename}")
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                item.image_filename = filename
        db.session.commit()
        flash('Item atualizado com sucesso!', 'success')
        return redirect(url_for('dashboard_menu'))
    return render_template('dashboard_menu_edit.html', item=item)

@app.route('/dashboard/menu/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_menu_item(item_id):
    item = MenuItem.query.get_or_404(item_id)
    if item.restaurant.owner != current_user: return "Acesso negado", 403
    db.session.delete(item)
    db.session.commit()
    flash('Item removido com sucesso.', 'success')
    return redirect(url_for('dashboard_menu'))

@app.route('/dashboard/settings', methods=['GET', 'POST'])
@login_required
def dashboard_settings():
    if current_user.role != 'owner': return redirect(url_for('home'))
    restaurant = current_user.restaurant
    
    if request.method == 'POST':
        restaurant.name = request.form.get('name')
        restaurant.whatsapp = request.form.get('whatsapp')
        restaurant.deliveryFee = float(request.form.get('deliveryFee'))
        restaurant.category = request.form.get('category')
        restaurant.description = request.form.get('description')
        restaurant.address = request.form.get('address')
        restaurant.latitude = request.form.get('latitude', type=float)
        restaurant.longitude = request.form.get('longitude', type=float)
        restaurant.theme = request.form.get('theme')
        
        tag_ids = request.form.getlist('tags')
        restaurant.tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()

        for i in range(7):
            day_index = str(i)
            open_time_str = request.form.get(f'open_time_{day_index}')
            close_time_str = request.form.get(f'close_time_{day_index}')
            is_closed = request.form.get(f'is_closed_{day_index}')
            operating_hour = OperatingHours.query.filter_by(restaurant_id=restaurant.id, day_of_week=i).first()
            if not operating_hour:
                operating_hour = OperatingHours(restaurant_id=restaurant.id, day_of_week=i)
                db.session.add(operating_hour)
            if is_closed:
                operating_hour.is_closed = True
                operating_hour.open_time = None
                operating_hour.close_time = None
            else:
                operating_hour.is_closed = False
                if open_time_str:
                    operating_hour.open_time = datetime.strptime(open_time_str, '%H:%M').time()
                else:
                    operating_hour.open_time = None
                if close_time_str:
                    operating_hour.close_time = datetime.strptime(close_time_str, '%H:%M').time()
                else:
                    operating_hour.close_time = None

        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file and logo_file.filename != '' and allowed_file(logo_file.filename):
                filename = secure_filename(f"logo_{restaurant.id}_{datetime.now().timestamp()}_{logo_file.filename}")
                logo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.logo_filename = filename
        if 'banner' in request.files:
            banner_file = request.files['banner']
            if banner_file and banner_file.filename != '' and allowed_file(banner_file.filename):
                filename = secure_filename(f"banner_{restaurant.id}_{datetime.now().timestamp()}_{banner_file.filename}")
                banner_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.banner_filename = filename
        db.session.commit()
        flash('Informações do restaurante atualizadas!', 'success')
        return redirect(url_for('dashboard_settings'))
    
    all_tags = Tag.query.all()
    return render_template('dashboard_settings.html', restaurant=restaurant, all_tags=all_tags)

# --- 8. ROTAS DO FLUXO DE COMPRA E FAVORITOS ---
@app.route('/cart/add/<int:item_id>', methods=['POST'])
def add_to_cart(item_id):
    cart = session.get('cart', [])
    item_to_add = MenuItem.query.get_or_404(item_id)
    if cart and cart[0]['restaurant_id'] != item_to_add.restaurant_id:
        cart = []
        flash("Seu carrinho foi esvaziado para adicionar itens de um novo restaurante.", "warning")
    found = False
    for item in cart:
        if item['id'] == item_id:
            item['quantity'] += 1
            found = True
            break
    if not found:
        cart.append({'id': item_to_add.id, 'name': item_to_add.name, 'price': item_to_add.price, 'quantity': 1, 'restaurant_id': item_to_add.restaurant_id})
    session['cart'] = cart
    flash(f"'{item_to_add.name}' foi adicionado ao carrinho!", "success")
    return redirect(request.referrer or url_for('home'))

@app.route('/cart/remove/<int:item_id>')
def remove_from_cart(item_id):
    cart = session.get('cart', [])
    cart = [item for item in cart if item['id'] != item_id]
    session['cart'] = cart
    flash("Item removido do carrinho.", "success")
    return redirect(url_for('checkout'))

@app.route('/cart')
@login_required
def view_cart():
    return redirect(url_for('checkout'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if current_user.role != 'customer':
        flash("Apenas clientes podem finalizar pedidos.", "warning")
        return redirect(url_for('home'))
    cart = session.get('cart', [])
    if not cart:
        flash("Seu carrinho está vazio.", "warning")
        return redirect(url_for('home'))
    restaurant = Restaurant.query.get(cart[0]['restaurant_id'])
    subtotal = sum(item['price'] * item['quantity'] for item in cart)
    if request.method == 'POST':
        if not restaurant.whatsapp:
            flash(f"O restaurante '{restaurant.name}' não está aceitando pedidos no momento.", "danger")
            return redirect(url_for('menu', restaurant_id=restaurant.id))
        form_data = request.form
        delivery_type = form_data.get('delivery_type')
        final_total = subtotal + restaurant.deliveryFee if delivery_type == 'delivery' and restaurant.deliveryFee else subtotal
        new_order = Order(total_price=final_total, customer_id=current_user.id, restaurant_id=restaurant.id)
        db.session.add(new_order)
        db.session.commit()
        for item in cart:
            order_item = OrderItem(product_name=item['name'], quantity=item['quantity'], price=item['price'], order_id=new_order.id)
            db.session.add(order_item)
        db.session.commit()
        phone_number = restaurant.whatsapp
        cleaned_phone = "".join(filter(str.isdigit, phone_number))
        message_parts = [f"*--- Novo Pedido #{new_order.id}: {restaurant.name} ---*"]
        for item in cart:
            message_parts.append(f"- {item['quantity']}x {item['name']}")
        message_parts.extend(["", f"*Subtotal:* R$ {subtotal:.2f}"])
        if delivery_type == 'delivery' and restaurant.deliveryFee:
            message_parts.append(f"*Taxa de Entrega:* R$ {restaurant.deliveryFee:.2f}")
        else:
             message_parts.append("*Taxa de Entrega:* R$ 0.00 (Retirada)")
        message_parts.extend([f"*Total:* R$ {final_total:.2f}", "", f"*--- Pagamento e Entrega ---*", f"*Forma de Pagamento:* {form_data.get('payment_method')}"])
        if form_data.get('payment_method') == 'Dinheiro' and form_data.get('change_for'):
            message_parts.append(f"*Troco para:* R$ {form_data.get('change_for')}")
        message_parts.extend(["", f"*--- Dados do Cliente ({current_user.name}) ---*"])
        if delivery_type == 'delivery':
            message_parts.append(f"*Endereço de Entrega:* {form_data.get('address')}")
        else:
            message_parts.append("*Tipo de Pedido:* Retirada no local")
        whatsapp_message = "\n".join(message_parts)
        whatsapp_url = f"https://wa.me/{cleaned_phone}?text={quote(whatsapp_message)}"
        session['cart'] = []
        session.modified = True
        flash('Pedido enviado! Você será redirecionado para o WhatsApp para confirmar.', 'success')
        return redirect(whatsapp_url)
    delivery_fee = restaurant.deliveryFee if restaurant and restaurant.deliveryFee else 0
    return render_template('checkout.html', cart=cart, subtotal=subtotal, delivery_fee=delivery_fee, restaurant=restaurant)

@app.route('/meus-pedidos')
@login_required
def customer_orders():
    if current_user.role != 'customer':
        return redirect(url_for('home'))
    orders = Order.query.filter_by(customer_id=current_user.id).order_by(Order.timestamp.desc()).all()
    return render_template('customer_orders.html', orders=orders)

@app.route('/submit_review/<int:restaurant_id>', methods=['POST'])
@login_required
def submit_review(restaurant_id):
    if current_user.role != 'customer':
        flash("Apenas clientes podem enviar avaliações.", "danger")
        return redirect(url_for('home'))
    rating = request.form.get('rating')
    if not rating:
        flash("Você precisa selecionar uma nota.", "warning")
        return redirect(url_for('customer_orders'))
    if Review.query.filter_by(customer_id=current_user.id, restaurant_id=restaurant_id).first():
        flash("Você já avaliou este restaurante.", "warning")
        return redirect(url_for('customer_orders'))
    new_review = Review(rating=int(rating), comment=request.form.get('comment'), customer_id=current_user.id, restaurant_id=restaurant_id)
    db.session.add(new_review)
    db.session.commit()
    flash("Obrigado pela sua avaliação!", "success")
    return redirect(url_for('customer_orders'))

@app.route('/meus-favoritos')
@login_required
def favorites():
    if current_user.role != 'customer':
        return redirect(url_for('home'))
    favorited = current_user.favorited_restaurants
    return render_template('favorites.html', favorites=favorited)

@app.route('/favorite/add/<int:restaurant_id>', methods=['POST'])
@login_required
def add_favorite(restaurant_id):
    if current_user.role != 'customer':
        return redirect(url_for('home'))
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    current_user.favorited_restaurants.append(restaurant)
    db.session.commit()
    return redirect(request.referrer or url_for('home'))

@app.route('/favorite/remove/<int:restaurant_id>', methods=['POST'])
@login_required
def remove_favorite(restaurant_id):
    if current_user.role != 'customer':
        return redirect(url_for('home'))
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    current_user.favorited_restaurants.remove(restaurant)
    db.session.commit()
    return redirect(request.referrer or url_for('home'))

# --- 9. INICIAR A APLICAÇÃO ---
if __name__ == '__main__':
    # A linha abaixo foi removida para usarmos o Flask-Migrate
    # with app.app_context():
    #     db.create_all()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        ip_address = "127.0.0.1"

    print("---")
    print("Para acessar de outro dispositivo na mesma rede (como seu celular), use o endereço:")
    print(f"   http://{ip_address}:5002")
    print("---")
    
    app.run(host='0.0.0.0', port=5002, debug=True)
