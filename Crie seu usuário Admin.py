from app import app, db, User
from werkzeug.security import generate_password_hash

# --- CONFIGURE SEU ADMIN AQUI ---
ADMIN_EMAIL = "admin@gmail.com"
ADMIN_NOME = "Administrador"
ADMIN_SENHA = "1234"
# ---------------------------------

print(f"Criando usuário admin com o e-mail: {ADMIN_EMAIL}...")

with app.app_context():
    # Verifica se o admin já não existe
    existing_admin = User.query.filter_by(email=ADMIN_EMAIL).first()
    if existing_admin:
        print("Usuário admin já existe.")
    else:
        admin_user = User(
            email=ADMIN_EMAIL,
            name=ADMIN_NOME,
            role="admin",
            password_hash=generate_password_hash(ADMIN_SENHA)
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Usuário admin criado com sucesso!")