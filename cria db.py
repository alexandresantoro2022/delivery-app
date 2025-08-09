from app import app, db

print("Iniciando a criação do banco de dados...")

with app.app_context():
    # Apaga todas as tabelas existentes (se houver) e cria as novas
    db.drop_all()
    db.create_all()

print("Banco de dados 'delivery.db' criado com sucesso!")