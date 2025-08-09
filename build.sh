#!/usr/bin/env bash
# Para o script se houver qualquer erro
set -o errexit

# Atualiza o pip e instala as dependências do requirements.txt
pip install --upgrade pip
pip install -r requirements.txt

# Executa as migrações do banco de dados para garantir que ele está atualizado
python -m flask db upgrade

echo "Build finalizado com sucesso!"

