<?php
// Configurações do Banco de Dados
$host = 'localhost';
$db_name = 'delivre_db';
$username = 'root';
$password = ''; // A senha padrão do XAMPP é vazia
$charset = 'utf8mb4';

// DSN (Data Source Name)
$dsn = "mysql:host=$host;dbname=$db_name;charset=$charset";

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    // Cria a conexão PDO
    $pdo = new PDO($dsn, $username, $password, $options);
} catch (\PDOException $e) {
    // Em caso de erro, exibe a mensagem e encerra o script
    throw new \PDOException($e->getMessage(), (int)$e->getCode());
}

// Inicia a sessão para o carrinho de compras
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>