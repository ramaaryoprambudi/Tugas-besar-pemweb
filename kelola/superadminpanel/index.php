<?php 
session_start();
require '../functions.php';

if (!isset($_SESSION['is_superadmin'])) {
    header("Location: /kelola/login.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SuperAdmin Panel</title>
</head>
<body>
    <h1>Halo Selamat Datang Boss</h1>
    <a href="user_management.php">User Management</a>
</body>
</html>
