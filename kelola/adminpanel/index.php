<?php
session_start();
require '../functions.php';

if (!isset($_SESSION['is_admin'])) {
    header("Location: /kelola/login.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
</head>
<body>
    <h1>Admin Panel</h1>
    <!-- Your admin panel content here -->
</body>
</html>
