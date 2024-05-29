<?php 
session_start();
    require 'functions.php';
    register($koneksi);
    if(isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
        header("Location: /adminpanel");
    }
    elseif(isset($_SESSION['is_peserta']) && $_SESSION['is_peserta']) {
        header("Location: /pesertalelang");
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register | Lelang Elektronik</title>
</head>
<body>
    <h1>Daftar Admin</h1>
    <?php if(isset($_GET['error'])){ ?>
        <?= htmlspecialchars(urldecode($_GET['error']));?>
        <?php }?>
        <?php if(isset($_GET['success'])){ ?>
        <?= htmlspecialchars(urldecode($_GET['success']));?>
        <?php }?>
    <form method="POST">
        <label for="nama">Nama Lengkap</label>
        <input type="text" name="nama" id="nama">
        <br>
        <label for="username">Username</label>
        <input type="text" name="username" id="username">
        <br>
        <label for="email">Alamat Email</label>
        <input type="email" name="email" id="email" >
        <br>
        <label for="password">Password</label>
        <input type="password" name="password" id="password" >
        <br>
        <button type="submit" name="btndaftar" >Daftar</button>
    </form>
    <span>Sudah punya akun? Ayo Login<a href="login.php">Disini</a> dan kelola lelang sekarang!.</span>
</body>
</html>