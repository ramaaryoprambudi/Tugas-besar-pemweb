<?php 
    session_start();
    require 'functions.php';
    login($koneksi);
    if(isset($_SESSION['is_superadmin']) && $_SESSION['is_superadmin']) {
        header("Location: /kelola/superadminpanel");
    }
    elseif(isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
        header("Location: /kelola/adminpanel");
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | Lelang Elektronik</title>
</head>
<body>
    <h1>Masuk</h1>
    <p>Silahkan masukan data Anda yang telah di daftarkan</p>
    <?php if(isset($_GET['error'])){ ?>
        <!-- Ini dikasih CSS  -->
        <i class="tulis css disini"><?=  htmlspecialchars(urldecode($_GET['error']));?></i>
        <!-- end kasih css  -->
        <?php }?>
    <form method="POST">
        <label for="email">Alamat Email</label>
        <input type="email" name="email" id="email" >
        <br>
        <label for="password">Password</label>
        <input type="password" name="password" id="password" >
        <br>
        <label for="role">Login Sebagai</label>
        <select name="role" id="role">
            <option value="Superadmin" selected>Super Admin</option>
            <option value="Admin">Admin</option>
        </select>
        <button type="submit" name="btnmasuk" >Masuk</button>
    </form>
    <span>Belum punya akun? Ayo daftar <a href="register.php">Disini</a> </span>
</body>
</html>