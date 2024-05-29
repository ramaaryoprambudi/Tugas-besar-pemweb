
<?php 
    
    session_start();
    require '../functions.php';
    if(!isset($_SESSION['is_peserta'])){
        header("Location: ../login.php");
        exit();

    }
?>

<h1>Peserta</h1>