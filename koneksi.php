<?php 

    $server = "localhost";
    $username = "root";
    $password = "";
    $dbname = "lelangelektronik";

    $koneksi = mysqli_connect($server, $username, $password,$dbname);
    
    if($koneksi->connect_error){
        echo "Koneksi Gagal".$koneksi->connect_error;
    }