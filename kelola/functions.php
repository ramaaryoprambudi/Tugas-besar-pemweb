<?php
     require __DIR__ . '/../koneksi.php';


    //ADMIN LOGIC AREA 

    // ADMIN AUTHENTICATION

    //LOGIN ADMIN & SUPERADMIN
    function login($koneksi){
        // Mengambil nilai dari $_POST yang berisi name 
        $email = isset($_POST['email']) ? $_POST['email'] : "";
        $password = isset($_POST['password']) ? $_POST['password'] : "";
        $role = isset($_POST['role']) ? $_POST['role'] : "";
        
        if(isset($_POST['btnmasuk'])){
            if(empty($email) || empty($password) || empty($role)){
                header("Location: login.php?error=".urlencode("Please fill in all fields"));
                exit();
            }elseif(!filter_var($email,FILTER_VALIDATE_EMAIL)){
                header("Location: login.php?error=".urlencode("Invalid email format"));
                exit();
            } 
            else {
                // Hash password menggunakan MD5
                $hashed_password = hash('md5', $password);
                
                // Query untuk memeriksa pengguna berdasarkan email, password, dan role
                $sql = "SELECT * FROM users WHERE email = ? AND user_type = ?";
                $stmt = $koneksi->prepare($sql);
                $stmt->bind_param("ss", $email, $role);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if($result->num_rows > 0){
                    $user = $result->fetch_assoc();
                   
                    if($hashed_password === $user['password_hash'] && $email === $user['email']){
                        session_start();
                        
                        if ($role === 'Superadmin') {
                            $_SESSION['is_superadmin'] = true;
                            header("Location: /kelola/superadminpanel");
                            exit();
                        } elseif ($role === 'Admin') {
                            $_SESSION['is_admin'] = true;
                            header("Location: /kelola/adminpanel");
                            exit();
                        }
                        
                    } else {
                        header("Location: login.php?error=".urlencode("Incorrect password"));
                        exit();
                    }
                } else {
                    header("Location: login.php?error=".urlencode("User not found or incorrect role"));
                    exit();
                }
            }
        }
    }
    // REGISTER ADMIN
    function register($koneksi){
        
        // Mengambil nilai POST Dari name
        $namaLengkap = htmlspecialchars(isset($_POST['nama']) ? $_POST['nama'] :"");
        $username = htmlspecialchars(isset($_POST['username']) ? $_POST['username'] :"");
        $email = htmlspecialchars(isset($_POST['email']) ? $_POST['email'] :"");
        $hash_password = hash('md5',htmlspecialchars(isset($_POST['password']) ? $_POST['password'] :""));
        
        if(isset($_POST['btndaftar'])){
            
            // Memeriksa form input agar data di isi semua
            if(empty($namaLengkap) || empty($username) || empty($email) || empty($hash_password)){
                header("Location:register.php?error=".urlencode("Please fill in all fields"));

            }
            // Memeriksa apakah format email benar
            elseif(!filter_var($email,FILTER_VALIDATE_EMAIL)){
                header("Location: register.php?error=".urlencode("Invalid email format"));
                exit();
            }
            else{

                // Memeriksa apakah email atau username sudah terdaftar
                $stmt = $koneksi->prepare("SELECT * FROM users WHERE email = ? OR username = ?");
                $stmt->bind_param("ss", $email, $username);
                $stmt->execute();
                $result = $stmt->get_result();

                if($result -> num_rows > 0){
                    header("Location: register.php?error=".urlencode("Email or Username already exists"));
                    exit();
                }else{
                    $role = 'admin';
                    $stmt = $koneksi->prepare("INSERT INTO users (full_name, username, email, password_hash, user_type) VALUES (?, ?, ?, ?, ?)");
                    $stmt->bind_param("sssss", $namaLengkap, $username, $email, $hash_password, $role);
                    $stmt->execute();
                    if($result){
                        header("Location: register.php?success=".urlencode("Successfully registered"));

                    }
                }
            }
        }
    }
    //END ADMIN AUTHENTICATION

    //USER MANAGEMENT

    // Update Management
    function updatedataUser($koneksi) {
        if (!isset($_POST['updatebtn'])) {
            return;
        }
    
        $namaLengkap = isset($_POST['updatenama']) ? htmlspecialchars($_POST['updatenama']) : "";
        $email = isset($_POST['updateemail']) ? htmlspecialchars($_POST['updateemail']) : "";
        $password = isset($_POST['updatepassword']) ? htmlspecialchars($_POST['updatepassword']) : "";
    
        if (empty($namaLengkap)) {
            echo "<script>alert('Nama Lengkap belum di isi')</script>";
            return;
        }
    
        if (empty($email)) {
            echo "<script>alert('Email belum di isi')</script>";
            return;
        }
    
        if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
            echo "<script>alert('ID tidak valid')</script>";
            return;
        }
    
        $id = $_GET['id'];
    
        $sql = "UPDATE users SET full_name = ?, email = ?, password_hash = ? WHERE user_id = ?";
        $stmt = mysqli_prepare($koneksi, $sql);
        if ($stmt === false) {
            echo "<script>alert('SQL error: ".mysqli_error($koneksi)."')</script>";
            return;
        }
    
        mysqli_stmt_bind_param($stmt, "sssi", $namaLengkap, $email, $password, $id);
    
        if (mysqli_stmt_execute($stmt)) {
            echo "<script>alert('User updated successfully')</script>";
            header("Location: user_management.php"); // Redirect setelah update berhasil
        } else {
            echo "<script>alert('Error updating user: ".mysqli_stmt_error($stmt)."')</script>";
        }
    
        mysqli_stmt_close($stmt);
    }

    // Update Password User
    function updatePassword($koneksi) {
        if (!isset($_POST['changepasswordbtn'])) {
            return;
        }
    
        $password = isset($_POST['updatepassword']) ? htmlspecialchars($_POST['updatepassword']) : "";
        $confirmPassword = isset($_POST['updateconfirmpassword']) ? htmlspecialchars($_POST['updateconfirmpassword']) : "";
    
        if (empty($password)) {
            echo "<script>alert('Password belum di isi')</script>";
            return;
        }
    
        if ($password !== $confirmPassword) {
            echo "<script>alert('Password tidak cocok')</script>";
            return;
        }
    
        if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
            echo "<script>alert('ID tidak valid')</script>";
            return;
        }
    
        $id = $_GET['id'];
        $hashedPassword = md5($password); // Using MD5 for hashing
    
        $sql = "UPDATE users SET password_hash = ? WHERE user_id = ?";
        $stmt = mysqli_prepare($koneksi, $sql);
        if ($stmt === false) {
            echo "<script>alert('SQL error: ".mysqli_error($koneksi)."')</script>";
            return;
        }
    
        mysqli_stmt_bind_param($stmt, "si", $hashedPassword, $id);
    
        if (mysqli_stmt_execute($stmt)) {
            echo "<script>alert('Password updated successfully')</script>";
            header("Location: user_management.php"); // Redirect setelah update berhasil
        } else {
            echo "<script>alert('Error updating password: ".mysqli_stmt_error($stmt)."')</script>";
        }
    
        mysqli_stmt_close($stmt);
    }

    // Delete User Management
    function deleteUser($koneksi, $user_id) {
        $sql = "DELETE FROM users WHERE user_id = ?";
        $stmt = $koneksi->prepare($sql);
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            echo "<script>alert('Berhasil Delete Data');</script>";
            header("Location: user_management.php"); // Redirect setelah penghapusan berhasil
            exit();
        } else {
            echo "<script>alert('Gagal Delete Data');</script>";
        }
    }
    
    
    //END USER MANAGEMENT

    //END ADMIN LOGIC AREA
