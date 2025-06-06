<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $fullname = trim($_POST['fullname']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $terms = isset($_POST['terms']);
  
    // Basic validation
    if (empty($fullname) || empty($email) || empty($password) || empty($confirm_password)) {
        die("All fields are required.");
    }
    if ($password !== $confirm_password) {
        die("Passwords do not match.");
    }
    if (strlen($password) < 8) {
        die("Password must be at least 8 characters.");
    }
    if (!$terms) {
        die("You must agree to the terms.");
    }

    // Hash password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    //  Save to database
     $conn = new mysqli('localhost', 'root', 'Pas5word##', 'login');
     $stmt = $conn->prepare("INSERT INTO `login`.`registration` (fullname, email, password) VALUES (?, ?, ?)");
     $stmt->bind_param("ssss", $fullname, $email, $hashed_password,);
     $stmt->execute();
     $stmt->close();
     $conn->close();

    echo "Registration successful!";
}
?>
