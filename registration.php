<?php

include('database.php'); // Ensure you include the database connection

// Process form submission
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Retrieve and sanitize inputs
    $name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_SPECIAL_CHARS);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_SPECIAL_CHARS);

    // Hash the password
    $hash = password_hash($password, PASSWORD_BCRYPT);

    // Prepare an SQL statement to prevent SQL injection
    $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $name, $email, $hash);

    // Execute the statement and check for success
    if ($stmt->execute()) {
        echo "<script>alert('User registered successfully');</script>";
    } else {
        echo "<script>alert('Error: " . $stmt->error . "');</script>";
    }

    // Close statement
    $stmt->close();
}

// Close MySQL connection
$conn->close();
?>
