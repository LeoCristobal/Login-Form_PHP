<?php
$db_server = "localhost";
$db_user = "root";
$db_password = "";
$db_name = "businessdb";

// Create connection
$conn = mysqli_connect($db_server, $db_user, $db_password, $db_name);

// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>
