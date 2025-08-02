<?php
$servername = "db"; // Change this to your database server name
$username = "root"; // Change this to your database username
$password = "root"; // Change this to your database password
$dbname = "users"; // Change this to your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title></title>
    <link rel="stylesheet" href="Style/style.css">
</head>
<body>
  <div class="container">
    <h1>Can you find the needle?</h1>
    <div class="search-container">
      <form action="" method="GET">
        <input type="text" placeholder="Search..." class="search-box" name='id'>
        <button type="submit" class="search-button">Search</button>
      </form>
    </div>
    <div class="result">
      <?php
        if(isset($_GET['id'])) {
            @$searchQ = $_GET['id'];
            @$sql = "SELECT information FROM info WHERE id = '$searchQ'";
            @$result = mysqli_query($conn, $sql);
            @$row_count = mysqli_num_rows($result);
            
            if ($row_count > 0) {
                echo "Yes, We found it !!";
            } else {
                echo "Nothing here";
            }
            $conn->close();
        }
      ?>
    </div>
  </div>
</body>
</html>
