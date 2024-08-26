<?php
// Start session to maintain user login state
session_start();

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Function to validate credentials against CSV file
function validateCredentialsCSV($username, $password)
{
    // Open the CSV file
    $file = fopen("users.csv", "r");

    // Check if file opened successfully
    if ($file !== FALSE) {
        // Iterate through each line in the file
        while (($data = fgetcsv($file, 1000, ",")) !== FALSE) {
            // Check if the username and password match
            if ($data[0] === $username && $data[1] === $password) {
                // Close the file
                fclose($file);
                return true; // Return true if match found
            }
        }
        // Close the file
        fclose($file);
    }
    return false; // Return false if no match found
}

function validateCredentialsDB($username_or_email, $password)
{
    $mysqli = new mysqli("localhost:3306", "pgibhara_pgibharatpur", "NurseNCLEX24@2081", "pgibhara_authorizeduser");

    // Enable error reporting for MySQLi
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    if ($mysqli->connect_error) {
        die("Connection failed: " . $mysqli->connect_error);
    }

    // Prepare SQL query
    $query = "SELECT UserName, is_logged_in FROM listinguser WHERE (UserName = ? OR Email = ?) AND Password = ?";
    $stmt = $mysqli->prepare($query);

    if (!$stmt) {
        die("Prepare failed: " . $mysqli->error);
    }

    // Bind parameters
    $stmt->bind_param("sss", $username_or_email, $username_or_email, $password);

    // Execute query
    if (!$stmt->execute()) {
        die("Execute failed: " . $stmt->error);
    }

    // Store result
    $stmt->store_result();

    // Handle result
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($username, $is_logged_in);
        $stmt->fetch();

        if ($is_logged_in == 1) {
            // User is already logged in
            $stmt->close();
            $mysqli->close();
            return "already_logged_in";
        } else {
            // Update user as logged in
            $updateStmt = $mysqli->prepare("UPDATE listinguser SET is_logged_in = 1 WHERE (UserName = ? OR Email = ?)");
            $updateStmt->bind_param("ss", $username_or_email, $username_or_email);
            $updateStmt->execute();
            $updateStmt->close();

            // Log successful login attempt
            $currentTimestamp = date("Y-m-d H:i:s");
            $insertStmt = $mysqli->prepare("INSERT INTO login_attempts (Username_or_Email, Timestamp) VALUES (?, ?)");
            $insertStmt->bind_param("ss", $username_or_email, $currentTimestamp);
            $insertStmt->execute();
            $insertStmt->close();

            $stmt->close();
            $mysqli->close();
            return true;
        }
    } else {
        $stmt->close();
        $mysqli->close();
        return false;
    }
}


//Function to validate credentials against admin database

function validateCredentialsADB($username, $password)
{
    // Database connection
    $mysqli = new mysqli("localhost:3306", "pgibhara_pgibharatpur", "NurseNCLEX24@2081", "pgibhara_admin");

    // Check connection
    if ($mysqli->connect_error) {
        die("Connection failed: " . $mysqli->connect_error);
    }

    // Prepare and execute statement
    $stmt = $mysqli->prepare("SELECT adminName FROM admindetails WHERE adminName = ? AND Password = ?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $stmt->store_result();

    // Check if a row was returned
    if ($stmt->num_rows > 0) {
        $stmt->close();
        $mysqli->close();
        return true; // Return true if match found
    } else {
        $stmt->close();
        $mysqli->close();
        return false; // Return false if no match found
    }
}


// Function to validate credentials
function validateCredentials($username, $password)
{
    // First, check credentials against CSV file
    if (validateCredentialsCSV($username, $password)) {
        return "admin"; // Return "admin" if match found in CSV file
    } else {
        // If not found in CSV file, check against database
        if (validateCredentialsDB($username, $password)) {
            return "database"; // Return "database" if match found in database
        } else {
            if (validateCredentialsADB($username, $password)) {
                return "Admindatabase"; // Return "database" if match found in database
            } else {
                return false; // Return false if no match found in CSV file or database
            } // Return false if no match found in CSV file or database
        }
    }
}

// If the login form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get username and password from the form
    $username = $_POST["Username"];
    $password = $_POST["password"];

    // Validate username and password
    if (empty($username) || empty($password)) {
        $error = "Username and password are required";
    } else {
        // Validate credentials
        $validationResult = validateCredentials($username, $password);
        if ($validationResult === "already_logged_in") {
            // Handle already logged in scenario
            echo("<script>alert('Already logged in on another device.')</script>");
            // Redirect or display appropriate message
            header("Location: https://pgibharatpur.com/inner-page/logged/Notes/authent_down_check/signup.php");
            exit();
        } elseif ($validationResult === "admin") {
            // Proceed with admin login
            // Set session variables to mark the user as authenticated
            $_SESSION["authenticated"] = true;
            $_SESSION["username"] = $username;
            // Redirect to admin page
            header("Location: notes verified/pgiadmin/index.php?entrypoint=1");
            exit();
        } elseif ($validationResult === "database") {
            // Proceed with regular user login
            // Set session variables to mark the user as authenticated
            $_SESSION["authenticated"] = true;
            $_SESSION["username"] = $username;
            // Redirect to logged-in page
            header("Location: ../../../../loggedpage.html?user=".$username);
            exit();
        } elseif ($validationResult === "Admindatabase") {
            // Proceed with admin user login
            // Set session variables to mark the user as authenticated
            $_SESSION["authenticated"] = true;
            $_SESSION["username"] = $username;
            // Redirect to admin panel
            header("Location: notes verified/pgiadmin/index.php?username=". $username);
            exit();
        } else {
            // Invalid username or password
            echo("<script>alert('Invalid username or password')</script>");
            header("Location: https://pgibharatpur.com/inner-page/logged/Notes/authent_down_check/signup.php?user=false");
            exit();
        }
    }
}
?>























<?php
// Assuming you have a MySQL database connection established
$servername = "localhost:3306";
$username = "pgibhara_pgibharatpur";
$password = "NurseNCLEX24@2081";
$dbname = "pgibhara_authorizeduser";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get the user parameter from the URL
$user = $_GET['user'];

// Prepare a SQL statement to check if the user exists in the database
$stmt = $conn->prepare("SELECT * FROM listinguser WHERE UserName = ?");
$stmt->bind_param("s", $user);
$stmt->execute();
$result = $stmt->get_result();

// Check if a row is returned
if ($result->num_rows > 0) {
    // Fetch the user's data
    $row = $result->fetch_assoc();
    
    // Check the is_logged_in value
    if ($row['is_logged_in'] == 0) {
        // User exists and not logged in, so execute the page
        // Modify this line to execute the appropriate page
          // Update user as logged in
            $updateStmt = $mysqli->prepare("UPDATE listinguser SET is_logged_in = 1 WHERE (UserName = ? OR Email = ?)");
            $updateStmt->bind_param("ss", $username_or_email, $username_or_email);
            $updateStmt->execute();
            $updateStmt->close();
        header("Location: https://pgibharatpur.com/loggedpage.html?user=$user&logg=first");
        exit();
    } else {
        
        // User exists but already logged in, display an alert and exit
        echo "<script>alert('User is already logged in');</script>";
        exit();
    }
} else {
    // User does not exist, display an alert and exit
    echo "<script>alert('User not found');</script>";
    exit();
}

// Close prepared statement and database connection
$stmt->close();
$conn->close();
?>
<script>
    var user = "<?php echo $user; ?>";
    // Check if logg=first is stored in local storage
    if(localStorage.getItem('logg') === 'first') {
        // Redirect to prevent login
        alert('You are already logged in.');
        window.location.href = 'https://pgibharatpur.com/loggedpage.php?user=' + user;
    } else {
        // Store logg=first in local storage
        localStorage.setItem('logg', 'first');
    }
</script>