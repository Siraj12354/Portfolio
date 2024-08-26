<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get form data
    $fullname = $_POST['fullname'];
    $email = $_POST['email'];
    $subject = $_POST['subject'];
    $message = $_POST['message'];

    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format";
        exit;
    }

    // Recipient email address
    $to = "sirajdhakal.52@gmail.com";  // Replace with your own email address

    // Email subject
    $email_subject = "New Contact Form Submission: " . $subject;

    // Email body
    $email_body = "You have received a new message from the contact form.\n\n".
                  "Here are the details:\n\n".
                  "FullName: $name\n".
                  "Email: $email\n".
                  "Subject: $subject\n".
                  "Message:\n$message";

    // Email headers
    $headers = "From: $email\n";
    $headers .= "Reply-To: $email";

    // Send the email
    if (mail($to, $email_subject, $email_body, $headers)) {
        echo "Your message has been sent. Thank you!";
    } else {
        echo "There was a problem sending your message. Please try again.";
    }
} else {
    echo "Invalid request.";
}
?>
