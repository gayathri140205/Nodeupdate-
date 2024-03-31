const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const mongoose = require('mongoose'); 
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000; 

// Connect to MongoDB using mongoose
mongoose.connect(process.env.MONGODB_ATLAS_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define a mongoose schema for users
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

// Create a mongoose model based on the schema
const User = mongoose.model('User', userSchema);

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Endpoint for password reset request
app.post('/reset-password/request', async (req, res) => {
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate a unique reset token
    const token = crypto.randomBytes(20).toString('hex');

    // Store the token in the user document
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    // Send password reset email with the token
    sendResetEmail(email, token);

    res.status(200).json({ message: 'Password reset email sent successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint for password reset confirmation
app.post('/reset-password/confirm', async (req, res) => {
  const { email, token, newPassword } = req.body;

  try {
    // Find the user by email and token
    const user = await User.findOne({ email, resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // Update user's password
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error confirming password reset:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Function to send reset password email
function sendResetEmail(email, token) {
  // Create a Nodemailer transporter
  let transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });

  // Define email options
  let mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Reset Your Password',
    text: `To reset your password, click on the following link: http://localhost:3000/reset-password?token=${token}`
  };

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
}

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
