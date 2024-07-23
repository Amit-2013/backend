const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());

const users = {}; // { username: { password: hashedPassword, role: 'user' or 'admin', isApproved: true/false, location: {latitude, longitude} } }
const adminPassword = 'adminpassword'; // Change this to a more secure password

// Middleware to check admin status
const isAdmin = (req, res, next) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === adminPassword) {
        next();
    } else {
        res.status(403).json({ message: 'Admin access required' });
    }
};

// Register new user
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (users[username]) {
        return res.json({ message: 'Username already exists' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    users[username] = { password: hashedPassword, role: 'user', isApproved: false, location: null };
    res.json({ message: 'Registration successful. Awaiting admin approval.' });
});

// Login user
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users[username];

    if (user && bcrypt.compareSync(password, user.password)) {
        if (user.isApproved) {
            res.json({ message: 'Login successful', role: user.role });
        } else {
            res.json({ message: 'User not approved by admin' });
        }
    } else {
        res.json({ message: 'Invalid credentials' });
    }
});

// Request password reset
app.post('/resetPassword', (req, res) => {
    const { username } = req.body;
    if (users[username]) {
        // Simulate sending a reset request (e.g., via email)
        res.json({ message: 'Password reset request received. Awaiting admin approval.' });
    } else {
        res.json({ message: 'Username not found' });
    }
});

// Update location
app.post('/updateLocation', (req, res) => {
    const { username, latitude, longitude } = req.body;
    const user = users[username];

    if (user && user.isApproved) {
        user.location = { latitude, longitude };
        res.json({ message: 'Location updated' });
    } else {
        res.status(403).json({ message: 'User not approved or not found' });
    }
});

// Track user location
app.post('/trackUser', (req, res) => {
    const { username, passcode } = req.body;
    const user = users[username];

    if (user && passcode === user.password) {
        res.json({ location: user.location || { latitude: null, longitude: null } });
    } else {
        res.status(403).json({ message: 'Invalid username or passcode' });
    }
});

// Admin: Approve user
app.post('/admin/approveUser', isAdmin, (req, res) => {
    const { username } = req.body;
    const user = users[username];

    if (user) {
        user.isApproved = true;
        res.json({ message: 'User approved' });
    } else {
        res.status(404).json({ message: 'User not found' });
    }
});

// Admin: View all user locations
app.post('/admin/getAllLocations', isAdmin, (req, res) => {
    res.json(users);
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
