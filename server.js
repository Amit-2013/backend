const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const https = require('https');
const fs = require('fs');

const app = express();
const port = 3000;

// Updated CORS configuration
app.use(cors({
  origin: 'https://funsparktv-ai.github.io/MapMasterPro',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const JWT_SECRET = 's#@@#jenewe#@!#!@FRERFE13213eweie3####@@#$%#@$%&ew@@#$@#';

// In-memory storage (replace with a database in production)
const users = [
    { id: 1, username: 'ADMIN', password: bcrypt.hashSync('adminpass', 10), isAdmin: true },
    { id: 2, username: 'user1', password: bcrypt.hashSync('pass1', 10), isAdmin: false },
    { id: 3, username: 'user2', password: bcrypt.hashSync('pass2', 10), isAdmin: false },
];

let visits = [];
let userLocations = {};

const upload = multer({ 
    dest: 'uploads/',
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error("Error: File upload only supports images"));
    }
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ message: 'Authentication required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

app.post('/login', 
    body('username').isString().trim().notEmpty(),
    body('password').isString().notEmpty(),
    (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ id: user.id, username: user.username, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, isAdmin: user.isAdmin });
    } else {
        res.status(400).json({ message: 'Invalid username or password' });
    }
});

app.post('/logout', authenticateToken, (req, res) => {
    // In a real-world scenario, you might want to invalidate the token here
    // For now, we'll just send a success message
    res.status(200).json({ message: 'Logged out successfully' });
});

app.post('/check-in', 
    authenticateToken,
    body('lat').isFloat({ min: -90, max: 90 }),
    body('lng').isFloat({ min: -180, max: 180 }),
    body('timestamp').isISO8601(),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { lat, lng, timestamp } = req.body;
        visits.push({ userId: req.user.id, checkIn: new Date(timestamp), lat, lng });
        res.status(200).json({ message: 'Checked in successfully' });
    }
);

app.post('/check-out', 
    authenticateToken,
    body('lat').isFloat({ min: -90, max: 90 }),
    body('lng').isFloat({ min: -180, max: 180 }),
    body('timestamp').isISO8601(),
    body('duration').isFloat({ min: 0 }),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { lat, lng, timestamp, duration } = req.body;
        const lastVisit = visits.filter(v => v.userId === req.user.id).pop();
        if (lastVisit && !lastVisit.checkOut) {
            lastVisit.checkOut = new Date(timestamp);
            lastVisit.duration = duration;
            lastVisit.endLat = lat;
            lastVisit.endLng = lng;
            res.status(200).json({ message: 'Checked out successfully' });
        } else {
            res.status(400).json({ message: 'No active check-in found' });
        }
    }
);

app.post('/upload-image', 
    authenticateToken, 
    upload.single('image'),
    body('lat').isFloat({ min: -90, max: 90 }),
    body('lng').isFloat({ min: -180, max: 180 }),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        if (!req.file) {
            return res.status(400).json({ message: 'No image uploaded' });
        }
        const { lat, lng } = req.body;
        // Here you would typically save the image metadata to a database
        res.status(200).json({ message: 'Image uploaded successfully', filename: req.file.filename });
    }
);

app.get('/visit-log', authenticateToken, (req, res) => {
    const userVisits = visits.filter(v => v.userId === req.user.id);
    res.status(200).json(userVisits);
});

app.post('/update-location', 
    authenticateToken,
    body('lat').isFloat({ min: -90, max: 90 }),
    body('lng').isFloat({ min: -180, max: 180 }),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { lat, lng } = req.body;
        userLocations[req.user.id] = { lat, lng, lastUpdated: new Date() };
        res.status(200).json({ message: 'Location updated successfully' });
    }
);

app.get('/users', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const userList = users.map(user => ({
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
        lastLocation: userLocations[user.id] || null
    }));
    
    res.status(200).json(userList);
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

https.createServer(app).listen(port, () => {
    console.log(`HTTPS Server running at https://localhost:${port}`);
});
