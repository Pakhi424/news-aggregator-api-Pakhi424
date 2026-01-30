require('dotenv').config();
const express = require('express');
const fs = require('fs');
const axios = require('axios');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;
const API_KEY = process.env.API_KEY || "4c2a55097034407ba34237db87595305"; 
const SECRET_KEY = process.env.JWT_SECRET || "secret_key_123"; 

app.use(express.json());

// Helper function to read/write users
const getUsers = () => {
    if (!fs.existsSync('users.json')) return [];
    try {
        const data = fs.readFileSync('users.json', 'utf-8');
        return data ? JSON.parse(data) : [];
    } catch (e) { return []; }
};

const saveUsers = (users) => {
    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
};

// Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (!token) return res.status(401).send({ error: "Token missing" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).send({ error: "Invalid token" });
        req.user = user;
        next();
    });
};

// --- ROUTES ---

// 1. REGISTER
app.post('/users/signup', async (req, res) => {
    const { name, email, password, preferences } = req.body;
    if (!name || !email || !password) return res.status(400).send({ error: 'Missing fields' });

    let users = getUsers();
    if (users.find(u => u.email === email)) return res.status(400).send({ error: 'User exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: Date.now(), name, email, password: hashedPassword, preferences: preferences || [] };
    
    users.push(newUser);
    saveUsers(users);
    res.status(201).send({ message: 'User registered', user: newUser });
});

// 2. LOGIN
app.post('/users/login', async (req, res) => {
    const { email, password } = req.body;
    const users = getUsers();
    const user = users.find(u => u.email === email);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).send({ token });
});

// 3. PREFERENCES
app.get('/users/preferences', authenticateToken, (req, res) => {
    const users = getUsers();
    const user = users.find(u => u.id === req.user.id);
    res.status(200).send({ preferences: user ? user.preferences : [] });
});

app.put('/users/preferences', authenticateToken, (req, res) => {
    const { preferences } = req.body;
    if (!Array.isArray(preferences)) return res.status(400).send({ error: 'Must be array' });

    let users = getUsers();
    const idx = users.findIndex(u => u.id === req.user.id);
    if (idx === -1) return res.status(404).send({ error: 'User not found' });

    users[idx].preferences = preferences;
    saveUsers(users);
    res.status(200).send({ message: "Updated", preferences });
});

// 4. NEWS
app.get('/news', authenticateToken, async (req, res) => {
    const users = getUsers();
    const user = users.find(u => u.id === req.user.id);
    
    let url = `https://newsapi.org/v2/top-headlines?country=in&apiKey=${API_KEY}`;
    if (user && user.preferences?.length > 0) {
        url = `https://newsapi.org/v2/everything?q=${user.preferences.join(' OR ')}&apiKey=${API_KEY}`;
    }

    try {
        const response = await axios.get(url);
        res.status(200).json({ articles: response.data.articles });
    } catch (error) {
        res.status(500).json({ error: "News API failed" });
    }
});

app.listen(port, () => console.log(`Server on ${port}`));
module.exports = app;
