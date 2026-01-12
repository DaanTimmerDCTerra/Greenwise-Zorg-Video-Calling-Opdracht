const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();
const PORT = 3000;
const SECRET_KEY = 'secret-key-change-me';

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Database Setup
const db = new sqlite3.Database('./database.db'); // Persistent file storage

db.serialize(() => {
    // Create Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        avatar TEXT,
        description TEXT DEFAULT 'description test',
        guide_seen INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        content TEXT,
        timestamp TEXT,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )`);

    // Insert Default User (Zorg) if not exists
    db.get("SELECT id FROM users WHERE username = 'Zorg'", (err, row) => {
        if (!row) {
             const stmt = db.prepare("INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)");
             const hash = bcrypt.hashSync('password', 8);
             stmt.run('Zorg', hash, 'https://ui-avatars.com/api/?name=Zorg&background=random');
             stmt.finalize();
        }
    });
});

// Routes

// Register
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 8);
    const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=0D8ABC&color=fff`;

    db.run(`INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)`, 
        [username, hash, avatar], 
        function(err) {
            if (err) return res.status(500).json({ error: "Gebruikersnaam bestaat al of er is een fout opgetreden." });
            
            // Auto Login
            const token = jwt.sign({ id: this.lastID }, SECRET_KEY, { expiresIn: '24h' });
            res.json({ auth: true, token, user: { id: this.lastID, username, avatar, description: 'description test' } });
        }
    );
});

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) return res.status(500).json({ error: "Serverfout" });
        if (!user) return res.status(404).json({ error: "Gebruiker niet gevonden" });

        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) return res.status(401).json({ auth: false, token: null, error: "Wachtwoord ongeldig" });

        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ auth: true, token, user: { id: user.id, username: user.username, avatar: user.avatar, description: user.description, guide_seen: user.guide_seen } });
    });
});

// Guide Seen
app.put('/api/users/guide_seen', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(401).json({ auth: false });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(500).json({ auth: false });
        db.run(`UPDATE users SET guide_seen = 1 WHERE id = ?`, [decoded.id], (err) => {
            res.json({ success: true });
        });
    });
});

// Messages
app.get('/api/messages/:otherId', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(401).send();
    
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if(err) return res.status(401).send();
        
        const myId = decoded.id;
        const otherId = req.params.otherId;
        
        db.all(`SELECT * FROM messages 
                WHERE (sender_id = ? AND receiver_id = ?) 
                   OR (sender_id = ? AND receiver_id = ?) 
                ORDER BY id ASC`, 
                [myId, otherId, otherId, myId], 
                (err, rows) => {
                    if(err) res.status(500).send();
                    else res.json(rows);
                });
    });
});

app.post('/api/messages', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(401).send();
    
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if(err) return res.status(401).send();
        
        const { receiver_id, content, timestamp } = req.body;
        db.run(`INSERT INTO messages (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, ?)`,
            [decoded.id, receiver_id, content, timestamp],
            function(err) {
                if(err) res.status(500).send();
                else res.json({ success: true, id: this.lastID });
            });
    });
});

app.delete('/api/messages/:id', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(401).send();

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if(err) return res.status(401).send();

        // Only allow deleting own messages
        db.run(`DELETE FROM messages WHERE id = ? AND sender_id = ?`, 
            [req.params.id, decoded.id], 
            function(err) {
                if(err) return res.status(500).send();
                if(this.changes === 0) return res.status(403).send("Not allowed or not found");
                res.json({ success: true });
            });
    });
});

// Update Profile
app.put('/api/users/me', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(401).json({ auth: false, message: 'Geen token aangeboden.' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(500).json({ auth: false, message: 'Fout bij authenticeren van token.' });

        const { username, avatar, description, password } = req.body;
        
        let query = "UPDATE users SET username = ?, avatar = ?, description = ?";
        let params = [username, avatar, description];

        if (password && password.trim() !== "") {
            query += ", password = ?";
            params.push(bcrypt.hashSync(password, 8));
        }

        query += " WHERE id = ?";
        params.push(decoded.id);

        db.run(query, params, function(err) {
            if (err) {
                console.error(err);
                if(err.message.includes('UNIQUE')) return res.status(400).json({ error: "Gebruikersnaam is al in gebruik" });
                return res.status(500).json({ error: "Update mislukt" });
            }
            res.json({ success: true });
        });
    });
});

// Get User Info
app.get('/api/users/:id', (req, res) => {
    db.get(`SELECT id, username, avatar, description FROM users WHERE id = ?`, [req.params.id], (err, user) => {
        if(err || !user) return res.status(404).send("Not found");
        res.json(user);
    });
});

// Get All Users (for sidebar)
app.get('/api/users', (req, res) => {
    db.all(`SELECT id as Id, username as Name, avatar as Avatar, description as Description FROM users`, [], (err, rows) => {
        if(err) return res.status(500).json([]);
        res.json(rows);
    });
});

app.listen(PORT, () => {
    console.log(`Server draait op http://localhost:${PORT}`);
});
