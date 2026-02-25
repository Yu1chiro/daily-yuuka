require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const ImageKit = require('imagekit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. GLOBAL MIDDLEWARE
// ==========================================
app.use(cors()); // Mengizinkan request dari domain lain (jika frontend & backend dipisah nantinya)
app.use(express.json({ limit: '10mb' })); // Limit diperbesar untuk handling base64 image
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Konfigurasi static folder agar URL tanpa .html (misal: /auth/signin) bisa otomatis terbaca
app.use(express.static(path.join(__dirname, 'public'), {
    extensions: ['html'] 
}));

// ==========================================
// 2. CONFIGURATIONS (DB & IMAGEKIT)
// ==========================================
// Database Pool (NeonDB - PostgreSQL)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Wajib untuk NeonDB
});

// ImageKit Initialization
const imagekit = new ImageKit({
    publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
    privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
    urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT
});

// ==========================================
// 3. AUTH MIDDLEWARE (BEST PRACTICE)
// ==========================================
const authenticateToken = (req, res, next) => {
    // Mengambil token dari header 'Authorization: Bearer <token>'
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access Denied. No token provided.' });
    }

    // Verifikasi Token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }
        req.user = user; // Menyimpan data user ke request untuk dipakai di route selanjutnya
        next(); // Melanjutkan ke controller
    });
};

// ==========================================
// 4. AUTHENTICATION ROUTES
// ==========================================
// Register
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, confirmPassword, birthday } = req.body;
    
    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash, birthday) VALUES ($1, $2, $3, $4) RETURNING id, username, email',
            [username, email, hashedPassword, birthday]
        );
        res.status(201).json({ message: 'User registered successfully', user: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed. Username or email might already exist.' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { identifier, password } = req.body;
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $1',
            [identifier]
        );
        const user = result.rows[0];
        
        if (!user) return res.status(400).json({ error: 'User not found' });

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

        // Generate JWT Token (Expired dalam 24 Jam)
        const token = jwt.sign(
            { id: user.id, username: user.username }, 
            process.env.JWT_SECRET, 
            { expiresIn: '24h' }
        );
        
        res.json({ token, message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ error: 'Login failed due to server error.' });
    }
});

// Recover Password
app.post('/api/auth/recover', async (req, res) => {
    const { identifier, birthday, newPassword } = req.body;
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE (username = $1 OR email = $1) AND birthday = $2',
            [identifier, birthday]
        );
        const user = result.rows[0];
        
        if (!user) return res.status(400).json({ error: 'Invalid credentials or birthday' });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, user.id]);
        
        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Recovery failed due to server error.' });
    }
});

// ==========================================
// 5. PROTECTED ROUTES (Requires Auth Middleware)
// ==========================================
// Fetch Logged-in User Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT name, quotes, profile_image_url FROM users WHERE id = $1', 
            [req.user.id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Update Profile & Upload Image
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    const { name, quotes, imageBase64 } = req.body;
    try {
        let imageUrl = null;
        
        // Upload to ImageKit if base64 image is provided
        if (imageBase64) {
            const uploadResponse = await imagekit.upload({
                file: imageBase64,
                fileName: `profile_${req.user.id}_${Date.now()}.jpg`,
                folder: '/litlink_profiles'
            });
            imageUrl = uploadResponse.url;
        }

        const currentProfile = await pool.query('SELECT profile_image_url FROM users WHERE id = $1', [req.user.id]);
        const finalImageUrl = imageUrl || currentProfile.rows[0].profile_image_url;

        await pool.query(
            'UPDATE users SET name = $1, quotes = $2, profile_image_url = $3 WHERE id = $4',
            [name, quotes, finalImageUrl, req.user.id]
        );
        
        res.json({ message: 'Profile updated successfully', imageUrl: finalImageUrl });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Get User Links
app.get('/api/links', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, title, url FROM links WHERE user_id = $1 ORDER BY id DESC', 
            [req.user.id]
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch links' });
    }
});

// Create New Link
app.post('/api/links', authenticateToken, async (req, res) => {
    const { title, url } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO links (user_id, title, url) VALUES ($1, $2, $3) RETURNING *',
            [req.user.id, title, url]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create link' });
    }
});

// Delete Link
app.delete('/api/links/:id', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM links WHERE id = $1 AND user_id = $2', 
            [req.params.id, req.user.id]
        );
        res.json({ message: 'Link deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete link' });
    }
});

// ==========================================
// 6. PUBLIC ROUTES (No Auth Required)
// ==========================================
// Endpoint ini wajib agar halaman Linktree bisa dilihat pengunjung publik
app.get('/api/u/:username', async (req, res) => {
    try {
        // Cari user berdasarkan username
        const userResult = await pool.query(
            'SELECT id, name, quotes, profile_image_url FROM users WHERE username = $1', 
            [req.params.username]
        );
        const user = userResult.rows[0];
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Ambil link milik user tersebut
        const linksResult = await pool.query(
            'SELECT id, title, url FROM links WHERE user_id = $1 ORDER BY id DESC', 
            [user.id]
        );

        res.json({
            profile: user,
            links: linksResult.rows
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error while fetching public profile' });
    }
});
// Route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin", "admin.html"));
});
app.get("/auth/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "auth", "register.html"));
});
app.get("/auth/signin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "auth", "signin.html"));
});
// ==========================================
// 7. START SERVER
// ==========================================
    app.listen(PORT, () => {
        console.log(`🚀 Server is running on http://localhost:${PORT}`);
    });

