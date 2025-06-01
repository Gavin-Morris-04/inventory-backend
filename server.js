// Alternative server.js - Uses query parameters instead of route parameters
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Create SQLite database
const dbPath = path.join(__dirname, 'inventory.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Error opening database:', err.message);
    process.exit(1);
  } else {
    console.log('🗄️  SQLite database connected:', dbPath);
  }
});

// Initialize database
const initDatabase = () => {
  console.log('🔧 Setting up database tables...');
  
  db.run('PRAGMA foreign_keys = ON');
  
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 0,
      barcode TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      UNIQUE(user_id, barcode)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS activities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      item_name TEXT NOT NULL,
      type TEXT NOT NULL,
      quantity INTEGER,
      old_quantity INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
  
  // Create demo user
  const demoEmail = 'demo@inventory.com';
  const demoPassword = bcrypt.hashSync('demo123', 10);
  
  db.get('SELECT * FROM users WHERE email = ?', [demoEmail], (err, row) => {
    if (!row) {
      db.run(
        'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
        [demoEmail, demoPassword, 'Demo User'],
        function(err) {
          if (!err) {
            console.log('✅ Demo user created: demo@inventory.com / demo123');
          }
        }
      );
    }
  });
  
  console.log('✅ Database tables ready');
};

initDatabase();

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://127.0.0.1:3000', 
    'http://localhost:8080',
    /\.railway\.app$/,  // Allow all Railway subdomains
    /\.vercel\.app$/,   // Allow Vercel if you deploy frontend there
    /\.netlify\.app$/   // Allow Netlify if you deploy frontend there
  ],
  credentials: true
}));
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, 'fallback-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Helper
const generateBarcode = (id) => 'INV' + id.toString().padStart(6, '0');

// ROUTES - No route parameters, using query strings and body data instead

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: 'SQLite'
  });
});

// Auth routes
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (row) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      
      const hashedPassword = await bcrypt.hash(password, 12);
      
      db.run(
        'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
        [email.toLowerCase(), hashedPassword, name],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          const token = jwt.sign({ userId: this.lastID }, 'fallback-secret-key', { expiresIn: '7d' });
          
          res.status(201).json({
            success: true,
            user: { id: this.lastID, email: email.toLowerCase(), name },
            token
          });
        }
      );
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      
      const token = jwt.sign({ userId: user.id }, 'fallback-secret-key', { expiresIn: '7d' });
      
      res.json({
        success: true,
        user: { id: user.id, email: user.email, name: user.name },
        token
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Items routes - using query parameters instead of route parameters
app.get('/api/items', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.userId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to get items' });
      }
      res.json(rows);
    }
  );
});

app.post('/api/items', authenticateToken, (req, res) => {
  const { name, quantity, barcode } = req.body;
  
  if (!name || quantity === undefined) {
    return res.status(400).json({ error: 'Name and quantity required' });
  }
  
  const itemBarcode = barcode || generateBarcode(Date.now());
  
  db.run(
    'INSERT INTO items (user_id, name, quantity, barcode) VALUES (?, ?, ?, ?)',
    [req.user.userId, name.trim(), parseInt(quantity), itemBarcode],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint')) {
          return res.status(400).json({ error: 'Barcode already exists' });
        }
        return res.status(500).json({ error: 'Failed to create item' });
      }
      
      db.run(
        'INSERT INTO activities (user_id, item_name, type, quantity) VALUES (?, ?, ?, ?)',
        [req.user.userId, name.trim(), 'created', parseInt(quantity)]
      );
      
      db.get('SELECT * FROM items WHERE id = ?', [this.lastID], (err, row) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to get created item' });
        }
        res.status(201).json(row);
      });
    }
  );
});

// Update item - using query parameter ?id=123
app.put('/api/items', authenticateToken, (req, res) => {
  const { id, quantity } = req.body;
  
  if (!id || quantity === undefined) {
    return res.status(400).json({ error: 'ID and quantity required' });
  }
  
  db.get(
    'SELECT * FROM items WHERE id = ? AND user_id = ?',
    [id, req.user.userId],
    (err, item) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!item) {
        return res.status(404).json({ error: 'Item not found' });
      }
      
      const oldQuantity = item.quantity;
      const quantityChange = parseInt(quantity) - oldQuantity;
      
      db.run(
        'UPDATE items SET quantity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
        [parseInt(quantity), id, req.user.userId],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to update item' });
          }
          
          if (quantityChange !== 0) {
            const activityType = quantityChange > 0 ? 'added' : 'removed';
            db.run(
              'INSERT INTO activities (user_id, item_name, type, quantity, old_quantity) VALUES (?, ?, ?, ?, ?)',
              [req.user.userId, item.name, activityType, Math.abs(quantityChange), oldQuantity]
            );
          }
          
          db.get('SELECT * FROM items WHERE id = ?', [id], (err, updatedItem) => {
            if (err) {
              return res.status(500).json({ error: 'Failed to get updated item' });
            }
            res.json(updatedItem);
          });
        }
      );
    }
  );
});

// Delete item - using query parameter
app.delete('/api/items', authenticateToken, (req, res) => {
  const { id } = req.body;
  
  if (!id) {
    return res.status(400).json({ error: 'ID required' });
  }
  
  db.get(
    'SELECT * FROM items WHERE id = ? AND user_id = ?',
    [id, req.user.userId],
    (err, item) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!item) {
        return res.status(404).json({ error: 'Item not found' });
      }
      
      db.run(
        'DELETE FROM items WHERE id = ? AND user_id = ?',
        [id, req.user.userId],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to delete item' });
          }
          
          db.run(
            'INSERT INTO activities (user_id, item_name, type, quantity) VALUES (?, ?, ?, ?)',
            [req.user.userId, item.name, 'deleted', item.quantity]
          );
          
          res.json({ success: true, message: 'Item deleted' });
        }
      );
    }
  );
});

// Find item by barcode - using query parameter ?barcode=INV000001
app.get('/api/items/search', authenticateToken, (req, res) => {
  const { barcode } = req.query;
  
  if (!barcode) {
    return res.status(400).json({ error: 'Barcode required' });
  }
  
  db.get(
    'SELECT * FROM items WHERE user_id = ? AND barcode = ?',
    [req.user.userId, barcode],
    (err, item) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!item) {
        return res.status(404).json({ error: 'Item not found' });
      }
      
      res.json(item);
    }
  );
});

// Activities
app.get('/api/activities', authenticateToken, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  
  db.all(
    'SELECT * FROM activities WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
    [req.user.userId, limit],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to get activities' });
      }
      res.json(rows);
    }
  );
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
  console.log(`💾 Database: ${dbPath}`);
});