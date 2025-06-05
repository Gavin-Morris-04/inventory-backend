// server.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();

// Security middleware
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Auth rate limiting (stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later'
});
app.use('/api/auth/', authLimiter);

// JWT middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user with company info
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      include: { company: true }
    });

    if (!user || !user.isActive || !user.company.isActive) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Check if trial has expired
    if (user.company.subscriptionTier === 'trial' && new Date() > new Date(user.company.trialEndsAt)) {
      return res.status(403).json({ error: 'Trial period has expired. Please upgrade your subscription.' });
    }

    req.user = user;
    req.companyId = user.companyId;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Generate company code
const generateCompanyCode = (companyName) => {
  const prefix = companyName
    .split(' ')
    .map(word => word[0])
    .join('')
    .toUpperCase()
    .slice(0, 3);
  const suffix = Math.random().toString(36).substring(2, 5).toUpperCase();
  return `${prefix}${suffix}`;
};

// ROUTES

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// Company Registration
app.post('/api/companies/register', async (req, res) => {
  try {
    const { companyName, adminEmail, adminPassword, adminName } = req.body;

    if (!companyName || !adminEmail || !adminPassword || !adminName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if email already exists in any company
    const existingUser = await prisma.user.findFirst({
      where: { email: adminEmail.toLowerCase() }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Generate unique company code
    let companyCode = generateCompanyCode(companyName);
    let codeExists = await prisma.company.findUnique({ where: { code: companyCode } });
    while (codeExists) {
      companyCode = generateCompanyCode(companyName);
      codeExists = await prisma.company.findUnique({ where: { code: companyCode } });
    }

    // Create company and admin user in a transaction
    const result = await prisma.$transaction(async (tx) => {
      // Create company
      const company = await tx.company.create({
        data: {
          name: companyName,
          code: companyCode,
          subscriptionTier: 'trial'
        }
      });

      // Create admin user
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      const user = await tx.user.create({
        data: {
          email: adminEmail.toLowerCase(),
          password: hashedPassword,
          name: adminName,
          role: 'admin',
          companyId: company.id
        }
      });

      return { company, user };
    });

    // Generate token
    const token = jwt.sign(
      { userId: result.user.id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: result.user.id,
        email: result.user.email,
        name: result.user.name,
        role: result.user.role
      },
      company: {
        id: result.company.id,
        name: result.company.name,
        code: result.company.code,
        subscriptionTier: result.company.subscriptionTier
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to register company' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Find user and include company
    const user = await prisma.user.findFirst({
      where: { 
        email: email.toLowerCase(),
        isActive: true
      },
      include: { company: true }
    });

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (!user.company.isActive) {
      return res.status(403).json({ error: 'Company account is suspended' });
    }

    // Update last login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() }
    });

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      },
      company: {
        id: user.company.id,
        name: user.company.name,
        code: user.company.code,
        subscriptionTier: user.company.subscriptionTier,
        maxUsers: user.company.maxUsers
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get company info
app.get('/api/companies/info', authenticateToken, async (req, res) => {
  try {
    const company = await prisma.company.findUnique({
      where: { id: req.companyId },
      include: {
        _count: {
          select: { users: true, items: true }
        }
      }
    });

    res.json({
      company: {
        ...company,
        userCount: company._count.users,
        itemCount: company._count.items
      }
    });
  } catch (error) {
    console.error('Error fetching company info:', error);
    res.status(500).json({ error: 'Failed to fetch company info' });
  }
});

// Items routes
app.get('/api/items', authenticateToken, async (req, res) => {
  try {
    const items = await prisma.item.findMany({
      where: { companyId: req.companyId },
      orderBy: { createdAt: 'desc' }
    });
    res.json(items);
  } catch (error) {
    console.error('Error fetching items:', error);
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

app.post('/api/items', authenticateToken, async (req, res) => {
  try {
    const { name, quantity, barcode } = req.body;

    if (!name || quantity === undefined) {
      return res.status(400).json({ error: 'Name and quantity required' });
    }

    // Check if barcode exists in company
    const existingItem = await prisma.item.findFirst({
      where: {
        barcode,
        companyId: req.companyId
      }
    });

    if (existingItem) {
      return res.status(400).json({ error: 'Barcode already exists' });
    }

    // Create item and activity in transaction
    const result = await prisma.$transaction(async (tx) => {
      const item = await tx.item.create({
        data: {
          name: name.trim(),
          quantity: parseInt(quantity),
          barcode,
          companyId: req.companyId
        }
      });

      await tx.activity.create({
        data: {
          type: 'created',
          quantity: parseInt(quantity),
          userId: req.user.id,
          itemId: item.id,
          companyId: req.companyId
        }
      });

      return item;
    });

    res.status(201).json(result);
  } catch (error) {
    console.error('Error creating item:', error);
    res.status(500).json({ error: 'Failed to create item' });
  }
});

app.put('/api/items', authenticateToken, async (req, res) => {
  try {
    const { id, quantity } = req.body;

    if (!id || quantity === undefined) {
      return res.status(400).json({ error: 'ID and quantity required' });
    }

    // Get current item
    const currentItem = await prisma.item.findFirst({
      where: {
        id,
        companyId: req.companyId
      }
    });

    if (!currentItem) {
      return res.status(404).json({ error: 'Item not found' });
    }

    const oldQuantity = currentItem.quantity;
    const quantityChange = parseInt(quantity) - oldQuantity;

    // Update item and create activity in transaction
    const result = await prisma.$transaction(async (tx) => {
      const item = await tx.item.update({
        where: { id },
        data: { quantity: parseInt(quantity) }
      });

      if (quantityChange !== 0) {
        await tx.activity.create({
          data: {
            type: quantityChange > 0 ? 'added' : 'removed',
            quantity: Math.abs(quantityChange),
            oldQuantity,
            userId: req.user.id,
            itemId: item.id,
            companyId: req.companyId
          }
        });
      }

      return item;
    });

    res.json(result);
  } catch (error) {
    console.error('Error updating item:', error);
    res.status(500).json({ error: 'Failed to update item' });
  }
});

app.delete('/api/items', authenticateToken, async (req, res) => {
  try {
    const { id } = req.body;

    if (!id) {
      return res.status(400).json({ error: 'ID required' });
    }

    // Get item before deletion
    const item = await prisma.item.findFirst({
      where: {
        id,
        companyId: req.companyId
      }
    });

    if (!item) {
      return res.status(404).json({ error: 'Item not found' });
    }

    // Create deletion activity then delete item
    await prisma.$transaction(async (tx) => {
      await tx.activity.create({
        data: {
          type: 'deleted',
          quantity: item.quantity,
          userId: req.user.id,
          itemId: item.id,
          companyId: req.companyId,
          notes: `Deleted item: ${item.name}`
        }
      });

      await tx.item.delete({
        where: { id }
      });
    });

    res.json({ success: true, message: 'Item deleted' });
  } catch (error) {
    console.error('Error deleting item:', error);
    res.status(500).json({ error: 'Failed to delete item' });
  }
});

app.get('/api/items/search', authenticateToken, async (req, res) => {
  try {
    const { barcode } = req.query;

    if (!barcode) {
      return res.status(400).json({ error: 'Barcode required' });
    }

    const item = await prisma.item.findFirst({
      where: {
        barcode,
        companyId: req.companyId
      }
    });

    if (!item) {
      return res.status(404).json({ error: 'Item not found' });
    }

    res.json(item);
  } catch (error) {
    console.error('Error searching item:', error);
    res.status(500).json({ error: 'Failed to search item' });
  }
});

// Activities
app.get('/api/activities', authenticateToken, async (req, res) => {
  try {
    const { limit = 100 } = req.query;

    const activities = await prisma.activity.findMany({
      where: { companyId: req.companyId },
      include: {
        user: {
          select: { name: true, email: true }
        },
        item: {
          select: { name: true, barcode: true }
        }
      },
      orderBy: { createdAt: 'desc' },
      take: parseInt(limit)
    });

    // Format response
    const formattedActivities = activities.map(activity => ({
      id: activity.id,
      type: activity.type,
      quantity: activity.quantity,
      oldQuantity: activity.oldQuantity,
      itemName: activity.item.name,
      userName: activity.user.name,
      createdAt: activity.createdAt
    }));

    res.json(formattedActivities);
  } catch (error) {
    console.error('Error fetching activities:', error);
    res.status(500).json({ error: 'Failed to fetch activities' });
  }
});

// User management (Admin only)
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      where: { companyId: req.companyId },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isActive: true,
        lastLogin: true,
        createdAt: true
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users/invite', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { email, name, role = 'user' } = req.body;

    if (!email || !name) {
      return res.status(400).json({ error: 'Email and name required' });
    }

    // Check if user already exists in company
    const existingUser = await prisma.user.findFirst({
      where: {
        email: email.toLowerCase(),
        companyId: req.companyId
      }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists in company' });
    }

    // Check user limit
    const userCount = await prisma.user.count({
      where: { companyId: req.companyId }
    });

    if (userCount >= req.user.company.maxUsers) {
      return res.status(403).json({ error: 'User limit reached. Please upgrade your plan.' });
    }

    // Create invitation
    const invitation = await prisma.invitation.create({
      data: {
        email: email.toLowerCase(),
        name,
        role,
        token: uuidv4(),
        companyId: req.companyId
      }
    });

    // TODO: Send invitation email
    // await sendInvitationEmail(email, name, invitation.token);

    res.json({
      success: true,
      message: 'Invitation sent successfully',
      invitationId: invitation.id
    });
  } catch (error) {
    console.error('Error inviting user:', error);
    res.status(500).json({ error: 'Failed to invite user' });
  }
});

app.delete('/api/users/delete', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'User ID required' });
    }

    // Prevent self-deletion
    if (userId === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    // Ensure user belongs to same company
    const user = await prisma.user.findFirst({
      where: {
        id: userId,
        companyId: req.companyId
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Soft delete (mark as inactive)
    await prisma.user.update({
      where: { id: userId },
      data: { isActive: false }
    });

    res.json({ success: true, message: 'User removed successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Analytics
app.get('/api/analytics', authenticateToken, async (req, res) => {
  try {
    const [itemStats, activityStats, userStats] = await Promise.all([
      // Item statistics
      prisma.item.aggregate({
        where: { companyId: req.companyId },
        _count: true,
        _sum: { quantity: true }
      }),
      
      // Activity statistics (last 30 days)
      prisma.activity.groupBy({
        by: ['type'],
        where: {
          companyId: req.companyId,
          createdAt: {
            gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
          }
        },
        _count: true
      }),
      
      // User statistics
      prisma.user.aggregate({
        where: { 
          companyId: req.companyId,
          isActive: true 
        },
        _count: true
      })
    ]);

    // Low stock items
    const lowStockItems = await prisma.item.count({
      where: {
        companyId: req.companyId,
        quantity: { lte: 5, gt: 0 }
      }
    });

    const outOfStockItems = await prisma.item.count({
      where: {
        companyId: req.companyId,
        quantity: 0
      }
    });

    res.json({
      items: {
        total: itemStats._count,
        totalQuantity: itemStats._sum.quantity || 0,
        lowStock: lowStockItems,
        outOfStock: outOfStockItems
      },
      activities: activityStats,
      users: {
        total: userStats._count
      }
    });
  } catch (error) {
    console.error('Error fetching analytics:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Multi-tenant server running on port ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await prisma.$disconnect();
  process.exit(0);
});