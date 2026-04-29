const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied: Insufficient permissions' });
        }
        next();
    };
};

const authorizePermissions = (requiredPermission) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Authentication required' });
        }

        // Superadmin and Company Owner bypass all permission checks
        if (req.user.role === 'SUPERADMIN' || req.user.role === 'COMPANY') {
            return next();
        }

        const permissions = req.user.permissions || [];
        
        if (!permissions.includes(requiredPermission)) {
            return res.status(403).json({ 
                message: `Access denied: You do not have permission to ${requiredPermission}`,
                requiredPermission 
            });
        }

        next();
    };
};

module.exports = { authenticateToken, authorizeRoles, authorizePermissions };
