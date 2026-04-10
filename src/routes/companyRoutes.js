const express = require('express');
const {
    createCompany,
    getCompanies,
    getCompanyById,
    updateCompany,
    deleteCompany
} = require('../controllers/companyController');
const { authenticateToken, authorizeRoles } = require('../middlewares/authMiddleware');
const { upload } = require('../utils/cloudinaryConfig');

const router = express.Router();

// Middleware to check if user has access to this company
const checkCompanyAccess = (req, res, next) => {
    if (req.user.role === 'SUPERADMIN') return next();
    if (req.user.role === 'COMPANY' && req.user.companyId === parseInt(req.params.id)) return next();
    return res.status(403).json({ message: 'Access denied: You do not have permission to access this company' });
};

// Only Superadmin can create or delete companies
router.post('/', authenticateToken, authorizeRoles('SUPERADMIN'), upload.single('logo'), createCompany);
router.get('/', authenticateToken, authorizeRoles('SUPERADMIN'), getCompanies);
router.delete('/:id', authenticateToken, authorizeRoles('SUPERADMIN'), deleteCompany);

// Both Superadmin and Company Admin can view/update their own company
router.get('/:id', authenticateToken, checkCompanyAccess, getCompanyById);
router.put('/:id', authenticateToken, checkCompanyAccess, upload.fields([{ name: 'logo', maxCount: 1 }, { name: 'invoiceLogo', maxCount: 1 }]), updateCompany);

module.exports = router;
