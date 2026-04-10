const express = require('express');
const router = express.Router();
const vendorController = require('../controllers/vendorController');
const { authenticateToken } = require('../middlewares/authMiddleware');

// Protect all routes
router.use(authenticateToken);

// CRUD Routes
router.post('/', vendorController.createVendor);
router.get('/', vendorController.getAllVendors);
router.get('/:id', vendorController.getVendorById);
router.get('/statement/:id', vendorController.getVendorStatement);
router.put('/:id', vendorController.updateVendor);
router.delete('/:id', vendorController.deleteVendor);

module.exports = router;
