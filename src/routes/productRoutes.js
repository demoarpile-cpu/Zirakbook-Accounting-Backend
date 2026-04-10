const express = require('express');
const router = express.Router();
const productController = require('../controllers/productController');
const { authenticateToken } = require('../middlewares/authMiddleware');



router.get('/', authenticateToken, productController.getProducts);
router.get('/upload-signature', authenticateToken, productController.getCloudinarySignature);
router.get('/:id', authenticateToken, productController.getProductById);
router.post('/', authenticateToken, productController.createProduct);
router.put('/:id', authenticateToken, productController.updateProduct);
router.delete('/:id', authenticateToken, productController.deleteProduct);

module.exports = router;