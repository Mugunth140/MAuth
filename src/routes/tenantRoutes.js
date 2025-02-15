const express = require('express');
const tenantController = require('../controllers/tenantController');
const authMiddleware = require('../middleware/authMiddleware');
const roleMiddleware = require('../middleware/roleMiddleware');

const router = express.Router();

// Create a new tenant (Admin only)
router.post(
    '/tenants',
    authMiddleware.authenticate,
    roleMiddleware.checkRole(['admin']),
    tenantController.createTenant
);

// Assign a user to a tenant (Admin only)
router.post(
    '/tenants/assign-user',
    authMiddleware.authenticate,
    roleMiddleware.checkRole(['admin']),
    tenantController.assignUserToTenant
);

// Get all tenants (Admin only)
router.get(
    '/tenants',
    authMiddleware.authenticate,
    roleMiddleware.checkRole(['admin']),
    tenantController.getAllTenants
);

// Get a single tenant by ID (Admin only)
router.get(
    '/tenants/:tenantId',
    authMiddleware.authenticate,
    roleMiddleware.checkRole(['admin']),
    tenantController.getTenantById
);

// Update a tenant (Admin only)
router.put(
    '/tenants/:tenantId',
    authMiddleware.authenticate,
    roleMiddleware.checkRole(['admin']),
    tenantController.updateTenant
);

// Delete a tenant (Admin only)
router.delete(
    '/tenants/:tenantId',
    authMiddleware.authenticate,
    roleMiddleware.checkRole(['admin']),
    tenantController.deleteTenant
);

module.exports = router;