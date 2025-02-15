const Tenant = require('../models/tenant');
const User = require('../models/User');

// Create a new tenant
exports.createTenant = async (req, res) => {
    const { name, domain } = req.body;

    try {
        // Check if the domain is already in use
        const existingTenant = await Tenant.findOne({ domain });
        if (existingTenant) {
            return res.status(400).json({ error: 'Domain already in use' });
        }

        // Create the tenant
        const tenant = new Tenant({ name, domain });
        await tenant.save();

        res.status(201).json({ message: 'Tenant created successfully', tenant });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Assign a user to a tenant
exports.assignUserToTenant = async (req, res) => {
    const { userId, tenantId } = req.body;

    try {
        // Find the user and tenant
        const user = await User.findById(userId);
        const tenant = await Tenant.findById(tenantId);

        if (!user || !tenant) {
            return res.status(404).json({ error: 'User or Tenant not found' });
        }

        // Assign the tenant to the user
        user.tenantId = tenantId;
        await user.save();

        res.json({ message: 'User assigned to tenant successfully', user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Get all tenants
exports.getAllTenants = async (req, res) => {
    try {
        const tenants = await Tenant.find();
        res.json({ tenants });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Get a single tenant by ID
exports.getTenantById = async (req, res) => {
    const { tenantId } = req.params;

    try {
        const tenant = await Tenant.findById(tenantId);
        if (!tenant) {
            return res.status(404).json({ error: 'Tenant not found' });
        }

        res.json({ tenant });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Update a tenant
exports.updateTenant = async (req, res) => {
    const { tenantId } = req.params;
    const { name, domain } = req.body;

    try {
        const tenant = await Tenant.findById(tenantId);
        if (!tenant) {
            return res.status(404).json({ error: 'Tenant not found' });
        }

        // Update tenant fields
        if (name) tenant.name = name;
        if (domain) tenant.domain = domain;

        await tenant.save();
        res.json({ message: 'Tenant updated successfully', tenant });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Delete a tenant
exports.deleteTenant = async (req, res) => {
    const { tenantId } = req.params;

    try {
        const tenant = await Tenant.findByIdAndDelete(tenantId);
        if (!tenant) {
            return res.status(404).json({ error: 'Tenant not found' });
        }

        res.json({ message: 'Tenant deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};