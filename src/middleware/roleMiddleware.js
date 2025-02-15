// Assign Role to User
exports.assignRole = async (req, res) => {
    const { userId, role } = req.body;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!user.roles.includes(role)) {
            user.roles.push(role);
            await user.save();
        }

        res.json({ message: 'Role assigned successfully', user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * Role-based access control middleware
 * @param {string[]} roles - Allowed roles (e.g., ['admin', 'moderator'])
 * @returns {function} - Middleware function
 */
exports.checkRole = (roles) => (req, res, next) => {
    const user = req.user; // User object attached by authMiddleware

    if (!user || !roles.includes(user.role)) {
        return res.status(403).json({ error: 'Access denied' });
    }

    next(); // Allow access if the user has the required role
};