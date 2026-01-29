const pool = require('../config/db');

// @desc    Get all permissions
// @route   GET /api/v1/superadmin/permissions
// @access  Private (SuperAdmin)
const getAllPermissions = async (req, res) => {
    try {
        const [permissions] = await pool.query('SELECT * FROM permissions');
        res.json({ success: true, data: permissions });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

// @desc    Get user permission overrides
// @route   GET /api/v1/superadmin/users/:id/permissions
// @route   GET /api/v1/permission-management/users/:id
// @access  Private (SuperAdmin)
const getUserPermissions = async (req, res) => {
    try {
        const userId = req.params.id;

        // Get user's role first
        const [users] = await pool.query('SELECT role FROM users WHERE id = ?', [userId]);
        const userRole = users[0]?.role || 'User';

        // Get user-specific permission overrides
        const [userPerms] = await pool.query(
            'SELECT p.name, up.type FROM user_permissions up JOIN permissions p ON up.permissionId = p.id WHERE up.userId = ?',
            [userId]
        );

        // Get role-based permissions
        const [rolePerms] = await pool.query(
            'SELECT p.name FROM role_permissions rp JOIN permissions p ON rp.permissionId = p.id WHERE rp.role = ?',
            [userRole]
        );

        // Separate into grant and revoke lists
        const grantedPermissions = userPerms
            .filter(up => up.type === 'grant')
            .map(up => up.name);

        const revokedPermissions = userPerms
            .filter(up => up.type === 'revoke')
            .map(up => up.name);

        const rolePermissions = rolePerms.map(rp => rp.name);

        // Calculate effective permissions: role permissions + grants - revokes
        const roleSet = new Set(rolePermissions);
        const revokeSet = new Set(revokedPermissions);

        // Start with role permissions
        const effectiveSet = new Set(rolePermissions);

        // Add grants
        grantedPermissions.forEach(p => effectiveSet.add(p));

        // Remove revokes
        revokedPermissions.forEach(p => effectiveSet.delete(p));

        const effectivePermissions = Array.from(effectiveSet);

        res.json({
            success: true,
            data: {
                userId,
                role: userRole,
                effectivePermissions,
                rolePermissions,
                grantedPermissions,
                revokedPermissions
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

// @desc    Update user permission override
// @route   POST /api/v1/superadmin/users/:id/permissions
// @route   PUT /api/v1/permission-management/users/:id (bulk)
// @access  Private (SuperAdmin)
const updateUserPermission = async (req, res) => {
    try {
        const userId = req.params.id;

        // Check if this is a bulk update (from AdminManagementPage)
        const { grantPermissions, revokePermissions } = req.body;

        if (grantPermissions || revokePermissions) {
            // Bulk update mode
            const toGrant = grantPermissions || [];
            const toRevoke = revokePermissions || [];

            // Grant permissions
            if (toGrant.length > 0) {
                const [perms] = await pool.query('SELECT id, name FROM permissions WHERE name IN (?)', [toGrant]);
                if (perms.length > 0) {
                    const values = perms.map(p => [userId, p.id, 'grant']);
                    await pool.query(
                        'INSERT INTO user_permissions (userId, permissionId, type) VALUES ? ON DUPLICATE KEY UPDATE type = "grant"',
                        [values]
                    );
                }
            }

            // Revoke permissions
            if (toRevoke.length > 0) {
                const [perms] = await pool.query('SELECT id, name FROM permissions WHERE name IN (?)', [toRevoke]);
                if (perms.length > 0) {
                    const values = perms.map(p => [userId, p.id, 'revoke']);
                    await pool.query(
                        'INSERT INTO user_permissions (userId, permissionId, type) VALUES ? ON DUPLICATE KEY UPDATE type = "revoke"',
                        [values]
                    );
                }
            }

            return res.json({ success: true, message: 'User permissions updated' });
        }

        // Single permission update mode (legacy)
        let { permissionId, type, permissionName } = req.body;

        // Frontend service sends permissionName for grant/revoke
        if (permissionName && !permissionId) {
            const [perms] = await pool.query('SELECT id FROM permissions WHERE name = ?', [permissionName]);
            if (perms.length > 0) permissionId = perms[0].id;
            else return res.status(404).json({ message: 'Permission not found' });
        }

        if (!type) {
            // For legacy or reset single
            await pool.query('DELETE FROM user_permissions WHERE userId = ? AND permissionId = ?', [userId, permissionId]);
        } else {
            await pool.query(
                'INSERT INTO user_permissions (userId, permissionId, type) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE type = ?',
                [userId, permissionId, type, type]
            );
        }

        res.json({ success: true, message: 'User permission updated' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

const grantUserPermission = async (req, res) => {
    req.body.type = 'grant';
    return updateUserPermission(req, res);
};

const revokeUserPermission = async (req, res) => {
    req.body.type = 'revoke';
    return updateUserPermission(req, res);
};

const resetUserPermissions = async (req, res) => {
    try {
        const userId = req.params.id;
        await pool.query('DELETE FROM user_permissions WHERE userId = ?', [userId]);
        res.json({ success: true, message: 'User permissions reset' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

const getRolePermissions = async (req, res) => {
    try {
        const { id: roleName } = req.params; // Frontend sends roleId as 'Admin', 'Instructor'

        // Get all permissions assigned to this role
        const [rolePerms] = await pool.query(`
            SELECT p.name 
            FROM role_permissions rp 
            JOIN permissions p ON rp.permissionId = p.id 
            WHERE rp.role = ?
        `, [roleName]);

        const permissionNames = rolePerms.map(p => p.name);

        res.json({
            success: true,
            data: {
                roleId: roleName,
                roleName: roleName,
                permissions: permissionNames,
                userCount: 0 // Mock count or fetch real count
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

const updateRolePermissions = async (req, res) => {
    try {
        const { id: roleName } = req.params;
        const { permissionNames } = req.body;

        // 1. Clear existing
        await pool.query('DELETE FROM role_permissions WHERE role = ?', [roleName]);

        // 2. Insert new
        if (permissionNames && permissionNames.length > 0) {
            // Get IDs
            const [perms] = await pool.query('SELECT id, name FROM permissions WHERE name IN (?)', [permissionNames]);

            if (perms.length > 0) {
                const values = perms.map(p => [roleName, p.id]);
                await pool.query('INSERT INTO role_permissions (role, permissionId) VALUES ?', [values]);
            }
        }

        res.json({ success: true, message: 'Role permissions updated' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

module.exports = {
    getAllPermissions,
    getUserPermissions,
    updateUserPermission,
    grantUserPermission,
    revokeUserPermission,
    resetUserPermissions,
    getRolePermissions,
    updateRolePermissions
};
