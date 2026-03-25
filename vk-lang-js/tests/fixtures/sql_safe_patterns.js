// SQL Safe Patterns - Should NOT be flagged
// This file contains safe SQL patterns that should not trigger SQL injection warnings

// Safe 1: Parameterized query with placeholders
function getUserByIdSafe(userId) {
    return db.query('SELECT * FROM users WHERE id = ?', [userId]);
}

// Safe 2: Parameterized query with named parameters
function getUserByEmailSafe(email) {
    return db.query('SELECT * FROM users WHERE email = :email', { email });
}

// Safe 3: Multiple parameters
function createUserSafe(req) {
    const username = req.body.username;
    const email = req.body.email;
    return db.query(
        'INSERT INTO users (username, email) VALUES (?, ?)',
        [username, email]
    );
}

// Safe 4: Sequelize query builder (should be recognized as sanitizer)
function findUserSequelize(email) {
    return sequelize.findAll({
        where: { email: email }
    });
}

// Safe 5: Sequelize findOne
function getUserSequelize(userId) {
    return sequelize.findOne({
        where: { id: userId }
    });
}

// Safe 6: TypeORM query builder
function getUserTypeORM(userId) {
    return repository.find({
        where: { id: userId }
    });
}

// Safe 7: Knex query builder
function getUserKnex(userId) {
    return knex.select('*')
        .from('users')
        .where('id', userId);
}

// Safe 8: Prepared statement
function getUserPrepared(userId) {
    return db.prepare('SELECT * FROM users WHERE id = ?').execute([userId]);
}

// Safe 9: Using db.prepared() method
function getUserPreparedMethod(userId) {
    return db.prepared('SELECT * FROM users WHERE id = ?', [userId]);
}

// Safe 10: Literal values only (no user input)
function getAllUsers() {
    return db.query('SELECT * FROM users WHERE active = 1');
}

// Safe 11: User input used in WHERE clause but with parameterized query
function searchUsersSafe(req) {
    const searchTerm = req.query.search;
    return db.query(
        'SELECT * FROM users WHERE name LIKE ?',
        [`%${searchTerm}%`]
    );
}

// Safe 12: User input used but not in SQL query
function logUserAction(req) {
    const userId = req.body.userId;
    const action = req.body.action;
    // User input is used in logging, not SQL
    console.log(`User ${userId} performed ${action}`);
    return db.query('SELECT * FROM audit_log WHERE date > NOW() - INTERVAL 1 DAY');
}

// Safe 13: String operations that don't affect SQL
function formatUserData(req) {
    const username = req.body.username;
    const formatted = username.toUpperCase(); // String operation, not SQL
    return db.query('SELECT * FROM users WHERE username = ?', [formatted]);
}

// Safe 14: User input sanitized before use
function getUserSanitized(req) {
    const userId = req.body.userId;
    // In a real scenario, this would be a proper sanitization function
    // For now, we'll just show the pattern
    const sanitized = parseInt(userId, 10); // Type conversion
    return db.query('SELECT * FROM users WHERE id = ?', [sanitized]);
}

