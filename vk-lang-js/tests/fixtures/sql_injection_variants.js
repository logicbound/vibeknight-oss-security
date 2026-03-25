// SQL Injection Test - Multiple Variants
// This file tests various SQL injection patterns

// Variant 1: Direct parameter concatenation (from request)
function getUserById(req) {
    const userId = req.params.id;
    const query = 'SELECT * FROM users WHERE id = ' + userId;
    return db.query(query);
}

// Variant 2: Template literal with user input
function searchUsers(req) {
    const searchTerm = req.query.search;
    return db.query(`SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`);
}

// Variant 3: Multiple concatenations
function getUserByEmailAndName(req) {
    const email = req.body.email;
    const name = req.body.name;
    const query = 'SELECT * FROM users WHERE email = "' + email + '" AND name = "' + name + '"';
    return db.query(query);
}

// Variant 4: Request body source
function createUser(req) {
    const username = req.body.username;
    const query = 'INSERT INTO users (username) VALUES ("' + username + '")';
    return db.query(query);
}

// Variant 5: Request query parameters
function filterUsers(req) {
    const role = req.query.role;
    const query = 'SELECT * FROM users WHERE role = ' + role;
    return connection.query(query);
}

// Variant 6: Request params (URL parameters)
function getUserProfile(req) {
    const userId = req.params.id;
    const query = 'SELECT * FROM profiles WHERE user_id = ' + userId;
    return db.query(query);
}

// Variant 7: Cookie source
function getSessionData(req) {
    const sessionId = req.cookies.sessionId;
    const query = 'SELECT * FROM sessions WHERE id = "' + sessionId + '"';
    return db.query(query);
}

// Variant 8: Nested property access
function updateUser(req) {
    const email = req.body.user.email;
    const query = 'UPDATE users SET email = "' + email + '" WHERE id = 1';
    return db.query(query);
}

// Variant 9: Chained assignments
function processRequest(req) {
    const input = req.body.input;
    const sanitized = input; // Not actually sanitized!
    const query = 'SELECT * FROM data WHERE value = "' + sanitized + '"';
    return db.query(query);
}

// Variant 10: Using execute() function
function deleteUser(req) {
    const userId = req.body.userId;
    const query = 'DELETE FROM users WHERE id = ' + userId;
    return execute(query);
}

// Variant 11: ORM raw query (Sequelize)
function findUserRaw(req) {
    const email = req.body.email;
    const query = 'SELECT * FROM users WHERE email = "' + email + '"';
    return sequelize.query(query);
}

// Variant 12: TypeORM raw query
function getUserRaw(req) {
    const userId = req.params.id;
    const query = 'SELECT * FROM users WHERE id = ' + userId;
    return queryRunner.query(query);
}

