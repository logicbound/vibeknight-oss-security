// SQL Injection Test - TypeScript without type annotations
// This is TypeScript syntax but without explicit type annotations

// Variant 1: Direct parameter concatenation (from request)
function getUserById(req) {
    const userId = req.params.id;
    const query = 'SELECT * FROM users WHERE id = ' + userId;
    return db.query(query);
}

// Variant 2: Template literal with user input (from request)
function searchUsers(req) {
    const searchTerm = req.query.search;
    return db.query(`SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`);
}

// Variant 3: Multiple concatenations (from request)
function getUserByEmailAndName(req) {
    const email = req.body.email;
    const name = req.body.name;
    const query = 'SELECT * FROM users WHERE email = "' + email + '" AND name = "' + name + '"';
    return db.query(query);
}

// Variant 4: Chained assignment (from request)
function updateProfile(req) {
    let username = req.body.username;
    let bio = username; // Chained assignment
    return db.query(`UPDATE users SET bio = '${bio}' WHERE username = '${username}'`);
}

// Variant 5: Object property access (from request)
function deleteUser(req) {
    const userToDelete = req.body.user.id;
    return connection.query('DELETE FROM users WHERE id = ' + userToDelete);
}

