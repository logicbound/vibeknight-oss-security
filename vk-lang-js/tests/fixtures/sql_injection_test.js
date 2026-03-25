// Test file for SQL injection detection

// Vulnerable: Direct user input in SQL query
function getUserById(userId) {
    const query = 'SELECT * FROM users WHERE id = ' + userId;
    return db.query(query);
}

// Vulnerable: User input from request body
function getUserByEmail(req, res) {
    const email = req.body.email;
    const query = 'SELECT * FROM users WHERE email = "' + email + '"';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.json(results);
        }
    });
}

// Vulnerable: Template literal with user input
function searchUsers(req) {
    const searchTerm = req.query.search;
    return db.query(`SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`);
}

// Safe: Parameterized query (should NOT be flagged)
function getUserByIdSafe(userId) {
    return db.query('SELECT * FROM users WHERE id = ?', [userId]);
}

// Safe: Query builder (should NOT be flagged)
function getUserByEmailSafe(req) {
    const email = req.body.email;
    return sequelize.findAll({
        where: { email: email }
    });
}

