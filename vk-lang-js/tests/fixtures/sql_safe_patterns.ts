// SQL Injection Test - Safe Patterns (TypeScript)
// This file contains examples of safe SQL query practices in TypeScript.

// Safe 1: Parameterized query with '?' placeholder
function getUserByIdSafe(req: any): any {
    const userId: string = req.params.id;
    return db.query('SELECT * FROM users WHERE id = ?', [userId]);
}

// Safe 2: Parameterized query with named parameters
function getUserByEmailSafe(req: any): any {
    const email: string = req.body.email;
    return db.query('SELECT * FROM users WHERE email = :email', { replacements: { email: email } });
}

// Safe 3: Query builder (Sequelize - findAll)
function getPostsByAuthorSafe(req: any): any {
    const authorId: string = req.query.authorId;
    return sequelize.findAll({
        where: { authorId: authorId }
    });
}

// Safe 4: Query builder (Sequelize - findOne)
function getSingleUserSafe(req: any): any {
    const username: string = req.body.username;
    return sequelize.findOne({
        where: { username: username }
    });
}

// Safe 5: Query builder (TypeORM - find)
function findItemsSafe(req: any): any {
    const itemName: string = req.query.name;
    return getRepository(Item).find({ name: itemName });
}

// Safe 6: Query builder (Knex - select)
function knexSelectSafe(req: any): any {
    const limit: number = parseInt(req.query.limit);
    return knex('users').select('*').where('active', true).limit(limit);
}

// Safe 7: Prepared statement (explicit prepare/execute)
function preparedStatementSafe(req: any): any {
    const userId: string = req.params.id;
    const stmt: any = db.prepare('SELECT * FROM users WHERE id = ?');
    return stmt.execute([userId]);
}

// Safe 8: Input used in non-SQL context
function logUserInput(req: any): string {
    const userInput: string = req.body.data;
    console.log('User input:', userInput);
    return 'Logged';
}

// Safe 9: Hardcoded query (no user input)
function getAllUsers(): any {
    return db.query('SELECT * FROM users');
}

// Safe 10: Sanitized input (e.g., integer parsing)
function getNumericIdSafe(req: any): any {
    const id: number = parseInt(req.params.id);
    if (isNaN(id)) {
        return res.status(400).send('Invalid ID');
    }
    return db.query('SELECT * FROM items WHERE id = ' + id); // 'id' is now safe
}

// Safe 11: Input used in a whitelist check
function getReportTypeSafe(req: any): any {
    const type: string = req.query.type;
    const allowedTypes: string[] = ['daily', 'monthly', 'yearly'];
    if (!allowedTypes.includes(type)) {
        return res.status(400).send('Invalid report type');
    }
    return db.query(`SELECT * FROM reports WHERE type = '${type}'`); // 'type' is now safe
}

// Safe 12: Input escaped before use
function getEscapedInputSafe(req: any): any {
    const input: string = escapeHtml(req.query.input); // Assuming escapeHtml sanitizes for SQL
    return db.query(`SELECT * FROM data WHERE value = '${input}'`);
}

// Safe 13: Using a safe ORM method that handles escaping
function ormSafeMethod(req: any): any {
    const username: string = req.body.username;
    return User.findByUsername(username); // Assuming findByUsername is safe
}

// Safe 14: Input used in a non-string context (e.g., limit)
function getLimitedResultsSafe(req: any): any {
    const limit: number = parseInt(req.query.limit);
    if (isNaN(limit) || limit > 100) {
        return res.status(400).send('Invalid limit');
    }
    return db.query(`SELECT * FROM results LIMIT ${limit}`); // 'limit' is safe as integer
}

// Safe 15: TypeScript type-safe query builder
interface UserQuery {
    id?: number;
    email?: string;
}

function findUserByQuery(query: UserQuery): any {
    return db.query('SELECT * FROM users WHERE id = ? AND email = ?', [query.id, query.email]);
}

