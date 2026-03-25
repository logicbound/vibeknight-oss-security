// SQL Injection Test - TypeScript Variants
// This file tests various SQL injection patterns in TypeScript

// Variant 1: Direct parameter concatenation (from request)
function getUserById(req: any): any {
    const userId: string = req.params.id;
    const query: string = 'SELECT * FROM users WHERE id = ' + userId;
    return db.query(query);
}

// Variant 2: Template literal with user input (from request)
function searchUsers(req: any): any {
    const searchTerm: string = req.query.search;
    return db.query(`SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`);
}

// Variant 3: Multiple concatenations (from request)
function getUserByEmailAndName(req: any): any {
    const email: string = req.body.email;
    const name: string = req.body.name;
    const query: string = 'SELECT * FROM users WHERE email = "' + email + '" AND name = "' + name + '"';
    return db.query(query);
}

// Variant 4: Chained assignment (from request)
function updateProfile(req: any): any {
    let username: string = req.body.username;
    let bio: string = username; // Chained assignment
    return db.query(`UPDATE users SET bio = '${bio}' WHERE username = '${username}'`);
}

// Variant 5: Object property access (from request)
function deleteUser(req: any): any {
    const userToDelete: string = req.body.user.id;
    return connection.query('DELETE FROM users WHERE id = ' + userToDelete);
}

// Variant 6: Array element access (from request)
function getProduct(req: any): any {
    const productId: string = req.query.ids[0];
    return db.execute(`SELECT * FROM products WHERE id = ${productId}`);
}

// Variant 7: Cookie-based injection
function getSessionData(req: any): any {
    const sessionId: string = req.cookies.session_id;
    return db.query(`SELECT * FROM sessions WHERE id = '${sessionId}'`);
}

// Variant 8: Environment variable injection
function getConfig(req: any): any {
    const configName: string = process.env.APP_CONFIG || ''; // Assuming APP_CONFIG can be tainted
    return db.query(`SELECT value FROM config WHERE name = '${configName}'`);
}

// Variant 9: ORM raw query (Sequelize)
function rawSequelizeQuery(req: any): any {
    const input: string = req.body.input;
    return sequelize.query(`SELECT * FROM data WHERE value = '${input}'`);
}

// Variant 10: ORM raw query (TypeORM QueryRunner)
function rawTypeOrmQuery(req: any): any {
    const input: string = req.body.input;
    const queryRunner: any = getConnection().createQueryRunner();
    return queryRunner.query(`SELECT * FROM items WHERE name = '${input}'`);
}

// Variant 11: Direct string literal concatenation with tainted variable
function getOrderDetails(req: any): any {
    const orderId: string = req.params.orderId;
    const baseQuery: string = "SELECT * FROM orders WHERE id = ";
    const finalQuery: string = baseQuery + orderId;
    return db.query(finalQuery);
}

// Variant 12: Multiple tainted inputs in a single query
function filterProducts(req: any): any {
    const category: string = req.query.category;
    const price: string = req.query.price;
    return db.query(`SELECT * FROM products WHERE category = '${category}' AND price > ${price}`);
}

// Variant 13: TypeScript interface with tainted property
interface UserRequest {
    id: string;
}

function getUserByIdTyped(req: UserRequest): any {
    const query: string = 'SELECT * FROM users WHERE id = ' + req.id;
    return db.query(query);
}

// Variant 14: Arrow function with type annotations
const getUserByEmail = (req: any): any => {
    const email: string = req.body.email;
    return db.query(`SELECT * FROM users WHERE email = '${email}'`);
};

// Variant 15: Class method with SQL injection
class UserService {
    findUser(req: any): any {
        const userId: string = req.params.id;
        return db.query(`SELECT * FROM users WHERE id = ${userId}`);
    }
}

