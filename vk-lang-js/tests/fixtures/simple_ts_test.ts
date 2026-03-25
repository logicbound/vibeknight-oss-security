// Simple TypeScript test to verify parsing

function test(): any {
    const x: string = 'hello';
    return x;
}

function sqlTest(req: any): any {
    const userId: string = req.params.id;
    const query: string = 'SELECT * FROM users WHERE id = ' + userId;
    return db.query(query);
}

