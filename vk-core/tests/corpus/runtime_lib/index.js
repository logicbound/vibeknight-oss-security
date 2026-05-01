// Pure library — exports only, no side effects at module scope.

function add(a, b) {
    return a + b;
}

function greet(name) {
    return 'Hello, ' + name;
}

module.exports = { add, greet };
