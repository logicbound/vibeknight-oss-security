// Benign: plain utility module, no network, no exec, no eval
// Should produce zero high-risk signals

function greet(name) {
    return 'Hello, ' + name + '!';
}

function add(a, b) {
    return a + b;
}

module.exports = { greet, add };
