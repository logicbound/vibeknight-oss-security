// Suspicious: dynamic require with environment variable
// Pattern: ObfuscatedFlow (require(variable))
const moduleName = process.env.LOAD_MODULE || 'fs';
const mod = require(moduleName);

module.exports = function run(path) {
    return mod.readFileSync(path, 'utf-8');
};
