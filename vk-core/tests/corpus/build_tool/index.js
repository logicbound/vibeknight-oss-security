// Typical native-module loader — hardcoded commands, writes to build/ only.
const { execSync } = require('child_process');
const fs = require('fs');

function rebuild() {
    execSync('node-gyp rebuild');
    fs.writeFileSync('build/Release/addon.node', Buffer.alloc(0));
}

module.exports = { rebuild };
