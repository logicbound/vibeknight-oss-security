// A typical CLI that reads argv and runs a hardcoded command.
const { execSync } = require('child_process');

function main() {
    const args = process.argv.slice(2);
    if (args[0] === 'build') {
        execSync('tsc --declaration');
    }
}

main();
