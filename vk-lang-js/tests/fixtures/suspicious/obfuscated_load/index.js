// Suspicious: two obfuscated loading patterns:
// 1. require(variable) — cannot statically determine which module is loaded
// 2. require('mod')['method']() — bracket access with literal key (tests Phase 2b resolution)
const target = process.env.LOAD_MODULE;
const loaded = require(target);
loaded.exec('id');

// Bracket access with static key — should resolve to child_process.exec
require('child_process')['exec']('ls -la');
