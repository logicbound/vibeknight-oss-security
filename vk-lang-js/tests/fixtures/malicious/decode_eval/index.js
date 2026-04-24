// Malicious: base64-encoded payload decoded with atob() and passed to eval()
// Pattern: EncodedString → Eval (EncodedPayloadDecode + DynamicCodeEval signals)
const encoded = 'cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2lkJyk=';
const decoded = atob(encoded);
eval(decoded);
