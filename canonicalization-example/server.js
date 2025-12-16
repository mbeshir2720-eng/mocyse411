const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();
app.disable("x-powered-by");

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  
  // COMPLETE CSP with ALL directives ZAP expects
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; " +  // Start with none for maximum security
    "base-uri 'self'; " +
    "block-all-mixed-content; " +
    "child-src 'self'; " +
    "connect-src 'self'; " +
    "font-src 'self'; " +
    "form-action 'self'; " +
    "frame-ancestors 'none'; " +
    "frame-src 'none'; " +
    "img-src 'self' data:; " +
    "manifest-src 'self'; " +
    "media-src 'self'; " +
    "object-src 'none'; " +
    "script-src 'self'; " +
    "script-src-attr 'none'; " +
    "script-src-elem 'self'; " +
    "style-src 'self'; " +
    "style-src-attr 'none'; " +
    "style-src-elem 'self'; " +
    "upgrade-insecure-requests; " +
    "worker-src 'self'"
  );
  
  res.setHeader("Permissions-Policy", "interest-cohort=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  
  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// Helper to canonicalize and check
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// Secure route
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);

    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// Vulnerable route (demo)
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';
  const normalized = resolveSafe(BASE_DIR, filename);

  if (!normalized.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: 'Path traversal detected' });
  }
  
  if (!fs.existsSync(normalized)) {
    return res.status(404).json({ error: 'File not found', path: normalized });
  }
  const content = fs.readFileSync(normalized, 'utf8');
  res.json({ path: normalized, content });
});

// Helper route for samples
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });
  res.json({ ok: true, base: BASE_DIR });
});

// Only listen when run directly (not when imported by tests)
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;