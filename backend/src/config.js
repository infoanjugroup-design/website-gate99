require('dotenv').config();
const crypto = require('crypto');

function need(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  return v;
}

const port = Number(need('PORT', 3000));

// Used to sign short-lived book-reader links (see security.tokenSecret below) —
// falling back to a random per-process secret if not set in .env.
const tokenSecretFromEnv = need('TOKEN_SECRET', 'phuKIeDWbeVRHf0KsTnl52H7qUOM7H2f2GrxeFZQk9xbMdGCeBoSCWlaPceg6d2P');
if (!tokenSecretFromEnv) {
  console.warn(
    '[config] TOKEN_SECRET not set in .env — using a random secret generated for ' +
    'this process only. Book-reader links will stop working after every server ' +
    'restart (students just re-open the book and get a fresh one, so this is not ' +
    'dangerous — just noisier than it needs to be). Set TOKEN_SECRET to any long ' +
    'random string in .env to avoid this.'
  );
}

module.exports = {
  nocodb: {
    url: need('NOCODB_URL', 'https://app.nocodb.com').replace(/\/+$/, ''),
    token: need('NOCODB_API_TOKEN', 'nc_pat_sXAoZc6ps9aCIVBF69yvHML3rbUx5LZ1YpUrw0tN'),
    baseName: need('NOCODB_BASE_NAME', 'GATE99'),
    baseId: need('NOCODB_BASE_ID', 'pdqt9l8tm9gvz0j').trim(),
  },
  server: {
    port,
    // This server's own public origin — used to build the signed book-stream
    // links returned by getBookFile. Point this at a CDN in front of this
    // server (see README "Performance" section, point 2) once you have one.
    publicUrl: need('PUBLIC_SERVER_URL', `http://localhost:${port}`).replace(/\/+$/, ''),
  },
  email: {
    user: need('EMAIL_USER', 'info.jagdeesh07@gmail.com),
    pass: need('EMAIL_PASS', 'lwnkgqfjozcitufa'),
    fromName: need('EMAIL_FROM_NAME', 'GATE99'),
  },
  uploads: {
    dir: need('UPLOAD_DIR', './uploads'),
    publicBaseUrl: need('PUBLIC_UPLOAD_BASE_URL', 'http://localhost:3000/uploads'),
  },
  security: {
    tokenSecret: tokenSecretFromEnv || crypto.randomBytes(32).toString('hex'),
    // How long a "Read Book" link stays valid once handed to a student's
    // browser. Short enough that a leaked link is useless soon after;
    // long enough that reading a big book in one sitting never expires
    // mid-read (pdf.js only re-requests bytes as new pages are turned).
    bookLinkTtlMs: Number(need('BOOK_LINK_TTL_SECONDS', 1800)) * 1000, // 30 min default
  },
  // Optional PDF post-processing on upload (see README point 3 & 4).
  // Both require system binaries (qpdf / ghostscript) — auto-skipped if absent.
  pdfOptimize: {
    linearize: need('PDF_LINEARIZE', 'true') !== 'false',
    compress: need('PDF_COMPRESS', 'true') !== 'false',
    compressMinSizeMB: Number(need('PDF_COMPRESS_MIN_MB', 15)),
  },
};
