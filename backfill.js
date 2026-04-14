// backfill.js — CommonJS (no top-level await)
const { Client } = require('pg');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ── Config ────────────────────────────────────────────────────
function getDbConfig() {
  const databaseUrl = process.env.DATABASE_URL;
  if (databaseUrl) {
    const parsed = new URL(databaseUrl);
    return {
      host: parsed.hostname || process.env.DB_HOST || 'localhost',
      port: parsed.port ? Number(parsed.port) : Number(process.env.DB_PORT || 5432),
      user: decodeURIComponent(parsed.username || process.env.DB_USER || 'postgres'),
      password: decodeURIComponent(parsed.password || process.env.DB_PASSWORD || ''),
      database: (parsed.pathname || '').replace(/^\//, '') || process.env.DB_NAME || 'gene_nft',
    };
  }

  return {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'gene_nft',
  };
}

const DB_CONFIG = getDbConfig();

const KEYS_DIR    = path.join(__dirname, '..', 'static', 'kg');
const ADMIN_UNAME = 'Admin'; // must match session username used in your app

// ── Key Loaders ───────────────────────────────────────────────
function loadPrivateKey(filePath) {
  const pem = fs.readFileSync(filePath, 'utf8');
  return crypto.createPrivateKey({ key: pem, format: 'pem' });
}

function loadPublicKey(filePath) {
  const pem = fs.readFileSync(filePath, 'utf8');
  return crypto.createPublicKey({ key: pem, format: 'pem' });
}

// ── Auto-generate Owner key if missing ───────────────────────
// Mirrors your Python register_user_crypto() logic
async function ensureOwnerKeys(uname, db) {
  const privPath = path.join(KEYS_DIR, `${uname}_pr.txt`);
  const pubPath  = path.join(KEYS_DIR, `${uname}_pb.txt`);

  if (!fs.existsSync(privPath)) {
    console.log(`  Owner key missing for "${uname}". Generating RSA-2048 key pair...`);
    fs.mkdirSync(KEYS_DIR, { recursive: true });

    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength      : 2048,
      publicKeyEncoding  : { type: 'spki',  format: 'pem' },
      privateKeyEncoding : { type: 'pkcs8', format: 'pem' },
    });

    fs.writeFileSync(privPath, privateKey, 'utf8');
    fs.writeFileSync(pubPath,  publicKey,  'utf8');

    // Sync public key back into gn_owner (matches your reg_owner INSERT)
    await db.query(
      `UPDATE gn_owner SET public_key = $1 WHERE uname = $2`,
      [publicKey, uname]
    );

    console.log(`  ✓ Keys generated and public_key updated in DB for "${uname}"`);
  }
}

function getOwnerPrivateKey(uname) {
  return loadPrivateKey(path.join(KEYS_DIR, `${uname}_pr.txt`));
}

// ── Auto-generate Admin key if missing ───────────────────────
// Mirrors your Python get_admin_private_key() logic
function ensureAdminKeys() {
  const privPath = path.join(KEYS_DIR, 'admin_pr.txt');
  const pubPath  = path.join(KEYS_DIR, 'admin_pb.txt');

  if (!fs.existsSync(privPath)) {
    console.log('Admin key not found. Generating RSA-2048 key pair...');
    fs.mkdirSync(KEYS_DIR, { recursive: true });

    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength      : 2048,
      publicKeyEncoding  : { type: 'spki',  format: 'pem' },
      privateKeyEncoding : { type: 'pkcs8', format: 'pem' },
    });

    fs.writeFileSync(privPath, privateKey, 'utf8');
    fs.writeFileSync(pubPath,  publicKey,  'utf8');
    console.log(`Admin keys saved:\n  ${privPath}\n  ${pubPath}\n`);
  }
}

function getAdminPrivateKey() {
  ensureAdminKeys();
  return loadPrivateKey(path.join(KEYS_DIR, 'admin_pr.txt'));
}

function getAdminPublicKey() {
  ensureAdminKeys();
  return loadPublicKey(path.join(KEYS_DIR, 'admin_pb.txt'));
}

// ── RSA-PSS Sign (matches your Python rsa_sign exactly) ───────
function rsaSign(privateKeyObj, message) {
  const sig = crypto.sign('sha256', Buffer.from(message), {
    key       : privateKeyObj,
    padding   : crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
  });
  return sig.toString('base64');
}

// ── RSA-PSS Verify ────────────────────────────────────────────
function rsaVerify(publicKeyObj, message, signatureB64) {
  try {
    return crypto.verify(
      'sha256',
      Buffer.from(message),
      {
        key       : publicKeyObj,
        padding   : crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
      },
      Buffer.from(signatureB64, 'base64')
    );
  } catch {
    return false;
  }
}

// ── Canonical Message Builders ────────────────────────────────
function buildOwnerMessage(row) {
  return (
    `GENENFT_OWNER_SIGN|` +
    `RID:${row.id}|` +
    `OWNER:${row.owner_id}|` +
    `RESEARCHER:${row.researcher_id}|` +
    `DATASET:${row.dataset_id}`
  );
}

// Matches exactly your Python admin_send_approvals canonical message
function buildAdminMessage(row, ownerSigB64) {
  const ts = new Date()
    .toISOString()
    .replace(/-/g, '')
    .replace(/:/g, '')
    .replace(/\.\d+Z$/, 'Z'); // YYYYMMDDTHHMMSSz

  const ownerSigHash = crypto
    .createHash('sha256')
    .update(ownerSigB64)
    .digest('hex')
    .slice(0, 32);

  return (
    `GENENFT_ADMIN_COSIGN|` +
    `RID:${row.id}|` +
    `ADMIN:${ADMIN_UNAME}|` +
    `OWNER:${row.owner_id}|` +
    `RESEARCHER:${row.researcher_id}|` +
    `OWNER_SIG_HASH:${ownerSigHash}|` +
    `TS:${ts}`
  );
}

// ── Main ──────────────────────────────────────────────────────
async function backfill() {
  const db = new Client(DB_CONFIG);
  await db.connect();
  console.log('Connected to database.\n');

  // Fetch all unsigned rows
  const rowsResult = await db.query(`
    SELECT id, owner_id, researcher_id, dataset_id
    FROM gn_data_requests
    WHERE owner_signature IS NULL
  `);
  const rows = rowsResult.rows;

  console.log(`Found ${rows.length} unsigned rows. Starting backfill...\n`);

  // Ensure admin keys exist once before the loop
  const adminPrivKey = getAdminPrivateKey();
  const adminPubKey  = getAdminPublicKey();

  let success = 0;
  let failed  = 0;

  for (const row of rows) {
    console.log(`\nProcessing Row ${row.id} — owner: ${row.owner_id}`);
    try {
      // ── 1. Ensure owner key files exist (generate if missing) ──
      await ensureOwnerKeys(row.owner_id, db);

      // ── 2. Load owner private key ──
      const ownerPrivKey = getOwnerPrivateKey(row.owner_id);

      // ── 3. Build + sign owner canonical message ──
      const ownerMessage   = buildOwnerMessage(row);
      const ownerSignature = rsaSign(ownerPrivKey, ownerMessage);

      // ── 4. Build + sign admin canonical message ──
      const adminMessage   = buildAdminMessage(row, ownerSignature);
      const adminSignature = rsaSign(adminPrivKey, adminMessage);

      // ── 5. Self-verify admin signature (matches Python step 6) ──
      const adminSigOk = rsaVerify(adminPubKey, adminMessage, adminSignature);
      if (!adminSigOk) {
        throw new Error('Admin self-verify failed');
      }

      // ── 6. Update row ──
      await db.query(`
        UPDATE gn_data_requests
        SET owner_signature    = $1,
            owner_sign_message = $2,
            admin_signature    = $3,
            admin_sign_message = $4,
            admin_approval     = 'Approved'
        WHERE id = $5
      `, [ownerSignature, ownerMessage, adminSignature, adminMessage, row.id]);

      console.log(`  ✓ Row ${row.id} signed & approved`);
      success++;

    } catch (err) {
      console.error(`  ✗ Row ${row.id} failed: ${err.message}`);
      failed++;
    }
  }

  console.log(`\nBackfill complete. ✓ ${success} signed | ✗ ${failed} failed`);
  await db.end();
}

backfill();