/**
 * VAJRA — Real PostgreSQL integration tests (Prompt 0021)
 *
 * Runs only when DATABASE_URL points at a reachable PostgreSQL instance.
 * Uses PrismaIdentityRepository — not the in-memory adapter.
 *
 * Dummy data only. Does not claim Windows/Android agent runtime verification.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import {
  generateDeviceKeyPair,
  signDeviceRequest,
  signEnrollmentProof,
  generateTotpSecret,
  encryptTotpSecret,
  generateTotpCodeAtTime,
  verifyTotpCode,
  verifyAuditChain,
} from '../packages/security/src/node.ts';
import { createVajraApiApp } from '../src/server/app.ts';
import { PrismaIdentityRepository } from '../src/server/db/repository.ts';
import { STEP_UP_SCOPES } from '../src/server/auth/middleware.ts';

const DATABASE_URL = process.env.DATABASE_URL?.trim() ?? '';
const TOTP_KEY = 'vajra-pg-integration-totp-key-32b!!';
const RUN_PG =
  (DATABASE_URL.startsWith('postgresql://') || DATABASE_URL.startsWith('postgres://')) &&
  process.env.VAJRA_PG_INTEGRATION === '1';

function extractCookie(setCookie: string | string[] | undefined): string {
  if (!setCookie) return '';
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return raw.split(';')[0] ?? '';
}

async function requestJson(
  server: http.Server,
  options: {
    method: string;
    path: string;
    body?: unknown;
    cookie?: string;
    csrfToken?: string;
    headers?: Record<string, string>;
  }
): Promise<{ status: number; body: any; headers: http.IncomingHttpHeaders }> {
  const addr = server.address();
  assert(addr && typeof addr === 'object');
  const payload = options.body === undefined ? undefined : JSON.stringify(options.body);
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(options.headers ?? {}),
  };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = String(Buffer.byteLength(payload));
  }
  if (options.cookie) headers.Cookie = options.cookie;
  if (options.csrfToken) headers['X-CSRF-Token'] = options.csrfToken;

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: addr.port,
        path: options.path,
        method: options.method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let body: unknown = null;
          try {
            body = text ? JSON.parse(text) : null;
          } catch {
            body = { _raw: text };
          }
          resolve({ status: res.statusCode ?? 0, body, headers: res.headers });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

describe(
  'PostgreSQL integration (requires VAJRA_PG_INTEGRATION=1 + DATABASE_URL)',
  {
    skip: !RUN_PG
      ? 'BLOCKED: Missing prerequisite — Set VAJRA_PG_INTEGRATION=1 and a disposable PostgreSQL DATABASE_URL (use `npm run test:pg`)'
      : false,
  },
  () => {
  let prisma: PrismaClient;
  let repo: PrismaIdentityRepository;
  let server: http.Server;
  const suffix = crypto.randomBytes(4).toString('hex');
  const emailA = `pg.owner.a.${suffix}@vajra.test`;
  const emailB = `pg.owner.b.${suffix}@vajra.test`;

  before(async () => {
    prisma = new PrismaClient({ datasources: { db: { url: DATABASE_URL } } });
    await prisma.$connect();
    repo = new PrismaIdentityRepository(prisma);
    const app = createVajraApiApp({
      repository: repo,
      totpEncryptionKey: TOTP_KEY,
    });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    // Best-effort cleanup; AuditLog is append-only so device/user deletes may be constrained
    try {
      await prisma.$disconnect();
    } catch {
      /* ignore */
    }
  });

  it('reports PostgreSQL backend health on readiness', async () => {
    const health = await repo.checkDatabaseHealth(3000);
    assert.equal(health.ok, true);
    assert.equal(health.backend, 'POSTGRESQL_PRISMA');

    const ready = await requestJson(server, { method: 'GET', path: '/api/ready' });
    assert.equal(ready.status, 200);
    assert.ok(ready.body.status === 'ready' || ready.body.ready === true || ready.body.status === 'ok');
  });

  it('registers a user and rejects duplicate email (unique constraint)', async () => {
    const reg = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: emailA,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'PG Owner A',
      },
    });
    assert.equal(reg.status, 201, JSON.stringify(reg.body));
    assert.ok(reg.body.user?.id);
    assert.ok(reg.body.csrfToken);

    const dup = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: emailA,
        password: 'Another-Passw0rd!',
        displayName: 'Dup',
      },
    });
    assert.ok(dup.status === 409 || dup.status === 400, JSON.stringify(dup.body));
  });

  it('persists session, enables MFA, and grants action-scoped step-up', async () => {
    const regAgain = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: `pg.session.${suffix}@vajra.test`,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'Session User',
      },
    });
    assert.equal(regAgain.status, 201, JSON.stringify(regAgain.body));
    const cookie = extractCookie(regAgain.headers['set-cookie']);
    const csrf = regAgain.body.csrfToken as string;
    const userId = regAgain.body.user.id as string;
    assert.ok(cookie && csrf && userId, JSON.stringify(regAgain.body));

    const secretBase32 = generateTotpSecret();
    const encrypted = encryptTotpSecret({
      secretBase32,
      userId,
      encryptionKeyMaterial: TOTP_KEY,
    });
    await repo.updateUserCredential({
      userId,
      totpSecretEncrypted: encrypted,
      totpEnabled: true,
    });

    const code = generateTotpCodeAtTime(secretBase32);
    assert.equal(verifyTotpCode({ secretBase32, code }), true);

    const stepUp = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/step-up',
      cookie,
      csrfToken: csrf,
      body: { totpCode: code, actionScope: STEP_UP_SCOPES.DEVICE_REVOKE },
    });
    assert.equal(stepUp.status, 200, JSON.stringify(stepUp.body));
    assert.equal(stepUp.body.stepUpVerified, true);
    assert.equal(stepUp.body.actionScope, STEP_UP_SCOPES.DEVICE_REVOKE);
  });

  it('enrolls a device through pending → confirm and rejects cross-user access', async () => {
    const reg = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: emailB,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'PG Owner B',
      },
    });
    assert.equal(reg.status, 201, JSON.stringify(reg.body));
    const cookie = extractCookie(reg.headers['set-cookie']);
    const csrf = reg.body.csrfToken as string;

    const init = await requestJson(server, {
      method: 'POST',
      path: '/api/devices/enrollment/initiate',
      cookie,
      csrfToken: csrf,
      body: { name: 'PG Test Phone', deviceType: 'ANDROID' },
    });
    assert.equal(init.status, 201, JSON.stringify(init.body));
    const enrollment = init.body.enrollment;
    const deviceId = enrollment.deviceId as string;
    const enrollmentToken = enrollment.enrollmentToken as string;
    const challengeNonce = enrollment.challengeNonce as string;

    const keyPair = generateDeviceKeyPair('ED25519');
    const timestampIso = new Date().toISOString();
    const clientNonce = crypto.randomBytes(16).toString('hex');
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      deviceId,
      enrollmentToken,
      challengeNonce,
      publicKeyFingerprint: keyPair.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    });

    const submit = await requestJson(server, {
      method: 'POST',
      path: '/api/devices/enrollment/submit',
      body: {
        enrollmentToken,
        publicKeyPem: keyPair.publicKeyPem,
        keyAlgorithm: 'ED25519',
        signatureBase64,
        timestampIso,
        clientNonce,
        hardwareBacked: false,
      },
    });
    assert.ok(submit.status === 200 || submit.status === 201, JSON.stringify(submit.body));

    const confirm = await requestJson(server, {
      method: 'POST',
      path: `/api/devices/${deviceId}/enrollment/confirm`,
      cookie,
      csrfToken: csrf,
    });
    assert.ok(confirm.status === 200 || confirm.status === 201, JSON.stringify(confirm.body));

    // Cross-user: register C and attempt to read B's device
    const regC = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: `pg.owner.c.${suffix}@vajra.test`,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'PG Owner C',
      },
    });
    assert.equal(regC.status, 201);
    const cookieC = extractCookie(regC.headers['set-cookie']);
    const getCross = await requestJson(server, {
      method: 'GET',
      path: `/api/devices/${deviceId}`,
      cookie: cookieC,
    });
    assert.ok(getCross.status === 404 || getCross.status === 403, JSON.stringify(getCross.body));

    // Heartbeat persistence via signed Plane-2 request
    const hbPath = `/api/devices/${deviceId}/heartbeat`;
    const hbBody = { connectivityStatus: 'ONLINE', agentVersion: '0.1.0-test' };
    const ts = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const sig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: hbPath,
      deviceId,
      timestampIso: ts,
      nonce,
      body: hbBody,
    });
    const hb = await requestJson(server, {
      method: 'POST',
      path: hbPath,
      body: hbBody,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': ts,
        'X-Vajra-Nonce': nonce,
        'X-Vajra-Signature': sig,
      },
    });
    assert.ok(hb.status === 200 || hb.status === 201, JSON.stringify(hb.body));

    const deviceRow = await prisma.device.findUnique({ where: { id: deviceId } });
    assert.ok(deviceRow);
    assert.ok(deviceRow.lastHeartbeatAt || deviceRow.lastSeenAt);

    const hbRow = await prisma.deviceHeartbeat.findFirst({ where: { deviceId } });
    assert.ok(hbRow, 'expected persisted DeviceHeartbeat row in PostgreSQL');

    const nonceRow = await prisma.deviceAuthNonce.findFirst({ where: { deviceId, nonce } });
    assert.ok(nonceRow, 'expected persisted DeviceAuthNonce row in PostgreSQL');

    // Replay of the same nonce must be rejected with 409 DEVICE_NONCE_REPLAYED
    const replay = await requestJson(server, {
      method: 'POST',
      path: hbPath,
      body: hbBody,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': ts,
        'X-Vajra-Nonce': nonce,
        'X-Vajra-Signature': sig,
      },
    });
    assert.equal(replay.status, 409, JSON.stringify(replay.body));
    assert.equal(replay.body?.error?.code, 'DEVICE_NONCE_REPLAYED');

    // Queue REQUEST_DEVICE_STATUS -> poll -> ack -> result receipt persisted in PostgreSQL
    const createCmd = await requestJson(server, {
      method: 'POST',
      path: `/api/devices/${deviceId}/commands`,
      cookie,
      csrfToken: csrf,
      body: { actionType: 'REQUEST_DEVICE_STATUS', ttlMinutes: 30 },
    });
    assert.equal(createCmd.status, 201, JSON.stringify(createCmd.body));
    const commandId = createCmd.body.command?.id as string;
    assert.ok(commandId);

    const pollPath = `/api/devices/${deviceId}/commands/pending`;
    const pollTs = new Date().toISOString();
    const pollNonce = crypto.randomUUID();
    const pollSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'GET',
      path: pollPath,
      deviceId,
      timestampIso: pollTs,
      nonce: pollNonce,
      body: undefined,
    });
    const pendingRes = await requestJson(server, {
      method: 'GET',
      path: pollPath,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': pollTs,
        'X-Vajra-Nonce': pollNonce,
        'X-Vajra-Signature': pollSig,
      },
    });
    assert.equal(pendingRes.status, 200, JSON.stringify(pendingRes.body));
    assert.ok(
      Array.isArray(pendingRes.body.commands) &&
        pendingRes.body.commands.some((c: any) => c.id === commandId)
    );

    const ackPath = `/api/devices/${deviceId}/commands/${commandId}/acknowledge`;
    const ackBody = { message: 'Acknowledged by PG test protocol client' };
    const ackTs = new Date().toISOString();
    const ackNonce = crypto.randomUUID();
    const ackSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: ackPath,
      deviceId,
      timestampIso: ackTs,
      nonce: ackNonce,
      body: ackBody,
    });
    const ackRes = await requestJson(server, {
      method: 'POST',
      path: ackPath,
      body: ackBody,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': ackTs,
        'X-Vajra-Nonce': ackNonce,
        'X-Vajra-Signature': ackSig,
      },
    });
    assert.ok(ackRes.status === 200 || ackRes.status === 201, JSON.stringify(ackRes.body));

    const resultPath = `/api/devices/${deviceId}/commands/${commandId}/result`;
    const resultBody = {
      status: 'COMPLETED',
      safeMessage: 'Status check completed and persisted in PostgreSQL.',
      executionLatencyMs: 25,
      metadata: { posture: 'HEALTHY' },
    };
    const resultTs = new Date().toISOString();
    const resultNonce = crypto.randomUUID();
    const resultSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: resultPath,
      deviceId,
      timestampIso: resultTs,
      nonce: resultNonce,
      body: resultBody,
    });
    const resultRes = await requestJson(server, {
      method: 'POST',
      path: resultPath,
      body: resultBody,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': resultTs,
        'X-Vajra-Nonce': resultNonce,
        'X-Vajra-Signature': resultSig,
      },
    });
    assert.ok(resultRes.status === 200 || resultRes.status === 201, JSON.stringify(resultRes.body));

    const persistedCmd = await prisma.remoteCommand.findUnique({ where: { id: commandId } });
    assert.ok(persistedCmd);
    assert.equal(persistedCmd.status, 'COMPLETED');

    const persistedReceipt = await prisma.commandResult.findUnique({ where: { commandId } });
    assert.ok(persistedReceipt, 'expected persisted CommandResult row in PostgreSQL');
    assert.equal(persistedReceipt.status, 'COMPLETED');
  });

  it('returns analytics from persisted records with PERSISTED dataSource', async () => {
    const reg = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: `pg.analytics.${suffix}@vajra.test`,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'Analytics User',
      },
    });
    assert.equal(reg.status, 201);
    const cookie = extractCookie(reg.headers['set-cookie']);
    const csrf = reg.body.csrfToken as string;

    const tc = await requestJson(server, {
      method: 'POST',
      path: '/api/threatcheck/inspect',
      cookie,
      csrfToken: csrf,
      body: { url: 'http://127.0.0.1:8080/admin?access_token=SECRET123#frag' },
    });
    assert.equal(tc.status, 200, JSON.stringify(tc.body));

    const res = await requestJson(server, {
      method: 'GET',
      path: '/api/analytics/summary',
      cookie,
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.summary?.dataSource, 'PERSISTED');
    assert.ok(typeof res.body.summary?.devices?.totalCount === 'number');
    assert.ok(res.body.summary?.threatChecks?.totalCount >= 1, JSON.stringify(res.body.summary));
  });

  it('enforces append-only AuditLog at the database layer', async () => {
    const rows = await prisma.auditLog.findMany({ take: 1 });
    assert.ok(rows.length > 0, 'expected persisted AuditLog rows in PostgreSQL');
    const id = rows[0].id;
    let updateRejected = false;
    try {
      await prisma.$executeRawUnsafe(
        `UPDATE "AuditLog" SET "eventType" = 'TAMPER' WHERE id = $1::uuid`,
        id
      );
    } catch (err) {
      updateRejected = true;
      const msg = String(err);
      assert.match(msg, /VAJRA_AUDIT_IMMUTABLE|append-only|AuditLog/i);
    }
    assert.equal(updateRejected, true, 'expected AuditLog UPDATE to be rejected by trigger');

    let deleteRejected = false;
    try {
      await prisma.$executeRawUnsafe(
        `DELETE FROM "AuditLog" WHERE id = $1::uuid`,
        id
      );
    } catch (err) {
      deleteRejected = true;
      const msg = String(err);
      assert.match(msg, /VAJRA_AUDIT_IMMUTABLE|append-only|AuditLog/i);
    }
    assert.equal(deleteRejected, true, 'expected AuditLog DELETE to be rejected by trigger');

    const allOrdered = await repo.getAllAuditEventsOrdered();
    const chainVerification = verifyAuditChain(allOrdered);
    assert.equal(chainVerification.valid, true, JSON.stringify(chainVerification));
  });
});

describe('Production fail-closed configuration (source-level)', () => {
  it('server.ts rejects production without a real DATABASE_URL', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const src = fs.readFileSync(path.join(process.cwd(), 'server.ts'), 'utf8');
    assert.match(src, /In-memory fallback is disabled/);
    assert.match(src, /Production requires a non-placeholder DATABASE_URL/);
    assert.match(src, /Production refuses to start without a healthy database/);
  });
});
