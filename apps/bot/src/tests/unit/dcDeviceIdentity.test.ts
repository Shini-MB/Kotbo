import { describe, expect, test } from 'bun:test';
import { browserIdOf, deviceFingerprint, withFingerprintHash } from '../../services/moderation/dc/deviceIdentity.js';

const desktop = {
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Safari/537.36',
  platform: 'Win32',
  language: 'fr-FR',
  screenResolution: '2560x1440',
  timeZone: 'Europe/Paris',
  canvas: '9f3a11c2',
  webgl: 'Google Inc. (NVIDIA)~ANGLE (NVIDIA, GeForce RTX 3070)',
  browserId: '3b1f0c5e-8a52-4a0e-9c53-0d7c0f5a9e11',
};
const iphone = {
  ...desktop,
  userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Version/18.1 Mobile/15E148 Safari/604.1',
  platform: 'iPhone',
};

describe('browserIdOf', () => {
  test('lit l\'identifiant persistant et refuse ce qui n\'en a pas la forme', () => {
    expect(browserIdOf(desktop)).toBe(desktop.browserId);
    expect(browserIdOf({ browserId: 'x' })).toBeNull();
    expect(browserIdOf({ browserId: { $ne: null } })).toBeNull();
    expect(browserIdOf(null)).toBeNull();
  });
});

describe('deviceFingerprint', () => {
  test('forte sur ordinateur avec canvas et WebGL, indépendante du browserId', () => {
    const a = deviceFingerprint(desktop);
    const b = deviceFingerprint({ ...desktop, browserId: 'ffffffff-ffff-4fff-8fff-ffffffffffff' });
    expect(a?.strength).toBe('strong');
    expect(b?.hash).toBe(a!.hash);
  });

  test('une autre carte graphique donne une autre empreinte', () => {
    const other = deviceFingerprint({ ...desktop, webgl: 'Google Inc. (AMD)~ANGLE (AMD, Radeon RX 6800)' });
    expect(other?.hash).not.toBe(deviceFingerprint(desktop)!.hash);
  });

  test('faible sans rendu graphique (anciennes vérifications) et sur mobile', () => {
    const { canvas: _c, webgl: _w, ...legacy } = desktop;
    expect(deviceFingerprint(legacy)?.strength).toBe('weak');
    expect(deviceFingerprint(iphone)?.strength).toBe('weak');
  });

  test('rien à comparer sans aucune caractéristique d\'appareil', () => {
    expect(deviceFingerprint({ browserId: desktop.browserId })).toBeNull();
    expect(deviceFingerprint(null)).toBeNull();
  });
});

describe('withFingerprintHash', () => {
  test('ajoute fpHash pour une empreinte forte seulement', () => {
    expect(withFingerprintHash(desktop)?.fpHash).toBe(deviceFingerprint(desktop)!.hash);
    expect(withFingerprintHash(iphone)).not.toHaveProperty('fpHash');
  });

  test('écarte un fpHash fourni par le client', () => {
    const forged = withFingerprintHash({ ...iphone, fpHash: 'hash-d-une-victime' });
    expect(forged).not.toHaveProperty('fpHash');
    expect(withFingerprintHash({ ...desktop, fpHash: 'hash-d-une-victime' })?.fpHash).toBe(deviceFingerprint(desktop)!.hash);
  });
});
