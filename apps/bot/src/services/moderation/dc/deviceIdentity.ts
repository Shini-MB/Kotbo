/**
 * dc/deviceIdentity.ts - Identité technique d'un navigateur, lue dans le
 * clientInfo que la page /verify envoie (stocké dans SecurityVerification.deviceInfo).
 *
 * Deux niveaux de preuve :
 *  - browserId   : identifiant aléatoire posé dans le stockage du navigateur.
 *                  Deux comptes qui le partagent ont vérifié depuis le même
 *                  profil de navigateur.
 *  - empreinte   : hash des caractéristiques de l'appareil. « strong » seulement
 *                  si le rendu graphique (canvas + WebGL) est connu et que
 *                  l'appareil n'est pas un mobile ; sinon « weak ».
 *
 * Fonctions pures, sans base ni Discord.
 */

import { createHash } from 'node:crypto';

const BROWSER_ID_RE = /^[a-f0-9-]{16,64}$/i;

/** Champs de l'appareil qui entrent dans l'empreinte (jamais browserId ni fpHash). */
const BASE_KEYS = [
  'userAgent',
  'platform',
  'language',
  'screenResolution',
  'timeZone',
  'deviceMemory',
  'hardwareConcurrency',
  'colorDepth',
  'pixelRatio',
  'maxTouchPoints',
] as const;
const RENDER_KEYS = ['canvas', 'webgl'] as const;

// Tous les téléphones d'un même modèle rendent la même image : leur empreinte
// désigne un modèle, pas une personne.
const MOBILE_UA_RE = /Mobi|Android|iPhone|iPad|iPod/i;

export type DeviceFingerprint = { hash: string; strength: 'strong' | 'weak' };

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

export function browserIdOf(deviceInfo: unknown): string | null {
  const id = asRecord(deviceInfo)?.browserId;
  return typeof id === 'string' && BROWSER_ID_RE.test(id) ? id : null;
}

export function deviceFingerprint(deviceInfo: unknown): DeviceFingerprint | null {
  const src = asRecord(deviceInfo);
  if (!src) return null;

  const picked: [string, unknown][] = [];
  for (const key of [...BASE_KEYS, ...RENDER_KEYS]) {
    const value = src[key];
    if (value !== undefined && value !== null && value !== '') picked.push([key, value]);
  }
  if (picked.length === 0) return null;

  const hasRender = RENDER_KEYS.every((key) => typeof src[key] === 'string' && src[key] !== '');
  const mobile = typeof src.userAgent === 'string' && MOBILE_UA_RE.test(src.userAgent);
  const hash = createHash('sha256').update(JSON.stringify(picked)).digest('hex').slice(0, 24);
  return { hash, strength: hasRender && !mobile ? 'strong' : 'weak' };
}

/**
 * Prépare le deviceInfo à stocker : ajoute `fpHash` quand l'empreinte est forte,
 * pour retrouver les autres comptes du même appareil par une requête JSON.
 * Un `fpHash` envoyé par le client est toujours écarté.
 */
// `any` : le résultat part tel quel dans une colonne Json de Prisma.
export function withFingerprintHash(clientInfo: unknown): Record<string, any> | null {
  const src = asRecord(clientInfo);
  if (!src) return null;
  const { fpHash: _clientSupplied, ...info } = src;
  const fp = deviceFingerprint(info);
  return fp?.strength === 'strong' ? { ...info, fpHash: fp.hash } : info;
}
