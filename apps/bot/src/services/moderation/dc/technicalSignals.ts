/**
 * dc/technicalSignals.ts
 *
 * Signaux techniques issus des vérifications OAuth (SecurityVerification) :
 *  - browser_token      : même profil de navigateur (identifiant persistant)
 *  - device_fingerprint : même appareil (empreinte forte) ou même modèle (faible)
 *  - shared_ip          : même adresse IP exacte
 *  - ip_subnet          : même sous-réseau (/24 IPv4, /64 IPv6) sans IP exacte
 *  - oauth_connections  : comptes tiers liés en commun (Steam, Spotify, etc.)
 */

import prisma from '../../../utils/db.js';
import type { DcSignal } from './types.js';
import { browserIdOf, deviceFingerprint } from './deviceIdentity.js';

type VerifRow = {
  userId: string;
  ipAddress: string | null;
  deviceInfo: unknown;
  connections: unknown;
};

function ipSubnet(ip: string | null): string | null {
  if (!ip) return null;
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return `${parts.slice(0, 4).join(':')}::/64`;
  }
  return null;
}

function connectionKeys(connections: unknown): Set<string> {
  const out = new Set<string>();
  if (!Array.isArray(connections)) return out;
  for (const c of connections) {
    if (c && typeof c === 'object') {
      const conn = c as Record<string, unknown>;
      const type = conn.type ?? conn.provider;
      const id = conn.id ?? conn.accountId ?? conn.name;
      if (type && id) out.add(`${String(type)}:${String(id)}`);
    }
  }
  return out;
}

/** Tout ce qu'un compte a montré au fil de ses vérifications. */
type TechnicalIdentity = {
  ips: Set<string>;
  subnets: Set<string>;
  browsers: Set<string>;
  strongDevices: Set<string>;
  weakDevices: Set<string>;
  connections: Set<string>;
};

function overlap(a: Set<string>, b: Set<string>): string[] {
  return [...a].filter((v) => b.has(v));
}

/** Agrège toutes les vérifications de chaque compte, pas seulement la dernière. */
async function loadIdentities(guildId: string, userIds: string[]): Promise<Map<string, TechnicalIdentity>> {
  const rows: VerifRow[] = await prisma.securityVerification
    .findMany({
      where: { guildId, userId: { in: userIds } },
      select: { userId: true, ipAddress: true, deviceInfo: true, connections: true },
    })
    .catch(() => []);

  const map = new Map<string, TechnicalIdentity>();
  for (const r of rows) {
    let id = map.get(r.userId);
    if (!id) {
      id = { ips: new Set(), subnets: new Set(), browsers: new Set(), strongDevices: new Set(), weakDevices: new Set(), connections: new Set() };
      map.set(r.userId, id);
    }
    if (r.ipAddress) id.ips.add(r.ipAddress);
    const subnet = ipSubnet(r.ipAddress);
    if (subnet) id.subnets.add(subnet);
    const browser = browserIdOf(r.deviceInfo);
    if (browser) id.browsers.add(browser);
    const fp = deviceFingerprint(r.deviceInfo);
    if (fp) (fp.strength === 'strong' ? id.strongDevices : id.weakDevices).add(fp.hash);
    for (const c of connectionKeys(r.connections)) id.connections.add(c);
  }
  return map;
}

/**
 * Produit les signaux techniques entre `userId` et chaque alt suspecté.
 */
export async function computeTechnicalSignals(
  guildId: string,
  userId: string,
  altIds: string[],
): Promise<DcSignal[]> {
  const identities = await loadIdentities(guildId, [userId, ...altIds]);
  const me = identities.get(userId);
  if (!me) return [];

  const signals: DcSignal[] = [];

  for (const altId of altIds) {
    const alt = identities.get(altId);
    if (!alt) continue;

    if (overlap(me.browsers, alt.browsers).length > 0) {
      signals.push({
        type: 'browser_token',
        score: 85,
        label: `Même navigateur que <@${altId}>`,
        matchedUserId: altId,
        detail: `Les deux comptes ont vérifié depuis le même profil de navigateur (identifiant persistant identique). Preuve quasi certaine : seul un appareil partagé l'explique autrement.`,
      });
    } else if (overlap(me.strongDevices, alt.strongDevices).length > 0) {
      signals.push({
        type: 'device_fingerprint',
        score: 55,
        label: `Même empreinte d'appareil que <@${altId}>`,
        matchedUserId: altId,
        detail: `Rendu graphique (canvas, carte graphique), écran, système et fuseau identiques. Preuve forte.`,
      });
    } else if (overlap(me.weakDevices, alt.weakDevices).length > 0) {
      signals.push({
        type: 'device_fingerprint',
        score: 15,
        label: `Même modèle d'appareil que <@${altId}>`,
        matchedUserId: altId,
        detail: `Navigateur, système et écran identiques, sans empreinte graphique exploitable (mobile ou ancienne vérification). Fréquent entre deux personnes différentes : simple renfort.`,
      });
    }

    const sharedIps = overlap(me.ips, alt.ips);
    const sharedSubnets = overlap(me.subnets, alt.subnets);
    if (sharedIps.length > 0) {
      signals.push({
        type: 'shared_ip',
        score: 45,
        label: `Même adresse IP que <@${altId}>`,
        matchedUserId: altId,
        detail: `IP exacte partagée lors d'une vérification OAuth.`,
      });
    } else if (sharedSubnets.length > 0) {
      signals.push({
        type: 'ip_subnet',
        score: 18,
        label: `Même sous-réseau IP que <@${altId}> (${sharedSubnets[0]})`,
        matchedUserId: altId,
        detail: `IP proche (même /24 ou /64). Signal faible seul (peut être une famille/réseau partagé).`,
      });
    }

    const shared = overlap(me.connections, alt.connections).length;
    if (shared > 0) {
      signals.push({
        type: 'oauth_connections',
        score: Math.min(50, 25 + shared * 15),
        label: `${shared} compte(s) tiers lié(s) en commun avec <@${altId}>`,
        matchedUserId: altId,
        detail: `Comptes externes (Steam, Spotify, etc.) identiques dans les connexions Discord. Preuve forte.`,
      });
    }
  }

  return signals;
}
