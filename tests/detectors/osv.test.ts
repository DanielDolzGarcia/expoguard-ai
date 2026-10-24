import { afterEach, describe, expect, it, vi } from 'vitest';
import { compareVersions, defaultOsvClient, fetchVulns, fixedVersionFor, osvSeverity, type OsvVuln } from '../../src/detectors/osv.js';
import { recordedOsvClient } from '../helpers.js';

describe('compareVersions', () => {
  it('ordena por mayor, menor y parche, y la prerelease antes que la final', () => {
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
    expect(compareVersions('0.21.1', '0.21.4')).toBe(-1);
    expect(compareVersions('1.10.0', '1.9.9')).toBe(1);
    expect(compareVersions('2.0.0-beta.1', '2.0.0')).toBe(-1);
    expect(compareVersions('2.0.0', '2.0.0-rc.1')).toBe(1);
  });
});

describe('fixedVersionFor', () => {
  const vuln: OsvVuln = {
    id: 'GHSA-test',
    affected: [
      { package: { name: 'otro', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }] },
      {
        package: { name: 'axios', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.21.2' }, { introduced: '1.0.0' }, { fixed: '1.6.0' }] }],
      },
    ],
  };

  it('elige el tramo que contiene la versión instalada', () => {
    expect(fixedVersionFor(vuln, 'axios', '0.21.1')).toBe('0.21.2');
    expect(fixedVersionFor(vuln, 'axios', '1.2.0')).toBe('1.6.0');
    expect(fixedVersionFor(vuln, 'axios', '0.30.0')).toBeUndefined();
  });
});

describe('osvSeverity', () => {
  it('traduce la severidad de GitHub Advisory y trata lo desconocido como media', () => {
    expect(osvSeverity({ id: 'a', database_specific: { severity: 'CRITICAL' } })).toBe('critical');
    expect(osvSeverity({ id: 'a', database_specific: { severity: 'MODERATE' } })).toBe('medium');
    expect(osvSeverity({ id: 'a', database_specific: { severity: 'LOW' } })).toBe('low');
    expect(osvSeverity({ id: 'a' })).toBe('medium');
  });
});

describe('fetchVulns', () => {
  it('descarga cada aviso una sola vez', async () => {
    const client = recordedOsvClient();
    const [ids] = await client.queryBatch([{ name: 'lodash', version: '4.17.15' }]);
    const map = await fetchVulns(client, [...ids!, ...ids!]);
    expect(map.size).toBe(6);
    expect(client.calls.vulns).toBe(6);
  });
});

describe('defaultOsvClient (fetch simulado)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('envía solo nombre, ecosistema y versión, y mantiene el orden de la respuesta', async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { queries: unknown[] };
      expect(body.queries).toEqual([
        { package: { name: 'axios', ecosystem: 'npm' }, version: '0.21.1' },
        { package: { name: 'react', ecosystem: 'npm' }, version: '19.1.0' },
      ]);
      return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-1' }] }, {}] }));
    });
    vi.stubGlobal('fetch', fetchMock);
    const ids = await defaultOsvClient.queryBatch([
      { name: 'axios', version: '0.21.1' },
      { name: 'react', version: '19.1.0' },
    ]);
    expect(ids).toEqual([['GHSA-1'], []]);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://api.osv.dev/v1/querybatch');
  });

  it('un error HTTP se convierte en excepción', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('caído', { status: 503 })));
    await expect(defaultOsvClient.getVuln('GHSA-1')).rejects.toThrow(/503/);
    await expect(defaultOsvClient.queryBatch([{ name: 'a', version: '1.0.0' }])).rejects.toThrow(/503/);
  });
});
