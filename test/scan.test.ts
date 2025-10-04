import { expect, test } from 'bun:test';
import { scanner } from '@socketsecurity/bun-security-scanner';

const mockInstallInfo: Bun.Security.Package[] = [
	{
		name: 'lodahs',
		version: '0.0.1-security',
		requestedRange: '^0.0.0',
		tarball: 'https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz',
	}
];

test('Scanner should warn about known malicious packages', async () => {
	const advisories = await scanner.scan({ packages: mockInstallInfo });

	expect(advisories.length).toBeGreaterThan(0);
	const advisory = advisories[0]!;

	expect(advisory).toMatchObject({
		description: expect.any(String),
		level: 'fatal',
		package: 'pkg:npm/lodahs@0.0.1-security',
		url: null,
	});
});
