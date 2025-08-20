import { expect, test } from 'bun:test';
import { provider } from './src';

const mockInstallInfo: Bun.Security.Package[] = [
	{
		name: 'bun',
		version: '1.3.0',
		requestedRange: '1.3.0',
		tarball: 'https://registry.npmjs.org/bun/-/bun-1.3.0.tgz',
	},
	{
		name: 'event-stream',
		version: '3.3.6', // This was a known incident in 2018 - https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
		requestedRange: '3.3.6',
		tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz',
	},
];

test('Provider should warn about known malicious packages', async () => {
	const advisories = await provider.scan({ packages: mockInstallInfo });

	expect(advisories.length).toBeGreaterThan(0);
	const advisory = advisories[0]!;

	expect(advisory).toMatchObject({
		level: 'warn',
		package: 'event-stream',
		url: expect.any(String),
		description: expect.any(String),
	});
});
