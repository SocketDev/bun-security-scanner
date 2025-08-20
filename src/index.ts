export const provider: Bun.Security.Provider = {
	version: '1',
	async scan({ packages }) {
		const response = await fetch('https://api.example.com/scan', {
			method: 'POST',
			body: JSON.stringify({
				packages: packages.map(p => ({
					name: p.name,
					version: p.version,
				})),
			}),
			headers: {
				'Content-Type': 'application/json',
			},
		});

		const json = await response.json();
		validateThreatFeed(json);

		// Iterate over reported threats and return an array of advisories. This
		// could longer, shorter or equal length to the input packages. Whatever
		// you return will be shown to the user.#

		const results: Bun.Security.Advisory[] = [];

		for (const item of json) {
			// Advisory levels control installation behavior:
			// - All advisories are always shown to the user regardless of level
			// - Fatal: Installation stops immediately (e.g., backdoors, botnets)
			// - Warning: User prompted in TTY, auto-cancelled in non-TTY (e.g., protestware, adware)

			const isFatal = item.categories.includes('backdoor') || item.categories.includes('botnet');

			const isWarning =
				item.categories.includes('protestware') || item.categories.includes('adware');

			if (!isFatal && !isWarning) continue;

			// Besides the .level property, the other properties are just here
			// for display to the user.
			results.push({
				level: isFatal ? 'fatal' : 'warn',
				package: item.package,
				url: item.url,
				description: item.description,
			});
		}

		// Return an empty array if there are no advisories!
		return results;
	},
};

type ThreatFeedItemCategory =
	| 'protestware'
	| 'adware'
	| 'backdoor'
	| 'botnet'; /* ...maybe you have some others */

interface ThreatFeedItem {
	package: string;
	version: string;
	url: string | null;
	description: string | null;
	categories: Array<ThreatFeedItemCategory>;
}

// You should really use a schema validation library like Zod here to validate
// the feed. This code needs to be defensive rather than fast, so it's sensible
// to check just to be sure.
function validateThreatFeed(json: unknown): asserts json is ThreatFeedItem[] {
	if (!Array.isArray(json)) {
		throw new Error('Invalid threat feed');
	}

	for (const item of json) {
		if (
			typeof item !== 'object' ||
			item === null ||
			!('package' in item) ||
			!('version' in item) ||
			!('url' in item) ||
			!('description' in item) ||
			typeof item.package !== 'string' ||
			typeof item.version !== 'string' ||
			(typeof item.url !== 'string' && item.url !== null) ||
			(typeof item.description !== 'string' && item.description !== null)
		) {
			throw new Error('Invalid threat feed item');
		}
	}
}
