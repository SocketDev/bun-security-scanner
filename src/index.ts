import type Bun from 'bun'
import path from 'node:path'
import os from 'node:os'

let SOCKET_API_KEY = process.env.SOCKET_API_KEY

if (typeof SOCKET_API_KEY !== 'string') {
	// get OS app data directory
	let dataHome = process.platform === 'win32'
			? Bun.env.LOCALAPPDATA
			: Bun.env.XDG_DATA_HOME

	// fallback
	if (!dataHome) {
		if (process.platform === 'win32') throw new Error('missing %LOCALAPPDATA%')

		const home = os.homedir()

		dataHome = path.join(home, ...(process.platform === 'darwin'
			? ['Library', 'Application Support']
			: ['.local', 'share']
		))
	}

	// append `socket/settings`
	const defaultSettingsPath = path.join(dataHome, 'socket', 'settings')
	const file = Bun.file(defaultSettingsPath)

	// attempt to read token from socket settings
	if (await file.exists()) {
		const rawContent = await file.text()
		// rawContent is base64, must decode

		try {
			SOCKET_API_KEY = JSON.parse(Buffer.from(rawContent, 'base64').toString().trim()).apiToken
		} catch {
			throw new Error('error reading Socket settings')
		}
	}
}

type SocketBatchEndpointBody = {
	components: {
		purl: string
	}[]
}

type SocketArtifact = {
	inputPurl: string
	alerts: {
		action: 'error' | 'warn'
		type: string,
		props: {
			note?: string,
			didYouMean?: string,
		} & Record<string, any>
		fix?: {
			description: string
		}
	}[]
}

let flightImplementation: FlightImplementation

if (SOCKET_API_KEY) {
	flightImplementation = async function*(packages) {
		let artifacts: SocketArtifact[] = []
		let batch: Bun.Security.Package[] = []
		const max_sending = 30
		const max_batch_length = 1
		let in_flight = 0
		const pending: Set<Promise<void>> = new Set()
		async function startFlight() {
			const purls = batch.map(p => `pkg:npm/${p.name}@${p.version}`)
			batch = []
			in_flight += purls.length
			if (in_flight >= max_sending) {
				if (pending.size !== 0) {
					await Promise.race([...pending])
				} else {
					// bug here
				}
			}
			const body = JSON.stringify({
				components: purls.map(purl => {
					return {
						purl
					}
				})
			} satisfies SocketBatchEndpointBody)

			const flight = fetch(`https://api.socket.dev/v0/purl?actions=error,warn`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${SOCKET_API_KEY}`
				},
				body,
			}).then(
				async (res) => {
					if (!res.ok) {
						throw new Error(`Socket Security Scanner: Received ${res.status} from server`)
					}
					const data = await res.text()
					artifacts.push(...data.split('\n').filter(Boolean).map(line => JSON.parse(line)))
				}
			)
			pending.add(flight)
			flight.finally(() => {
				in_flight -= purls.length
				pending.delete(flight)
			})
		}

		while (packages.length > 0) {
			const item = packages.shift()!
			if (!item) {
				break
			}
			batch.push(item)
			if (batch.length >= max_batch_length) {
				await startFlight()
				if (artifacts.length > 0) {
					const tmp = artifacts
					artifacts = []
					yield tmp
				}
			}
		}
		await startFlight()
		await Promise.all([...pending])
		if (artifacts.length > 0) {
			yield artifacts
		}
	}
} else {
	console.log(
		`Socket Security Scanner results using free configuration. Provide SOCKET_API_KEY to Socket for granular controls.`
	)
	flightImplementation = async function*(packages) {
		let artifacts: SocketArtifact[] = []
		let batch: Bun.Security.Package[] = []
		const max_sending = 20
		const max_batch_length = 50
		let in_flight = 0
		const pending: Set<Promise<void>> = new Set()
		async function startFlight() {
			const purls = batch.map(p => `pkg:npm/${p.name}@${p.version}`)
			batch = []
			in_flight += purls.length
			if (in_flight >= max_sending) {
				if (pending.size !== 0) {
					await Promise.race([...pending])
				} else {
					// bug here
				}
			}
			const urls = purls.map(purl => `https://firewall-api.socket.dev/purl/${encodeURIComponent(purl)}`)
			const flights = Promise.all(urls.map(async url => {
				const res = await fetch(url)
				if (!res.ok) {
					throw new Error(`Socket Security Scanner: Received ${res.status} from server`)
				}
				const data = await res.text()
				artifacts.push(...data.split('\n').filter(Boolean).map(line => JSON.parse(line)))
			})).then(()=>{})
			flights.finally(() => {
				in_flight -= purls.length
				pending.delete(flights)
			})
			pending.add(flights)
		}
		while (packages.length > 0) {
			const item = packages.shift()!
			if (!item) {
				break
			}
			batch.push(item)
			if (batch.length >= max_batch_length) {
				await startFlight()
				if (artifacts.length > 0) {
					const tmp = artifacts
					artifacts = []
					yield tmp
				}
			}
		}
		await startFlight()
		await Promise.all([...pending])
		if (artifacts.length > 0) {
			yield artifacts
		}
	}
}

type FlightImplementation = (packages: Array<Bun.Security.Package>) => AsyncIterable<SocketArtifact[]>
class SocketSecurityScan implements Bun.Security.Scanner {
	version: '1' = '1'
	flightImplementation: FlightImplementation
	constructor(flightImplementation: FlightImplementation) {
		this.flightImplementation = flightImplementation
	}
	async scan({ packages }: { packages: Array<Bun.Security.Package> }) {
		const results: Bun.Security.Advisory[] = []
		while (packages.length) {
			const flightResults = this.flightImplementation(packages)
			for await (const artifacts of flightResults) {
				for (const artifact of artifacts) {
					if (artifact.alerts && artifact.alerts.length > 0) {
						for (const alert of artifact.alerts) {
							let description = ''
							if (alert.type === 'didYouMean') {
								description = `This package could be a typo-squatting attempt of another package (${alert.props.alternatePackage}).`
							}
							if (alert.props.description) {
								description = description ? `${description}\n\n${alert.props.description}` : alert.props.description
							}
							if (alert.props.note) {
								description = description ? `${description}\n\n${alert.props.note}` : alert.props.note
							}
							const fix = alert.fix?.description
							if (fix) {
								description = description ? `${description}\n\nFix: ${fix}` : `Fix: ${fix}`
							}
							results.push({
								level: alert.action === 'error' ? 'fatal' : 'warn',
								package: artifact.inputPurl,
								url: null,
								description
							})
						}
					}
				}
			}
		}
		return results
	}
}
export const scanner: Bun.Security.Scanner = new SocketSecurityScan(flightImplementation);
