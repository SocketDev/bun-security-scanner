import process from 'node:process'

if (process.env['GITHUB_ACTIONS'] !== 'true') {
  throw new Error('Publish this package through the npm GitHub Actions workflow.')
}
