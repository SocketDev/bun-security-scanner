export interface ScannerFuzzParameters {
  seed: number
  numRuns: number
}

export function scannerFuzzOptions(
  env: Record<string, string | undefined>,
): ScannerFuzzParameters {
  const seed = Number(env['SCANNER_FUZZ_SEED'] ?? 20_260_908)
  const numRuns = Number(env['SCANNER_FUZZ_RUNS'] ?? 100)
  if (
    !Number.isInteger(seed) ||
    seed < -2_147_483_648 ||
    seed > 2_147_483_647
  ) {
    throw new RangeError(
      'Invalid fuzz seed; SCANNER_FUZZ_SEED requires a signed 32-bit integer.',
    )
  }
  if (!Number.isInteger(numRuns) || numRuns < 1 || numRuns > 100_000) {
    throw new RangeError(
      'Invalid fuzz count; SCANNER_FUZZ_RUNS requires an integer from 1 to 100000.',
    )
  }
  return { seed, numRuns }
}
