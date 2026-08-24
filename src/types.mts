import type Bun from 'bun'

export type SocketArtifact = {
  inputPurl: string
  alerts: Array<{
    action: 'error' | 'warn'
    type: string
    props: {
      note?: string | undefined
      description?: string | undefined
      didYouMean?: string | undefined
      alternatePackage?: string | undefined
    } & Record<string, unknown>
    fix?:
      | {
          description: string
        }
      | undefined
  }>
}

export type ScannerImplementation = (
  packages: Bun.Security.Package[],
) => AsyncIterable<SocketArtifact[]>
