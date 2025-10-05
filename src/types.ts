import type Bun from 'bun'

export type SocketArtifact = {
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

export type ScannerImplementation = (packages: Array<Bun.Security.Package>) => AsyncIterable<SocketArtifact[]>
