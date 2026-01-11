import type { CreateCredentialSuccessData, GetCredentialSuccessData } from 'electron-webauthn'

export interface CreateCredentialJsonResponse {
  id: string
  rawId: string
  response: {
    clientDataJSON: string
    authenticatorData: string
    transports: string[]
    publicKey: string
    publicKeyAlgorithm: number
    attestationObject: string
  }
  authenticatorAttachment: 'platform'
  clientExtensionResults: CreateCredentialSuccessData['extensions']
  type: 'public-key'
}

export interface AssertCredentialJsonResponse {
  id: string
  rawId: string
  response: {
    clientDataJSON: string
    authenticatorData: string
    signature: string
    userHandle: string
  }
  authenticatorAttachment: 'platform'
  clientExtensionResults: {
    prf?: {
      results?: {
        first: string
        second?: string
      }
    }
    largeBlob?: {
      blob?: string
      written?: boolean
    }
  }
  type: 'public-key'
}

export function fromUrlB64ToB64(urlB64Str: string): string {
  let output = urlB64Str.replace(/-/g, '+').replace(/_/g, '/')
  switch (output.length % 4) {
    case 0:
      break
    case 2:
      output += '=='
      break
    case 3:
      output += '='
      break
    default:
      throw new Error('Illegal base64url string!')
  }

  return output
}

export function fromB64ToArray(str: string | null | undefined): Uint8Array | null {
  if (str == null) {
    return null
  }

  const binaryString = globalThis.atob(str)
  const bytes = new Uint8Array(binaryString.length)
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }
  return bytes
}

export function stringToBuffer(str: string): ArrayBuffer {
  const array = fromB64ToArray(fromUrlB64ToB64(str))
  if (array === null) {
    throw new Error('Failed to convert base64 to array')
  }
  return array.buffer as ArrayBuffer
}

export function createResultToJson(
  result: CreateCredentialSuccessData
): CreateCredentialJsonResponse {
  return {
    id: result.credentialId,
    rawId: result.credentialId,
    response: {
      clientDataJSON: result.clientDataJSON,
      authenticatorData: result.authData,
      transports: result.transports,
      publicKey: result.publicKey,
      publicKeyAlgorithm: result.publicKeyAlgorithm,
      attestationObject: result.attestationObject
    },
    authenticatorAttachment: 'platform',
    clientExtensionResults: result.extensions,
    type: 'public-key'
  }
}

export function getResultToJson(result: GetCredentialSuccessData): AssertCredentialJsonResponse {
  const clientExtensionResults: AssertCredentialJsonResponse['clientExtensionResults'] = {}

  if (result.extensions?.prf?.results) {
    clientExtensionResults.prf = {
      results: {
        first: result.extensions.prf.results.first,
        second: result.extensions.prf.results.second
      }
    }
  }

  if (result.extensions?.largeBlob) {
    clientExtensionResults.largeBlob = {
      blob: result.extensions.largeBlob.blob,
      written: result.extensions.largeBlob.written
    }
  }

  return {
    id: result.credentialId,
    rawId: result.credentialId,
    response: {
      clientDataJSON: result.clientDataJSON,
      authenticatorData: result.authenticatorData,
      signature: result.signature,
      userHandle: result.userHandle
    },
    authenticatorAttachment: 'platform',
    clientExtensionResults,
    type: 'public-key'
  }
}

export function mapCredentialRegistrationResult(
  result: CreateCredentialSuccessData
): PublicKeyCredential {
  const response: AuthenticatorAttestationResponse = {
    clientDataJSON: stringToBuffer(result.clientDataJSON),
    attestationObject: stringToBuffer(result.attestationObject),
    getAuthenticatorData(): ArrayBuffer {
      return stringToBuffer(result.authData)
    },
    getPublicKey(): ArrayBuffer {
      return stringToBuffer(result.publicKey)
    },
    getPublicKeyAlgorithm(): number {
      return result.publicKeyAlgorithm
    },
    getTransports(): string[] {
      return result.transports
    }
  }

  const extensionResults: AuthenticationExtensionsClientOutputs = {}
  if (result.extensions.credProps) {
    extensionResults.credProps = result.extensions.credProps
  }
  if (result.extensions.prf) {
    const prfResults: {
      enabled?: boolean
      results?: {
        first: ArrayBuffer
        second?: ArrayBuffer
      }
    } = {}
    if (result.extensions.prf.enabled !== undefined) {
      prfResults.enabled = result.extensions.prf.enabled
    }
    if (result.extensions.prf.results?.first) {
      prfResults.results = {
        first: stringToBuffer(result.extensions.prf.results.first),
        second: result.extensions.prf.results.second
          ? stringToBuffer(result.extensions.prf.results.second)
          : undefined
      }
    }
    extensionResults.prf = prfResults
  }
  if (result.extensions.largeBlob) {
    extensionResults.largeBlob = result.extensions.largeBlob
  }

  const credential: PublicKeyCredential = {
    id: result.credentialId,
    rawId: stringToBuffer(result.credentialId),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response,
    getClientExtensionResults: () => extensionResults,
    toJSON: () => createResultToJson(result)
  }

  // Modify prototype chains to fix `instanceof` calls.
  // This makes these objects indistinguishable from the native classes.
  // Unfortunately PublicKeyCredential does not have a javascript constructor so `extends` does not work here.
  Object.setPrototypeOf(credential.response, AuthenticatorAttestationResponse.prototype)
  Object.setPrototypeOf(credential, PublicKeyCredential.prototype)

  return credential
}

export function mapCredentialAssertResult(result: GetCredentialSuccessData): PublicKeyCredential {
  const response: AuthenticatorAssertionResponse = {
    authenticatorData: stringToBuffer(result.authenticatorData),
    clientDataJSON: stringToBuffer(result.clientDataJSON),
    signature: stringToBuffer(result.signature),
    userHandle: stringToBuffer(result.userHandle)
  }

  const extensionResults: AuthenticationExtensionsClientOutputs = {}

  if (result.extensions?.prf?.results) {
    extensionResults.prf = {
      results: {
        first: stringToBuffer(result.extensions.prf.results.first),
        second: result.extensions.prf.results.second
          ? stringToBuffer(result.extensions.prf.results.second)
          : undefined
      }
    }
  }

  if (result.extensions?.largeBlob) {
    extensionResults.largeBlob = {
      blob: result.extensions.largeBlob.blob
        ? stringToBuffer(result.extensions.largeBlob.blob)
        : undefined,
      written: result.extensions.largeBlob.written
    }
  }

  const credential: PublicKeyCredential = {
    id: result.credentialId,
    rawId: stringToBuffer(result.credentialId),
    type: 'public-key',
    response,
    getClientExtensionResults: () => extensionResults,
    authenticatorAttachment: 'platform',
    toJSON: () => getResultToJson(result)
  }

  // Modify prototype chains to fix `instanceof` calls.
  // This makes these objects indistinguishable from the native classes.
  // Unfortunately PublicKeyCredential does not have a javascript constructor so `extends` does not work here.
  Object.setPrototypeOf(credential.response, AuthenticatorAssertionResponse.prototype)
  Object.setPrototypeOf(credential, PublicKeyCredential.prototype)

  return credential
}
