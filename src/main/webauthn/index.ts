import type {
  CreateCredentialSuccessData,
  GetCredentialSuccessData,
  CreateCredentialErrorCodes,
  GetCredentialErrorCodes
} from 'electron-webauthn'
import { getWebauthnAddon } from './module'
import { isPublicSuffix } from './psl-check'
import { BrowserWindow, ipcMain } from 'electron'

/**
 * Convert a BufferSource (ArrayBuffer | ArrayBufferView) to a Node/Bun Buffer.
 * Zero-copy when possible (shares memory with the underlying ArrayBuffer).
 */
export function bufferSourceToBuffer(src: BufferSource): Buffer {
  if (Buffer.isBuffer(src)) return src

  // ArrayBuffer / SharedArrayBuffer
  if (
    src instanceof ArrayBuffer ||
    (typeof SharedArrayBuffer !== 'undefined' && src instanceof SharedArrayBuffer)
  ) {
    return Buffer.from(src)
  }

  // ArrayBufferView: Uint8Array, DataView, etc.
  // (DataView is also an ArrayBufferView)
  if (ArrayBuffer.isView(src)) {
    return Buffer.from(src.buffer, src.byteOffset, src.byteLength)
  }

  throw new TypeError('Expected BufferSource (ArrayBuffer or ArrayBufferView)')
}

ipcMain.handle(
  'webauthn:create',
  async (
    event,
    options: CredentialCreationOptions | undefined
  ): Promise<
    CreateCredentialSuccessData | CreateCredentialErrorCodes | 'NotSupportedError' | null
  > => {
    const webauthn = await getWebauthnAddon()
    if (!webauthn) {
      return 'NotSupportedError'
    }

    if (!options) {
      return null
    }

    const publicKeyOptions = options.publicKey

    const senderFrame = event.senderFrame
    if (!senderFrame) {
      return null
    }

    const topFrame = senderFrame.top
    if (!topFrame) {
      // Some weird case where the top frame is not available, its unsafe to continue
      return null
    }

    const currentOrigin = senderFrame.origin
    if (!currentOrigin) {
      return null
    }

    const isMainFrame = topFrame === senderFrame
    let topFrameOrigin: string | undefined
    if (!isMainFrame) {
      topFrameOrigin = topFrame.origin
    }

    const win = BrowserWindow.fromWebContents(event.sender)
    if (!win) {
      return null
    }

    const result = await webauthn.createCredential(publicKeyOptions, {
      currentOrigin,
      topFrameOrigin,
      isPublicSuffix,
      nativeWindowHandle: win.getNativeWindowHandle()
    })

    if (result.success === false) {
      return result.error
    }

    return result.data
  }
)

ipcMain.handle(
  'webauthn:get',
  async (
    event,
    options: CredentialRequestOptions | undefined
  ): Promise<GetCredentialSuccessData | GetCredentialErrorCodes | 'NotSupportedError' | null> => {
    const webauthn = await getWebauthnAddon()
    if (!webauthn) {
      return 'NotSupportedError'
    }

    if (!options) {
      return null
    }

    const publicKeyOptions = options.publicKey

    // Conditional mediation is not supported yet
    if (options.mediation === 'conditional') {
      return 'NotSupportedError'
    }

    const senderFrame = event.senderFrame
    if (!senderFrame) {
      return null
    }

    const topFrame = senderFrame.top
    if (!topFrame) {
      // Some weird case where the top frame is not available, its unsafe to continue
      return null
    }

    const currentOrigin = senderFrame.origin
    if (!currentOrigin) {
      return null
    }

    const isMainFrame = topFrame === senderFrame
    let topFrameOrigin: string | undefined
    if (!isMainFrame) {
      topFrameOrigin = topFrame.origin
    }

    const win = BrowserWindow.fromWebContents(event.sender)
    if (!win) {
      return null
    }

    const result = await webauthn.getCredential(publicKeyOptions, {
      currentOrigin,
      topFrameOrigin,
      isPublicSuffix,
      nativeWindowHandle: win.getNativeWindowHandle()
    })

    if (result.success === false) {
      return result.error
    }

    return result.data
  }
)

ipcMain.handle('webauthn:is-available', async (): Promise<boolean> => {
  const webauthn = await getWebauthnAddon()
  if (!webauthn) {
    return false
  }
  return true
})
