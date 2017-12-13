/**
 * @file JSONRPC 2.0 request authentication with steem authorities.
 * @author Johan Nordberg <johan@steemit.com>
 */

import {PrivateKey, hexify} from '@steemit/libcrypto'
import {createHash, randomBytes} from 'crypto'

/**
 * Signing constant used to reserve opcode space and prevent cross-protocol attacks.
 * Output of `sha256('steem_jsonrpc_auth')`.
 */
export const K = Buffer.from('3b3b081e46ea808d5a96b08c4bc5003f5e15767090f344faab531ec57565136b', 'hex')

/**
 * JSONRPC 2.0 ID.
 */
export type JsonRpcId = string | number | null

/**
 * JSONRPC 2.0 Request.
 */
export interface JsonRpcRequest {
    jsonrpc: '2.0'
    id: JsonRpcId
    method: string
    params?: any
}

/**
 * Signed JSONRPC 2.0 Request.
 */
export interface SignedJsonRpcRequest extends JsonRpcRequest {
    params: {
        __signed: {
            /** 8 bytes of hex-encoded random data */
            nonce: string
            /** ISO8601 formatted date */
            timestamp: string
            /** Signers steemit account name */
            account: string
            /** JSON+base64 encoded request params */
            params: string
            /** Array of hex-encoded ecdsa signatures */
            signatures: string[]
        }
    }
}

/**
 * Thrown when a request fails validation.
 */
class ValidationError extends Error {

    /** Underlying error. */
    public cause?: Error

    constructor(message: string, cause?: Error) {
        super(message)
        this.name = 'ValidationError'
        if (cause) {
            this.cause = cause
            this.message += ` (${ cause.message })`
        }
    }

}

/**
 * Create request hash to be signed.
 *
 * @param timestamp  ISO8601 formatted date e.g. `2017-11-14T19:40:29.077Z`.
 * @param account    Steem account name that is the signer.
 * @param method     RPC request method.
 * @param params     Base64 encoded JSON string containing request params.
 * @param nonce      8 bytes of random data.
 *
 * @returns bytes to be signed or validated.
 */
function hashMessage(timestamp: string, account: string, method: string,
                     params: string, nonce: Buffer): Buffer {
    const first = createHash('sha256')
    first.update(timestamp)
    first.update(account)
    first.update(method)
    first.update(params)

    const second = createHash('sha256')
    second.update(K)
    second.update(first.digest())
    second.update(nonce)

    return second.digest()
}

/**
 * Sign a JSON RPC Request.
 */
export function sign(request: JsonRpcRequest, account: string, keys: any[]): SignedJsonRpcRequest {
    if (!request.params) {
        throw new Error('Unable to sign a request without params')
    }

    const params = Buffer.from(JSON.stringify(request.params), 'utf8').toString('base64')
    const nonceBytes = randomBytes(8)
    const nonce = nonceBytes.toString('hex')
    const timestamp = new Date().toISOString()

    const message = hashMessage(
        timestamp, account, request.method, params, nonceBytes
    )

    const signatures: string[] = []
    for (let key of keys) {
        if (typeof key === 'string') {
            key = PrivateKey.from(key)
        }
        const signature = hexify(key.sign(message.buffer))
        signatures.push(signature)
    }

    return {
        jsonrpc: '2.0',
        method: request.method,
        id: request.id,
        params: {
            __signed: {
                account,
                nonce,
                params,
                signatures,
                timestamp,
            }
        }
    }
}

/**
 * Verify that message is signed by account and that the signatures are valid, should throw if verification fails.
 *
 * @param message     Message to verify.
 * @param signatures  Signatures to verify.
 * @param account     Account whose posting authority created the signatures.
 *
 * Responsible for:
 *   1. Account must be a valid steem blockchain account
 *   2. All signatures must be a hex string >= 64 chars (32+ bytes decoded)
 *   3. Signature matches message
 *   4. Signature was made with accounts posting authority
 *
 */
export type VerifyMessage = (message: Buffer, signatures: string[], account: string) => Promise<void>

/**
 * Validate a signed JSON RPC request.
 * Throws a {@link ValidationError} if the request fails validation.
 *
 * @returns Resolved request params.
 */
export async function validate(request: SignedJsonRpcRequest, verify: VerifyMessage): Promise<any> {

    if (request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
        throw new ValidationError('Invalid JSON RPC Request')
    }

    if (request.params == undefined || request.params.__signed == undefined) {
        throw new ValidationError('Signed payload missing')
    }

    if (Object.keys(request.params).length !== 1) {
        throw new ValidationError('Invalid request params')
    }

    const signed = request.params.__signed

    if (signed.account == undefined) {
        throw new ValidationError('Missing account')
    }

    let params: string
    try {
        const jsonString = Buffer.from(signed.params, 'base64').toString('utf8')
        params = JSON.parse(jsonString)
    } catch (cause) {
        throw new ValidationError('Invalid encoded params', cause)
    }

    if (signed.nonce == undefined || typeof signed.nonce !== 'string') {
        throw new ValidationError('Invalid nonce')
    }
    const nonce = Buffer.from(signed.nonce, 'hex')
    if (nonce.length !== 8) {
        throw new ValidationError('Invalid nonce')
    }

    const timestamp = Date.parse(signed.timestamp)
    if (Number.isNaN(timestamp)) {
        throw new ValidationError('Invalid timestamp')
    }

    if (Date.now() - timestamp > 60 * 1000) {
        throw new ValidationError('Signature expired')
    }

    const message = hashMessage(
        signed.timestamp, signed.account, request.method, signed.params, nonce
    )

    try {
        await verify(message, signed.signatures, signed.account)
    } catch (cause) {
        throw new ValidationError('Verification failed', cause)
    }

    return params
}
