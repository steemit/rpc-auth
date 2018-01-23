import 'mocha'
import * as assert from 'assert'
import {randomBytes} from 'crypto'
import * as fetch from 'node-fetch'
import {PrivateKey, Client, utils, Signature} from 'dsteem'

import {sign, validate, JsonRpcRequest, VerifyMessage, SignedJsonRpcRequest} from './../src/'

const dummyVerify: VerifyMessage = async (message: Buffer, signatures: string[], account: string) => {}

const client = Client.testnet()
const dsteemVerify: VerifyMessage = async (message: Buffer, signatures: string[], account: string) => {
    const opts = {
        hash: message,
        signatures,
        required_posting: [account],
    }
    const rv = await client.database.call('verify_signatures', [opts])
    if (rv.valid !== true) {
        throw new Error('Signature invalid')
    }
}

function randomString(length: number) {
    return randomBytes(length*2)
        .toString('base64')
        .replace(/[^0-9a-z]+/gi, '')
        .slice(0, length)
        .toLowerCase()
}

async function createTestnetAccount(): Promise<{username: string, password: string}> {
    if (process.env['TESTNET_USER'] && process.env['TESTNET_PASSWORD']) {
        return {
            username: process.env['TESTNET_USER'] as string,
            password: process.env['TESTNET_PASSWORD'] as string,
        }
    }
    const password = randomString(32)
    const username = `rpcauth-${ randomString(8) }`
    const response = await fetch('https://testnet.steem.vc/create', {
        method: 'POST',
        body: `username=${ username }&password=${ password }`,
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    }, 1000, (n) => n*10)
    const text = await response.text()
    if (response.status !== 200) {
        throw new Error(`Unable to create user: ${ text }`)
    }
    return {username, password}
}

async function assertThrows(block: () => Promise<any>) {
    try {
        await block()
    } catch (error) {
        return error
    }
    assert.fail('Missing expected exception')
}

describe('rpc auth', function() {
    this.timeout(20 * 1000)
    this.slow(10 * 1000)

    let testAccount: {username: string, password: string}
    let testKey: string
    before(async function() {
        testAccount = await createTestnetAccount()
        testKey = PrivateKey.fromLogin(testAccount.username, testAccount.password, 'posting').toString()
    })

    it('signs and validates', async function() {
        const req: JsonRpcRequest = {
            jsonrpc: '2.0',
            id: 123,
            method: 'foo.bar',
            params: {bongo: 'bingo'}
        }
        const signed = sign(req, testAccount.username, [testKey])

        assert(signed.params.__signed != undefined)
        assert.equal(signed.jsonrpc, '2.0')
        assert.equal(signed.method, req.method)
        assert.equal(signed.id, req.id)

        const verifiedParams = await validate(signed, dummyVerify)
        assert.deepEqual(req.params, verifiedParams)
    })

    it('handles invalid requests', async function() {
        let error
        let req: any = {}

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Invalid JSON RPC Request', String(error))

        req.jsonrpc = '2.0'
        req.method = 'foo.bar'

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Signed payload missing', String(error))

        req.params = {__signed: {}, other: 'foo'}

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Invalid request params', String(error))

        req.params = {__signed: {}}

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Missing account', String(error))

        req.params.__signed.account = 'foo'

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Invalid encoded params', String(error).slice(0, 39))

        req.params.__signed.params = Buffer.from(JSON.stringify({foo: 'bar'})).toString('base64')

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Invalid nonce', String(error))

        req.params.__signed.nonce = 'banana'

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Invalid nonce', String(error))

        req.params.__signed.nonce = randomBytes(8).toString('hex')

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Invalid timestamp', String(error))

        req.params.__signed.timestamp = '2001-01-01T00:00:00Z'

        error = await assertThrows(async () => {
            await validate(req, dummyVerify)
        })
        assert.equal('ValidationError: Signature expired', String(error))

        req.params.__signed.timestamp = new Date().toISOString()

        error = await assertThrows(async () => {
            await validate(req, async () => {
                throw new Error('Nope')
            })
        })
        assert.equal('ValidationError: Verification failed (Nope)', String(error))
    })

    it('handles invalid signatures', async function() {
        this.skip() // This should be broken out as an integration later

        let error, invalid: SignedJsonRpcRequest
        const req: JsonRpcRequest = {
            jsonrpc: '2.0',
            id: 123,
            method: 'foo.bar',
            params: {hello: 'there'}
        }
        const signed = sign(req, testAccount.username, [testKey])

        // valid
        await validate(signed, dsteemVerify)

        // invalid method
        invalid = utils.copy(signed)
        invalid.method = 'foo.bar2'
        error = await assertThrows(async () => {
            await validate(invalid, dsteemVerify)
        })
        assert.equal(String(error), 'ValidationError: Verification failed (Signature invalid)')

        // invalid account
        invalid = utils.copy(signed)
        invalid.params.__signed.account = 'baz'
        error = await assertThrows(async () => {
            await validate(invalid, dsteemVerify)
        })
        assert.equal(String(error), 'ValidationError: Verification failed (Signature invalid)')

        // invalid account
        invalid = utils.copy(signed)
        invalid.params.__signed.account = 'baz'
        error = await assertThrows(async () => {
            await validate(invalid, dsteemVerify)
        })
        assert.equal(String(error), 'ValidationError: Verification failed (Signature invalid)')

        // invalid nonce
        invalid = utils.copy(signed)
        invalid.params.__signed.nonce = randomBytes(8).toString('hex')
        error = await assertThrows(async () => {
            await validate(invalid, dsteemVerify)
        })
        assert.equal(String(error), 'ValidationError: Verification failed (Signature invalid)')

        // invalid params
        invalid = utils.copy(signed)
        invalid.params.__signed.params = 'eyJpbGlrZSI6InR1cnRsZXMifQ=='
        error = await assertThrows(async () => {
            await validate(invalid, dsteemVerify)
        })
        assert.equal(String(error), 'ValidationError: Verification failed (Signature invalid)')

        // invalid timestamp
        invalid = utils.copy(signed)
        invalid.params.__signed.timestamp = '3020-01-01T00:00:00Z'
        error = await assertThrows(async () => {
            await validate(invalid, dsteemVerify)
        })
        assert.equal(String(error), 'ValidationError: Verification failed (Signature invalid)')

        // invalid signatures (other key)
        invalid = utils.copy(signed)
        invalid.params.__signed.signatures = [
            PrivateKey.fromSeed('foobar').sign(randomBytes(32)).toString()
        ]
        error = await assertThrows(async () => {
            await validate(invalid, dsteemVerify)
        })
        assert.equal(String(error), 'ValidationError: Verification failed (Signature invalid)')

        // invalid signatures (same key)
        invalid = utils.copy(signed)
        invalid.params.__signed.signatures = [
            PrivateKey.fromString(testKey).sign(randomBytes(32)).toString()
        ]
        error = await assertThrows(async () => {
            await validate(invalid, dsteemVerify)
        })
        assert.equal(String(error), 'ValidationError: Verification failed (Signature invalid)')
    })

    it('handles invalid requests when signing', function() {
        const req: JsonRpcRequest = {
            jsonrpc: '2.0', id: 123, method: 'foo',
        }
        assert.throws(() => {
            sign(req, testAccount.username, [testKey])
        })
    })

})
