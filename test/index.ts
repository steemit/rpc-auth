import 'mocha'
import * as assert from 'assert'
import {PrivateKey} from 'dsteem'

import {sign, validate, JsonRpcRequest} from './../src/'

describe('rpc auth', function() {

    it('signs and validates', function() {

        const key = PrivateKey.fromLogin('foo', 'barman', 'posting')

        const req: JsonRpcRequest = {
            jsonrpc: '2.0',
            id: 123,
            method: 'foo.bar',
            params: {bongo: 'bingo'}
        }

        const signed = sign(req, 'foo', [key])

        assert(signed.params.__signed != undefined)
        assert.equal(signed.jsonrpc, '2.0')
        assert.equal(signed.method, req.method)
        assert.equal(signed.id, req.id)

        validate(signed)

    })

})

