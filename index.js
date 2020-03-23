#!/usr/bin/env node

'use strict'

const ripemd160 = require('ripemd160')
const bs = require('bs58')
const BN = require('bn.js')
const elliptic = require('elliptic')
const EC = elliptic.ec
const hash = require('hash.js')
const debug = require('debug')

module.exports = {
  eck1: new EC('secp256k1')
  , ecr1: new EC('p256')
  , ecsm2: new EC(new elliptic.curves.PresetCurve({
    type: 'short',
    prime: null,
    p: 'fffffffe ffffffff ffffffff ffffffff ffffffff 00000000 ffffffff ffffffff',
    a: 'fffffffe ffffffff ffffffff ffffffff ffffffff 00000000 ffffffff fffffffc',
    b: '28e9fa9e 9d9f5e34 4d5a9e4b cf6509a7 f39789f5 15ab8f92 ddbcbd41 4d940e93',
    n: 'fffffffe ffffffff ffffffff ffffffff 7203df6b 21c6052b 53bbf409 39d54123',
    hash: hash.sha256,
    gRed: false,
    g: [
      '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7',
      'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0'
    ]
  }))

  , stringToKey: (pk) => {
    const arr = pk.split('_')
    if (arr.length !== 3 || !['PVT', 'PUB', 'SIG'].includes(arr[0])) {
      throw new Error('unrecognized key format')
    }
    const type = arr[1]
    const bytes = bs.decode(arr[2])
    const keyLength = bytes.length - 4
    const payload = bytes.slice(0, keyLength)
    const checksum = bytes.slice(keyLength)
    const buf = Buffer.concat([payload, Buffer.from(type)])
    const expected = new ripemd160().update(buf).digest().slice(0, 4)
    if (!checksum.equals(expected)) {
      throw new Error('checksum doesn\'t match')
    }
    return { prefix: arr[0], type: type, payload: payload }
  }

  , keyToString: (prefix, type, payload) => {
    const bytes = Buffer.concat([Buffer.from(payload), Buffer.from(type)])
    const checksum = new ripemd160().update(bytes).digest().slice(0, 4)
    return prefix + '_' + type + '_'
      + bs.encode(Buffer.concat([Buffer.from(payload), checksum]))
  }

  , getPointFromEcc: (n, ec) => {
    if (ec == module.exports.ecsm2) {
      ec = module.exports.ecsm2
    } else {
      ec = module.exports.eck1
    }

    const pvt = new BN(n, 'be')
    debug('pvt =', pvt.toString('hex'))
    const pub = ec.g.mul(pvt)
    debug('x =', pub.getX().toString('hex'))
    debug('y =', pub.getY().toString('hex'))
    const y = pub.getY().isEven() ? 2 : 3
    return Buffer.from([y].concat(pub.getX().toArray()))
  }

  , privateKeyToPublicKey: (privateKey) => {
    const { type, payload } = module.exports.stringToKey(privateKey)
    let ec
    if (type == 'SM2') {
      ec = module.exports.ecsm2
    } else {
      ec = module.exports.eck1
    }

    return module.exports.keyToString('PUB', type, module.exports.getPointFromEcc(payload, ec))
  }

  , newKeyPair: (ec) => {
    let type
    if (ec == module.exports.ecsm2) {
      ec = module.exports.ecsm2
      type = 'SM2'
    } else {
      ec = module.exports.eck1
      type = 'K1'
    }

    const key = ec.genKeyPair()

    const pri = key.getPrivate()
    const prikey = module.exports.keyToString('PVT', type, pri.toBuffer())

    const pub = key.getPublic()
    const y = pub.getY().isEven() ? 2 : 3
    const pubkey = module.exports.keyToString('PUB', type
      , Buffer.from([y].concat(pub.getX().toArray())))
    return { priKey: prikey, pubKey: pubkey }
  }

  , isCanonical: (n) => {
    // MUST be in range [0x0080..00, 0x7fff..ff]
    return !(n[0] & 0x80) && !(n[0] === 0 && !(n[1] & 0x80))
  }
  , signFromECKey: (digest, ecKey) => {
    let sigData
    let tries = 0
    for (; ;) {
      const sig = ecKey.sign(digest, { canonical: true, pers: [++tries] })
      const r = sig.r.toArray()
      const s = sig.s.toArray()
      if (!module.exports.isCanonical(r) || !module.exports.isCanonical(s)) {
        continue
      }
      return new Uint8Array([sig.recoveryParam + 27].concat(r, s));
    }
  }

  , sign: (digest, priKey) => {
    const key = module.exports.stringToKey(priKey)
    const type = key.type
    let ec
    if (type == 'SM2') {
      ec = module.exports.ecsm2
    } else {
      ec = module.exports.eck1
    }
    const ecKey = ec.keyFromPrivate(key.payload)

    const data = hash.sha256().update(digest).digest()
    const sigData = module.exports.signFromECKey(data, ecKey)
    return module.exports.keyToString('SIG', type, sigData)
  }

  , recover: (digest, sig) => {
    const data = hash.sha256().update(digest).digest()
    const h = new BN(data, 16, 'be')
    const {prefix, type, payload } = module.exports.stringToKey(sig)
    if (prefix != "SIG") {
      return null;
    }
  
    const x = new BN(payload.slice(1, 1 + 32))
    debug('x =', x.toString(16))
    const s = new BN(payload.slice(1 + 32, 1 + 32 + 32))
    debug('s =', s.toString(16))
    
    let ec
    if (type == 'SM2') {
      ec = module.exports.ecsm2
    } else {
      ec = module.exports.eck1
    }

    const rg = ec.curve.pointFromX(x, (payload[0] - 27) & 1)
    debug('rg = [' + rg.getX().toString(16) + ', ' + rg.getY().toString(16) + ']')
  
    // u1 = h/s
    const sinv = s.invm(ec.n)
    const u1 = h.mul(sinv).umod(ec.n)
    const p1 = ec.g.mul(u1)
    const opposite_p1 = ec.curve.pointFromX(p1.getX(), !p1.getY().isOdd())
    const u2 = rg.add(opposite_p1)
  
    const xinv = x.invm(ec.n)
    const K = u2.mul(s).mul(xinv)
  
    debug('K = [' + K.getX().toString(16) + ', ' + K.getY().toString(16) + ']')
    return module.exports.keyToString('PUB', type, Buffer.from(
      [K.getY().isEven() ? 2 : 3].concat(K.getX().toArray())))
  },
}
