#!/usr/bin/env node

'use strict'
const assert = require("assert");

const keyTools = require('../')
const hash = require('hash.js')

let data = Buffer.from(
  // chainId
  'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906'
  // serializedTransaction
  + 'c0fbc75d000000000000000000000000'
  // sha256 of serializedContextFreeData
  + '0000000000000000000000000000000000000000000000000000000000000000', 'hex')

data = Buffer.from("Hello World!");

// keyTools.ecsm2 or keyTools.eck1 (default)
const key = keyTools.newKeyPair(keyTools.ecsm2)
console.log(key)
console.log('privateKeyToPublicKey: ' + keyTools.privateKeyToPublicKey(key.priKey))

//digest need sha256
const sigStr = keyTools.sign(data, key.priKey);
console.log(sigStr)

const recoverKey = keyTools.recover(data, sigStr)
console.log(recoverKey)
assert(recoverKey == key.pubKey)
