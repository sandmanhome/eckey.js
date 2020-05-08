#!/usr/bin/env node

'use strict'
const assert = require("assert");
const keyTools = require('../')

let data = Buffer.from(
  // chainId
  'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906'
  // serializedTransaction
  + 'c0fbc75d000000000000000000000000'
  // sha256 of serializedContextFreeData
  + '0000000000000000000000000000000000000000000000000000000000000000', 'hex')

data = Buffer.from("Hello World!");

// keyTools.eck1 or keyTools.ecr1 or keyTools.ecsm2 (default)
const key = keyTools.newKeyPair()
console.log(key)
assert(keyTools.privateKeyToPublicKey(key.priKey) == key.pubKey)

//sign will sha256 of data
const sigStr = keyTools.sign(data, key.priKey);
console.log(sigStr)

//recover will sha256 of data
const recoverKey = keyTools.recover(data, sigStr)
console.log('recoverKey: ' + recoverKey)
assert(recoverKey == key.pubKey)
