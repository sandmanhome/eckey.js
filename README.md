## eckey.js

secp256k1 secp256r1 sm2p256v1 keytools by js
use sha256 for sign

## Usage

``` js
const keyTools- = require('eckey.js');
```

### newKeyPair

```js
'use strict'
const assert = require("assert");
const keyTools- = require('eckey.js');

const key = keyTools.newKeyPair()
console.log(key)
assert(keyTools.privateKeyToPublicKey(key.priKey) == key.pubKey)
```

### sign

```js
'use strict'
const assert = require("assert");
const keyTools- = require('eckey.js');

let data = Buffer.from("Hello World!");

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
```

#### LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2014.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.
