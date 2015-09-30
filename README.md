# Introduction

jwt-keygrip is a wrapper around [node-jws](https://github.com/brianloveswords/node-jws) that allows for more than one simultaneously valid signing keys like [keygrip](https://github.com/crypto-utils/keygrip). The implementation does not use keygrip.

# Installation

	$ npm install jwt-keygrip

# Usage

##### `constructor(String|Array<String> keys [, String algorithm])`

Returns a new JWT encoder/decoder that uses an array of keys to validate tokens but only the first key to encode tokens.

- `keys`: If a string should be a comma delimited list of signing keys (keys can't contain commas) otherwise keys is just an array of strings. When encoding tokens only the first (and freshest) key will be used.
- `algorithm`: should be one of the encoding algorithms that jws supports. Defaults to 'HS512'.

```js
var jwt = require('jwt-keygrip')('12345,54321,xxoxx,ooxoo')
```



<hr>

##### `encode(Object payload [,Object headers]) -> JWT`

Encodes a payload and optional headers to return a signed JWT.

- `payload`: an object with any content that is JSON serializable.
- `headers`: additional headers to add to the JWT. Won't override `typ` nor `alg`.

```js
var token = jwt.encode({email:'em@macprog.com', scope:'root'})
```




<hr>
##### `decode(String token [,Boolean full]) -> Object`

Encodes a payload and optional headers to return a signed JWT. A token is considered valid if it has been signed with any of the above specified signatures. If the token cannot be verified then returns `null`.

- `token`: a JWT originally signed with any of the provided keys.
- `full`: if true returns an an object `{headers,payload,signature}` otherwise returns only the payload. Defaults to false.

```js
var token = jwt.decode( mytoken )
```

