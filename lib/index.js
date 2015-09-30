'use strict'

var jws = require('jws')

module.exports = JwtKeygrip


/**

 @api public

 Returns a JWT encoder/decoder using a list of keys with a specific algorithm.

 Unlike many JWT implementations, we can't override the algorithm that was 
 specified at initialization time.

 @param   {string|string[]} keys	          - Array of signing keys or comma delimited list of such keys.
 @param   {string}          [algorithm=HS512] - Signing algorithm to use.

 @returns {object} to encode and decode JWT.

 */
function JwtKeygrip(keys, algorithm) {

	// Always return an instance 
	if (!(this instanceof JwtKeygrip))
		return new JwtKeygrip(keys, algorithm)

	// Default signing algorithm is HS512
	algorithm = algorithm || 'HS512'
	keys = keys || []

	// Keys can be a comma delimited list or an array
	if (typeof keys === 'string')
		keys = keys.split(',')
	
	if (!keys.length)
		throw new Error('jwt-keygrip keys can be comma delimited string or array with at least one string')

	// Set keygrip and keygrip.hash
	this.keys = keys
	this.algorithm = algorithm

	return this
}

/**

 @api public

 Encodes the payload and optional headers and returns a token.

 The token is signed using the first key in the key list. Unlike many JWT 
 implementations, we can't override the algorithm that was specified at 
 initialization time. 

 @param      {object} payload	- User data that needs signing.
 @param      {object} headers   - Additional headers (typ and alg are set automatically)

 @returns    {string} token     - Proper JSON Web Token base64 encoded.
 
 */

JwtKeygrip.prototype.encode = function JwtEncode(payload, header) {

	header = clone(header)
	header.typ = 'JWT'
	header.alg = this.algorithm

	delete header.index

	if (!this.keys || !this.keys.length)
		throw new Error('jwt-keygrip keys must be an array of at least one key')

	return jws.sign({header, payload, secret:this.keys[0]})
}


/**

 @api public

 Decodes the token and returns object with header, payload, signature and index.
 The index property is the index of the key that was successful in authenticating
 the token. If the index is not zero then the token should eventually be re-signed.

 @param      {string} token    - a JSON Web Token

 @returns    {object} token    - a decoded token with additional index
 
 */

JwtKeygrip.prototype.decode = function JwtDecode(token, full) {

	if (!this.keys || !this.keys.length)
		throw new Error('jwt-keygrip keys must be an array of at least one key')

	try {
		for (var i in this.keys) {
			if (jws.verify(token, this.algorithm, this.keys[i])) {
				var decoded = jws.decode(token)
				decoded.index = parseInt(i)
				return full? decoded : decoded.payload
			}
		}
	}
	catch(err) {
		// Ignore errors and return null
	}

	return null
}



/**

 @api private

 Quick cloning function to avoid dependencies on other libraries.

 @param      {object} obj	- the object that needs cloning.

 @returns    {object}
 
 */

function clone(obj) {
	let copy = {}
	for (var k in obj)
		copy[k] = obj[k]
	return copy
}

