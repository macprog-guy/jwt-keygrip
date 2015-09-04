jwtChain = require('../lib/index.js')
jws      = require('jws')
chai     = require('chai')
should   = chai.should()

describe('jwt-keygrip', function(){

	var key1 = 'abcdefgh12345678'
	var key2 = 'o0110o|o0110o'
	var jwt  = jwtChain([key1, key2])

	it('should throw an error indicating that we need keys', function(done){
		try {
			should.throw(function(){ jwtChain() })
			should.throw(function(){ jwtChain([]) })
			should.throw(function(){ jwtChain('') })
			done()
		}
		catch(err) {
			done(err)
		}
	})

	it('should return a valid JWT signed with the first key', function(done){
		try {			
			var content = {scope:'root'}
			var token1 = jws.sign({
				header:{typ:'JWT',alg:'HS512'},
				payload:content, 
				secret:key1
			})

			var token2 = jwt.encode(content)

			token1.should.equal(token2)

			done()
		}
		catch(err) {
			done(err)
		}
	})

	it('should return a valid payload', function(done){
		try {
			var content1 = {scope:'root'}
			var content2 = jwt.decode(jwt.encode(content1))
			content2.should.eql(content1)
			done()
		}
		catch(err) {
			done(err)
		}
	})


	it('should return a valid payload even when signed with older keys', function(done){
		try {
			var content1 = {scope:'root'}
			var token    = jws.sign({header:{typ:'JWT',alg:'HS512'},payload:content1,secret:key2})
			var content2 = jwt.decode(token,true)
			content2.payload.should.eql(content1)
			content2.index.should.equal(1)
			done()
		}
		catch(err) {
			done(err)
		}
	})

	it('should return null when signed with an invalid key', function(done){
		try {
			var content1 = {scope:'root'}
			var token    = jws.sign({header:{typ:'JWT',alg:'HS512'},payload:content1,secret:'bad-key'})
			var content2 = jwt.decode(token)
			should.not.exist(content2)
			done()
		}
		catch(err) {
			done(err)
		}
	})
})