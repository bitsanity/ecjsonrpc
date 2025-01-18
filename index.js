const crypto = require( 'node:crypto' )
const ecies = require( 'eciesjs' )
const EC = require( 'elliptic' ).ec
var ec = new EC( 'secp256k1' )

// ===========================================================================
// a javascript library implementing a secure json-rpc based protocol, useful
// when calling secure services via websockets.
// ===========================================================================

// client and service exchange stringified versions of encrypted message
// objects over the websocket
//
// msghex : stringified object encrypted with ecies and hex-encoded
// sighex : an ECDSA digital signature of the message
// spkhex : pubkey of the message signer in hex

exports.BLACKMSG = {
  msghex : "",
  sighex : "",
  spkhex : ""
}

// a service automatically returns this unencrypted whenever something connects
//
// params[0] : service's session pubkey as a hex string
//        id : ignored for this message type

exports.REDHELLO = {
  jsonrpc: "2.0",
  method: "hello",
  params: [],
  id: 0
}

// Standard generic JSON-RPC 2.0 request having a method and parameters, and
// a client-specified id the server includes in the corresponding response.

exports.REQUEST = {
  jsonrpc: "2.0",
  method: "",
  params: [],
  id: 0
}

// JSON-RPC 2.0 response returned when a request has been processed ok.
// The id will be the same as set by the client in the request.

exports.RESPONSE = {
  jsonrpc: "2.0",
  result: {},
  id: 0
}

// Returned by a service that encounters an error when processing a request,
// with id matching the request and details explaining the error

exports.ERRORRESPONSE = {
  jsonrpc: "2.0",
  error: {
    code: 0,
    message: ''
  },
  id: 0
}

// craft a REDHELLOMSG instance containing the session pubkey created for
// this connection in the right spot

exports.makeRedHello = function( sesspubkeyhex ) {
  let result = JSON.parse( JSON.stringify(exports.REDHELLO) )
  result.params = [ sesspubkeyhex ]
  return result
}

// craft a plain error object for return to UI or logging

exports.makeErrorObj = function( errcode, errmessage, id ) {
  let result = JSON.parse( JSON.stringify(exports.ERRORRESPONSE) )
  result.error.code = errcode
  result.error.message = errmessage
  result.id = id
  return result
}

// decrypt black message object that has a message field encrypted with
// eciesjs, a digital signature field and a field that identifies the sender

exports.blackToRed = function( myprivkeyhex, blackobj ) {
  let msg = Buffer.from( blackobj.msghex, 'hex' )
  let sig = Buffer.from( blackobj.sighex, 'hex' )
  let msghash = crypto.createHash('sha256').update(msg).digest()

  let pubkey = ec.keyFromPublic( blackobj.spkhex, 'hex' )
  if (!pubkey.verify(msghash, sig))
    throw 'Sender verification failure'

  let red = ecies.decrypt( myprivkeyhex, msg )
  return JSON.parse( red )
}

// encrypt red object to black message object
//
// txprivkeyhex : sender's private key in hex format
//  rxpubkeyhex : receiver's public key in hex format
//       redobj : an object to be encrypted as the message

exports.redToBlack = function( txprivkeyhex, rxpubkeyhex, redobj ) {
  let redstr = JSON.stringify( redobj )
  let msg = ecies.encrypt( rxpubkeyhex, Buffer.from(redstr) )
  let msghash = crypto.createHash('sha256').update(msg).digest()

  let privkey = ec.keyFromPrivate( txprivkeyhex, 'hex' )
  let sig = Buffer.from( privkey.sign( msghash ).toDER() )
  let txpubkeyhex = privkey.getPublic( true, 'hex' )

  let result = JSON.parse( JSON.stringify(exports.BLACKMSG) )
  result.msghex = msg.toString('hex')
  result.sighex = sig.toString('hex')
  result.spkhex = txpubkeyhex

  return result
}

// confirm object specified seems to be an encrypted message per this protocol

exports.isBlackMsg = function( obj ) {
  return    obj != null
         && obj.msghex != null
         && obj.sighex != null
         && obj.spkhex != null
}

// confirm red object provided is some kind of valid JSON-RPC 2.0 object

exports.isJSONRPC = function( obj ) {
  return (obj != null &&
          obj.jsonrpc != null &&
          obj.jsonrpc === "2.0" &&
          obj.id != null &&
          (obj.method != null || obj.error != null || obj.result != null) )
}

// enable clients to make a new identity and services to make a session key

exports.makeKey = function() {
  let privkeyhex = Buffer.from( crypto.randomBytes(32) ).toString('hex')
  let privkey = ec.keyFromPrivate( privkeyhex, 'hex' )
  let pubkeyhex = privkey.getPublic().encode( 'hex' )

  return {
    prv : privkeyhex,
    pub : pubkeyhex
  }
}

// perform a self-test to confirm dependencies are there and work (check for
// presence of smoke)

exports.smokeTest = function() {

  let clnttestkey = exports.makeKey()
  let svrsesskey = exports.makeKey()

  // client makes a network connection to a service

  // service creates a "hello" message containing a unique session pubkey
  let redhello = exports.makeRedHello( svrsesskey.pub )
  console.log( 'Red hello: ' + JSON.stringify(redhello,null,2) + '\n' )

  // client forms some kind of request object with an id field having some
  // unique number
  let redReqObj = JSON.parse( JSON.stringify(exports.REQUEST) )
  redReqObj.method = "doSomething"
  redReqObj.params = [ "testing", 123 ]
  redReqObj.id = process.pid
  console.log( 'request isJSONRPC: ' + exports.isJSONRPC(redReqObj) + '\n' )
  console.log( 'request: ' + JSON.stringify(redReqObj,null,2) + '\n' )

  // client encrypts red request to black message to send to service
  let black = exports.redToBlack( clnttestkey.prv, svrsesskey.pub, redReqObj )
  console.log( 'Black request: ' + JSON.stringify(black,null,2) + '\n' )
  console.log( 'isBlackMsg: ' + exports.isBlackMsg(black) + '\n' )

  // black message is serialized and goes over the wire to server

  // server deserializes message to black object

  // server decrypts client's request message
  let red = exports.blackToRed( svrsesskey.prv, black )
  console.log( 'Server received: ' + JSON.stringify(red,null,2) + '\n' )

  // server does the action and forms a response
  let redresponse = JSON.parse( JSON.stringify(exports.RESPONSE) )
  redresponse.result = { answer: 42 }
  redresponse.id = red.id

  let blackreply =
    exports.redToBlack( svrsesskey.prv, clnttestkey.pub, redresponse )

  console.log( 'Black response: ' + JSON.stringify(blackreply, null, 2) )

  // server sends black response back to client

  // client deserializes message to black object

  // client decrypts service's reply
  let redreply = exports.blackToRed( clnttestkey.prv, blackreply )
  console.log( 'Red reply: ' + JSON.stringify(redreply, null, 2) )
}

