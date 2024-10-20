# ecjsonrpc
Javascript library for encrypting and exchanging json-rpc messages.

## Protocol

This custom protocol works as follows:
1. A client makes a network connection to a service
2. The service immediately sends an unencrypted "hello" message to the client
   containing a session-specific pubkey, a session being the lifetime of the
   connection.
3. The client formulates a request object in JSON-RPC 2.0 format.
4. The client encrypts the request using the server's session pubkey and
   creates a digital signature of the result.
5. The encrypted message with digital signature and client's public key are
   sent to the service. Yes the client public key is sent unencrypted and yes
   this could be susceptible to monitoring so we assume a wss connection.
6. The service decrypts the client's request, validates the signature, does
   the method implied and makes a response containing the result (or error).
7. The server encrypts the response, signs it and returns this black response
   back to the client. Same if an error occurs - an encrypted error response
   is returned.
8. Client validates the message and signature and decrypts the response.

