# authlist-sign

Sample implementation for supporting OriginByte `AuthList` request signing.

With testnet around the corner, it is more important than ever to have a system in place to verify authorized entities who can grant permission for peer-to-peer transfers. This is where OriginByte's `AuthList` comes in, it allows establishing a set of authorities which are able authorize peer-to-peer transactions by signing transaction requests which can then be executed by the user.

This library exposes three main functions:

- `sign(privateKey, nft_id, source, destination, epoch, nonce): signature`
- `signRandom(privateKey, nft_id, source, destination, epoch): { signature, nonce }`
- `verify(signature, publicKey, nft_id, source, destination, epoch, nonce): boolean`

`sign` allows signing a source and destination peer-to-peer transaction.

The chosen nonce must not be repeated for a given source and destination as this would allow forging peer-to-peer transactions for the transaction.

`signRandom` opts to use a 32-byte nonce which ensures that peer-to-peer transactions cannot be forged by re-using signatures. It is however recommended that authorities determine the best nonce to use for their use case, options include a counter, or timestamp.

`verify` is a helper function to ensure test whether the message was correctly signed.

Correct working of the library can be verified using:

```
npm install
node tests.js
```

## Migration

We expect that at `mainnet` launch the support for seamless P2P transactions will not be supported by most wallets and marketplaces.
To solve this issue, OriginByte publicises a private ED25519 keypair and register it as a trusted authority within their official `AuthList`.

```
PUBLIC_KEY = 8a1a8348dde5d979c85553c03e204c73efc3b91a2c9ce96b1004c9ec26eaacc8
PRIVATE_KEY = ac5dbb29bea100f5f6382ebcb116afc66fc7b05ff64d2d1e3fc60849504a29f0
```

Since the keypair is public, wallets and marketplaces will enable users to authorize their own transactions purely on the client-side until a server-side authority flow is setup.
Once ecosystem adoption occurs such that P2P transactions are relatively accessible, OriginByte will remove this keypair from their `AuthList` making it no longer usable.

`signPermissionless(nft_id, source, destination, epoch): signature` is also provided as an example method for client-side signing.
Note that an empty nonce is used.
