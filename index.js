import { sha512 } from "@noble/hashes/sha512";
import * as ed from "@noble/ed25519";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

import { BCS, getSuiMoveConfig } from "@mysten/bcs";
const bcs = new BCS(getSuiMoveConfig());

const { randomBytes } = await import("node:crypto");

/**
 * @typedef {Object} Parameters
 * @property {Buffer} nonce - Nonce that was used to generate the signature
 * @property {Buffer} signature - Signature after signing message
 */

/**
 * Sign source and destination transaction
 *
 * Nonce must not be repeated for a given source and destination as this would
 * allow forging peer-to-peer transactions for the transaction.
 * @param {String} privateKey - Hex-encoded private key of the transfer authority
 * @param {String} nft_id - Hex-encoded NFT ID subject to transfer
 * @param {String} source - Hex-encoded source address of peer-to-peer transfer
 * @param {String} destination - Hex-encoded destination address of peer-to-peer transfer
 * @param {BigInt} epoch - Current Sui epoch
 * @param {String} nonce - Hex-encoded, non-repeating nonce
 * @returns {String} - Signature
 */
function sign(privateKey, nft_id, source, destination, epoch, nonce) {
  const msg = Buffer.concat([
    normalize(nft_id),
    normalize(source),
    normalize(destination),
    bcs.ser(BCS.U64, epoch).toBytes(),
    normalize(nonce),
  ]);
  let signature = ed.sign(msg, normalize(privateKey));
  return Buffer.from(signature).toString("hex");
}

/**
 * Sign source and destination transaction with random nonce.
 *
 * Uses a 32-byte nonce which ensures that peer-to-peer transactions cannot be
 * forged by re-using signatures.
 * @param {String} privateKey - Hex-encoded private key of the transfer authority
 * @param {String} nft_id - Hex-encoded NFT ID subject to transfer
 * @param {String} source - Hex-encoded source address of peer-to-peer transfer
 * @param {String} destination - Hex-encoded destination address of peer-to-peer transfer
 * @param {BigInt} epoch - Current Sui epoch
 * @returns {Parameters} - Signature and nonce that was used
 */
function signRandom(privateKey, nft_id, source, destination, epoch) {
  let nonce = randomBytes(32).toString("hex");
  let signature = sign(privateKey, nft_id, source, destination, epoch, nonce);
  return { nonce, signature };
}

const PERMISSIONLESS_PUBLIC_KEY =
  "8a1a8348dde5d979c85553c03e204c73efc3b91a2c9ce96b1004c9ec26eaacc8";
const PERMISSIONLESS_PRIVATE_KEY =
  "ac5dbb29bea100f5f6382ebcb116afc66fc7b05ff64d2d1e3fc60849504a29f0";

/**
 * Signs source and destination transaction with OriginByte's public keypair
 *
 * OriginByte initially provides a public keypair such that any user can
 * self-sign peer-to-peer transactions during the period where third-party
 * signing authorities are not yet well-established.
 *
 * The user may expect that this keypair will be listed in official OriginByte
 * `AuthList` objects but will be removed with due time.
 *
 * @param {String} nft_id - Hex-encoded NFT ID subject to transfer
 * @param {String} source - Hex-encoded source address of peer-to-peer transfer
 * @param {String} destination - Hex-encoded destination address of peer-to-peer transfer
 * @param {BigInt} epoch - Current Sui epoch
 */
function signPermissionless(nft_id, source, destination, epoch) {
  return sign(
    PERMISSIONLESS_PRIVATE_KEY,
    nft_id,
    source,
    destination,
    epoch,
    ""
  );
}

/**
 * Verify that transaction will be able to be made on-chain
 * @param {Buffer} signature - Signature to verify
 * @param {String} publicKey - Hex-encoded public key of the transfer authority
 * @param {String} nft_id - Hex-encoded NFT ID subject to transfer
 * @param {String} source - Hex-encoded source address of peer-to-peer transfer
 * @param {String} destination - Hex-encoded destination address of peer-to-peer transfer
 * @param {BigInt} epoch - Current Sui epoch
 * @param {String} nonce - Nonce that was used to generate the signature
 * @returns {boolean} - Whether signature was verified
 */
function verify(
  signature,
  publicKey,
  nft_id,
  source,
  destination,
  epoch,
  nonce
) {
  const msg = Buffer.concat([
    normalize(nft_id),
    normalize(source),
    normalize(destination),
    bcs.ser(BCS.U64, epoch).toBytes(),
    normalize(nonce),
  ]);

  return ed.verify(signature, msg, publicKey);
}

/**
 * Convert string addresses to byte buffers
 * @param {string} address - String hex-encoded address to normalize
 * @returns {Buffer} Address represented as buffer
 */
function normalize(address) {
  let normalized = address;

  if (normalized.startsWith("0x")) {
    normalized = normalized.slice(2);
  }

  normalized = Buffer.from(normalized, "hex");

  return normalized;
}

export {
  sign,
  signRandom,
  signPermissionless,
  normalize,
  verify,
  PERMISSIONLESS_PUBLIC_KEY,
  PERMISSIONLESS_PRIVATE_KEY,
};
