import assert from "node:assert/strict";
import {
  sign,
  signRandom,
  signPermissionless,
  verify,
  PERMISSIONLESS_PUBLIC_KEY,
  PERMISSIONLESS_PRIVATE_KEY,
} from "./index.js";

// Placeholder for known byte data
//
// `0x` prefix is not necessary but tests that normalization works correctly
const BYTES = "0x" + PERMISSIONLESS_PUBLIC_KEY;
const NFT_ID =
  "0xef20b433672911dbcc20c2a28b8175774209b250948a4f10dc92e952225e8025";

function testSign() {
  const signature = sign(
    PERMISSIONLESS_PRIVATE_KEY,
    NFT_ID,
    BYTES, // source
    BYTES, // destination
    0n, // epoch
    BYTES // nonce
  );

  assert.equal(
    signature,
    "f620b1af0c6f4593e19a62867264775691d28d8ea446d68a426c8e6c4521cb6e9e85534fb3f6d21b1eb5be0be6a8d7c3d4dba741cbf3c1f675726668b8f19108"
  );
}

function testRandom() {
  const { nonce, signature } = signRandom(
    PERMISSIONLESS_PRIVATE_KEY,
    NFT_ID,
    BYTES, // source
    BYTES, // destination
    0n
  );

  assert(
    verify(signature, PERMISSIONLESS_PUBLIC_KEY, NFT_ID, BYTES, BYTES, 0, nonce)
  );
}

function testPermissionless() {
  const signature = signPermissionless(
    NFT_ID,
    BYTES, // source
    BYTES, // destination
    0n
  );

  assert(
    verify(signature, PERMISSIONLESS_PUBLIC_KEY, NFT_ID, BYTES, BYTES, 0, "")
  );
}

testSign();
testRandom();
testPermissionless();

console.log("Tests passed!");
