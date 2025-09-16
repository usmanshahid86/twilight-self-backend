import { TxRaw, AuthInfo } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';
import { PubKey as SecpPubKey } from 'cosmjs-types/cosmos/crypto/secp256k1/keys.js';
import { rawSecp256k1PubkeyToRawAddress } from '@cosmjs/amino';
import { bech32 } from 'bech32';

export { b64ToBytes, extractFirstSecpPubkey, pubkeyToTwilightAddress };

// Convert base64 to bytes
function b64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}

// Extract the first secp256k1 public key from the transaction
function extractFirstSecpPubkey(txBytes) {
  const txRaw = TxRaw.decode(txBytes);
  if (!txRaw?.authInfoBytes?.length) throw new Error('no auth_info in tx');
  const auth = AuthInfo.decode(txRaw.authInfoBytes);

  const any = auth?.signerInfos?.[0]?.publicKey;
  if (!any) throw new Error('no signer public key found');
  if (any.typeUrl !== '/cosmos.crypto.secp256k1.PubKey') {
    throw new Error(`unsupported pubkey type: ${any.typeUrl}`);
  }
  const secp = SecpPubKey.decode(any.value);
  if (!secp?.key?.length) throw new Error('empty secp256k1 key');
  if (secp.key.length !== 33)
    throw new Error(`pubkey must be 33 bytes, got ${secp.key.length}`);

  return secp.key; // Uint8Array
}

// Convert the secp256k1 public key to a twilight address

function pubkeyToTwilightAddress(pubkey33) {
  const addrBytes = rawSecp256k1PubkeyToRawAddress(pubkey33);

  return bech32.encode('twilight', bech32.toWords(addrBytes));
}



