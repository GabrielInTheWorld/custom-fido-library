import { AuthenticationData } from './definitions';
import { decodeOnlyFirst } from './vanilla-cbor';

/*
 * parsing Auth Data for FIDO
 * https://medium.com/webauthnworks/verifying-fido2-responses-4691288c8770
 *
 * Copyright (c) 2018-2021 Yuriy Ackermann <ackermann.yuriy@gmail.com> <yuriy@webauthn.works>
 * Licensed under the MIT license.
 */
export function parseAuthData(buffer: Buffer): AuthenticationData {
  if (buffer.byteLength < 37) {
    throw new Error('Authenticator Data must be at least 37 bytes long!');
  }

  const rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);

  /* Flags */
  const flagsBuffer = buffer.slice(0, 1);
  buffer = buffer.slice(1);
  const flagsInt = flagsBuffer[0];
  const up = !!(flagsInt & 0x01); // Test of User Presence
  const uv = !!(flagsInt & 0x04); // User Verification
  const at = !!(flagsInt & 0x40); // Attestation data
  const ed = !!(flagsInt & 0x80); // Extension data
  const flags = { up, uv, at, ed, flagsInt };

  const counterBuffer = buffer.slice(0, 4);
  buffer = buffer.slice(4);
  const counter = counterBuffer.readUInt32BE(0);

  /* Attested credential data */
  let aaguid;
  let aaguidBuffer;
  let credIdBuffer;
  let cosePublicKeyBuffer;
  const attestationMinLen = 16 + 2 + 16 + 77; // aaguid + credIdLen + credId + pk

  if (at) {
    // Attested Data
    if (buffer.byteLength < attestationMinLen) {
      throw new Error(
        `It seems as the Attestation Data flag is set, but the remaining data is smaller than ${attestationMinLen} bytes. You might have set AT flag for the assertion response.`
      );
    }

    aaguid = buffer.slice(0, 16).toString('hex');
    buffer = buffer.slice(16);
    aaguidBuffer = `${aaguid.slice(0, 8)}-${aaguid.slice(8, 12)}-${aaguid.slice(12, 16)}-${aaguid.slice(
      16,
      20
    )}-${aaguid.slice(20)}`;

    const credIdLenBuffer = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    const credIdLen = credIdLenBuffer.readUInt16BE(0);
    credIdBuffer = buffer.slice(0, credIdLen);
    buffer = buffer.slice(credIdLen);

    const pubKeyLength = decodeOnlyFirst(buffer).byteLength;
    cosePublicKeyBuffer = buffer.slice(0, pubKeyLength);
    buffer = buffer.slice(pubKeyLength);
  }

  let coseExtensionsDataBuffer;
  if (ed) {
    // Extension Data
    const extensionsDataLength = decodeOnlyFirst(buffer).byteLength;

    coseExtensionsDataBuffer = buffer.slice(0, extensionsDataLength);
    buffer = buffer.slice(extensionsDataLength);
  }

  if (buffer.byteLength) {
    console.warn(`Failed to decode authData! Leftover ${buffer.byteLength} bytes been detected!`);
    console.warn(`Bytes:`, buffer);
  }

  return {
    rpIdHash,
    counter,
    flags,
    counterBuffer,
    aaguid,
    credIdBuffer,
    cosePublicKeyBuffer,
    coseExtensionsDataBuffer
  };
}
