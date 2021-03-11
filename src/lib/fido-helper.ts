import { Base64 } from 'base-coding';
import cbor from 'cbor';
import crypto from 'crypto';

import { Cose } from './cose-to-jwk';
import { AuthenticationData, CredentialLike, MakeCredentialResponse, WebAuthnData } from './definitions';
import { parseAuthData as _parseAuthData } from './parse-auth-data';

export namespace FidoHelper {
  export function parseAuthData(buffer: Buffer): AuthenticationData {
    return _parseAuthData(buffer);
  }

  export function coseToJwk(cose: any): any {
    return Cose.coseToJwk(cose);
  }

  export function randomNumber(length: number = 32): string {
    return crypto
      .randomBytes(Math.ceil(length / 2))
      .toString('hex')
      .slice(0, length);
  }

  export function decodeAttestation(credential: CredentialLike): WebAuthnData {
    const attestationObject = credential.response.attestationObject;
    const attestationObjectBuffer = Buffer.from(attestationObject, 'base64');
    const ctapMakeCredResponse: MakeCredentialResponse = cbor.decodeAllSync(attestationObjectBuffer)[0];
    return FidoHelper.decode(credential.response.clientDataJSON, ctapMakeCredResponse.authData);
  }

  export function decode(jsonToParse: string, authDataToParse: string | Buffer): WebAuthnData {
    const clientData = JSON.parse(Base64.decode(jsonToParse));
    if (typeof authDataToParse === 'string') {
      authDataToParse = Buffer.from(authDataToParse, 'base64');
    }
    const authData = FidoHelper.parseAuthData(authDataToParse);
    return { clientData, authData };
  }

  export function fromBufferToArrayBuffer(buffer: Buffer | undefined): ArrayBuffer {
    if (!buffer) {
      return new ArrayBuffer(0);
    }
    const ab = new ArrayBuffer(buffer.length);
    const view = new Uint8Array(ab);
    for (let index = 0; index < buffer.length; ++index) {
      view[index] = buffer[index];
    }
    return ab;
  }

  export function createChallenge(): string {
    return stringToBase64Buffer(FidoHelper.randomNumber());
  }

  export function trimBase64(input: string): string {
    const indexOfPadding = input.indexOf('=');
    return input.slice(0, indexOfPadding);
  }

  function stringToBase64Buffer(buffer: string): string {
    return Buffer.from(Uint8Array.from(buffer, c => c.charCodeAt(0))).toString('base64');
  }
}
