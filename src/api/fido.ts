import crypto from 'crypto';
import jwkToPem from 'jwk-to-pem';

import {
  AuthenticationData,
  AuthenticatorAttachment,
  AttestationExpectations,
  ClientData,
  CredentialLike,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentials,
  PublicKeyObject,
  RegisterOptions,
  CredentialLikeLogin,
  AssertionExpectations
} from '../lib/definitions';
import { FidoHelper } from '../lib/fido-helper';
import { FidoValidator } from '../lib/fido-validator';

export {
  PublicKeyObject,
  AttestationExpectations,
  AssertionExpectations,
  CredentialLikeLogin,
  AuthenticatorAttachment
};

export class FidoService {
  public static getRegisterOptions(args: RegisterOptions): PublicKeyCredentialCreationOptions {
    return {
      challenge: FidoHelper.createChallenge(),
      rp: {
        name: args.rpName || 'http://localhost:8000'
      },
      user: {
        id:
          args.userId ||
          Buffer.from(Uint8Array.from(FidoHelper.randomNumber(8), c => c.charCodeAt(0))).toString('base64'),
        name: args.username,
        displayName: args.username
      },
      extensions: {
        txAuthSimple: ''
      },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      authenticatorSelection: {
        residentKey: 'discouraged',
        requireResidentKey: false,
        authenticatorAttachment: args.authenticatorAttachment,
        userVerification: 'discouraged'
      },
      timeout: 60000,
      attestation: 'direct'
    };
  }

  public static getLoginOptions(credentialId: string): any {
    const publicKeyCredentialRequestOptions = {
      challenge: FidoHelper.createChallenge(),
      allowCredentials: [
        {
          id: Buffer.from(
            Uint8Array.from(Buffer.from(credentialId, 'base64').toString('hex'), (c: string) => c.charCodeAt(0))
          ).toString('base64'),
          type: 'public-key',
          transports: ['usb', 'ble', 'nfc']
        }
      ],
      userVerification: 'discouraged',
      timeout: 60000
    };
    return publicKeyCredentialRequestOptions;
  }

  public static decodeAttestationObject(credential: CredentialLike): PublicKeyCredentials {
    const { authData }: { authData: AuthenticationData } = FidoHelper.decodeAttestation(credential);

    const publicKeyCose = FidoHelper.fromBufferToArrayBuffer(authData.cosePublicKeyBuffer);
    const publicKeyJwk = FidoHelper.coseToJwk(publicKeyCose);
    const publicKeyPem = jwkToPem(publicKeyJwk);

    return {
      publicKeyBytes: authData.cosePublicKeyBuffer,
      publicKeyPem,
      credentialId: authData.credIdBuffer,
      counter: authData.counter
    };
  }

  public static verifyAttestationObject(
    credential: CredentialLike,
    expectations: AttestationExpectations
  ): PublicKeyCredentials {
    const {
      clientData,
      authData
    }: { clientData: ClientData; authData: AuthenticationData } = FidoHelper.decodeAttestation(credential);
    FidoValidator.validate(clientData, expectations, 'webauthn.create');
    const publicKeyCose = FidoHelper.fromBufferToArrayBuffer(authData.cosePublicKeyBuffer);
    const publicKeyJwk = FidoHelper.coseToJwk(publicKeyCose);
    const publicKeyPem = jwkToPem(publicKeyJwk);

    return {
      publicKeyBytes: authData.cosePublicKeyBuffer,
      publicKeyPem,
      credentialId: authData.credIdBuffer,
      counter: authData.counter
    };
  }

  public static verifySignature(credential: CredentialLikeLogin, expectations: AssertionExpectations): void {
    const { clientData, authData }: { clientData: ClientData; authData: AuthenticationData } = FidoHelper.decode(
      credential.response.clientDataJSON,
      credential.response.authenticatorData
    );
    FidoValidator.validate(clientData, expectations, 'webauthn.get');
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.from(credential.response.clientDataJSON, 'base64'));
    const digest = hash.digest();

    const verify = crypto.createVerify('sha256');
    verify.write(Buffer.from(credential.response.authenticatorData, 'base64'));
    verify.write(digest);
    verify.end();

    const signature = Buffer.from(credential.response.signature, 'base64');
    const isValid = verify.verify(expectations.publicKeyPem, signature);
    if (!isValid) {
      throw new Error('Signature is invalid!');
    }
  }
}
