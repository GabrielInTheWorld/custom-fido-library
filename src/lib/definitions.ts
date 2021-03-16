export interface AuthenticationData {
  rpIdHash: Buffer;
  counter: number;
  flags: {
    up: boolean;
    uv: boolean;
    at: boolean;
    ed: boolean;
    flagsInt: number;
  };
  counterBuffer: Buffer;
  aaguid?: string;
  credIdBuffer?: Buffer;
  cosePublicKeyBuffer?: Buffer;
  coseExtensionsDataBuffer?: Buffer;
}

export interface WebAuthnData {
  clientData: ClientData;
  authData: AuthenticationData;
}

export interface RegisterOptions {
  userId?: string;
  rpName?: string;
  username: string;
  authenticatorAttachment: AuthenticatorAttachment;
  publicKeyAlgs?: PublicKeyAlg[];
}

export interface CredentialLike extends PartialCredentialLike {
  response: {
    /**
     * Attestation object from fido2 encoded as base64.
     */
    attestationObject: string;
    /**
     * Client data encoded as json-string.
     */
    clientDataJSON: string;
  };
}

export interface CredentialLikeLogin extends PartialCredentialLike {
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
  };
}

export interface PublicKeyObject {
  publicKeyPem: string;
  credentialId: string;
  publicKeyBytes: string;
  counter: number;
}

export interface MakeCredentialResponse {
  fmt: string;
  attStmt: {
    sig: Buffer;
    x5c: [Buffer];
  };
  authData: Buffer;
}

export interface PublicKeyCredentialCreationOptions {
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity;
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeycredentialDescriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: string;
  extensions?: object;
}

export interface PublicKeyCredentials {
  credentialId?: Buffer;
  publicKeyBytes?: Buffer;
  publicKeyPem: string;
  counter: number;
}

export interface AssertionExpectations extends Expectations {
  publicKeyPem: string;
  counter: number;
}

export interface AttestationExpectations extends Expectations {}

export interface ClientData {
  type: WebAuthnType;
  challenge: string;
  origin: string;
  crossOrigin: boolean;
}

export type PublicKeyAlg = -7 | -35 | -36 | -257 | -258 | -259 | -37 | -38 | -39 | -8;

export type WebAuthnType = 'webauthn.create' | 'webauthn.get';

export type AuthenticatorAttachment = 'cross-platform' | 'platform';

interface Expectations {
  origin: string | string[];
  challenge: string;
}

interface PublicKeyCredentialRpEntity {
  id?: string;
  name: string;
}

interface PublicKeyCredentialUserEntity {
  id: string;
  name: string;
  displayName: string;
}

interface PublicKeyCredentialParameters {
  type: string;
  alg: number;
}

interface PublicKeycredentialDescriptor {
  type: string;
  id: BufferSource | string;
  transports: string[];
}

interface AuthenticatorSelectionCriteria {
  authenticatorAttachment: string;
  residentKey: string;
  requireResidentKey?: boolean;
  userVerification?: string;
}

interface PartialCredentialLike {
  id: string;
  rawId: string;
  type: string;
}
