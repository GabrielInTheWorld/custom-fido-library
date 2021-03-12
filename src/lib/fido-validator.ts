import { WebAuthnType } from './definitions';
import { FidoHelper } from './fido-helper';

export namespace FidoValidator {
  export function validate(clientData: any, expectations: any, type: WebAuthnType): void {
    validateType(clientData, type);
    validateChallenge(clientData, expectations);
    validateOrigin(clientData, expectations);
  }

  function validateType(clientData: any, type: WebAuthnType): void {
    if (clientData.type !== type) {
      throw new Error(`Wrong type of webauthn! Expected ${type} - Received ${clientData.type}`);
    }
  }

  function validateChallenge(clientData: any, expectations: any): void {
    if (clientData.challenge !== FidoHelper.trimBase64(expectations.challenge)) {
      throw new Error(
        `Challenges are different! Expected ${expectations.challenge} - Received ${clientData.challenge}`
      );
    }
  }

  function validateOrigin(clientData: any, expectations: any): void {
    if (clientData.origin !== expectations.origin) {
      throw new Error(`Origins are different! Expected ${expectations.origin} - Received ${clientData.origin}`);
    }
  }
}
