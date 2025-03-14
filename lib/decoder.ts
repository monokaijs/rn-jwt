import Base64 from 'crypto-js/enc-base64';
import Utf8 from 'crypto-js/enc-utf8';
import SHA256 from 'crypto-js/sha256';
import Hex from 'crypto-js/enc-hex';
import elliptic from 'elliptic';

import Verifier from './verifier';
import * as Errors from './errors';
import algorithms, { supportedAlgorithms, JWTAlgorithm } from './algorithms';
import { urlEncodeBase64, urlSafeBase64ToBase64 } from './helpers';

import {
  EncodingKey,
  JWTBody,
  JWTHeader,
  DecodingOptions,
  JWTToken,
} from '../types/jwt';

let _key: EncodingKey;

const parse = (encodedString: string) => {
  const safeEncodeString = urlSafeBase64ToBase64(encodedString);
  return JSON.parse(Base64.parse(safeEncodeString).toString(Utf8));
};

const sign = (body: string, algorithm: JWTAlgorithm) =>
  urlEncodeBase64(algorithm.sign(body, _key || '').toString(Base64));

// ES256 verification
const verifyES256 = (data: string, signature: string, key: string): boolean => {
  try {
    // Create EC instance with P-256 curve
    const ec = new elliptic.ec('p256');
    
    // Parse the public key
    const keyPair = ec.keyFromPublic(key, 'hex');
    
    // Hash the data
    const hash = SHA256(data).toString(Hex);
    
    // Convert base64 signature to DER format
    const derSignature = Buffer.from(urlSafeBase64ToBase64(signature), 'base64');
    
    // Verify the signature
    return keyPair.verify(hash, derSignature);
  } catch (error) {
    console.error('ES256 verification error:', error);
    return false;
  }
};

class Decoder<T> {
  _header: JWTHeader;
  _body: JWTBody<T>;
  options: DecodingOptions;
  algorithm: 'none' | JWTAlgorithm;
  signature: string;

  constructor(key: EncodingKey) {
    _key = key;
  }

  set header(header: string) {
    try {
      this._header = parse(header);
    } catch (error) {
      throw new Errors.InvalidHeader();
    }
  }

  set body(body: string) {
    try {
      this._body = parse(body);
    } catch (error) {
      throw new Errors.InvalidBody();
    }
  }

  getAlgorithm() {
    const algorithm = this._header && this._header.alg;

    if (!algorithm) {
      throw new Errors.AlgorithmMissing();
    }

    if (algorithm === 'none') {
      return 'none';
    }

    if (!~supportedAlgorithms.indexOf(algorithm)) {
      throw new Errors.AlgorithmNotSupported();
    }

    return algorithms[algorithm];
  }

  verifySignature(encodedHeader: string, encodedBody: string) {
    if (this.algorithm === 'none') {
      return true;
    }

    const signatureBody = `${encodedHeader}.${encodedBody}`;

    if (this._header.alg === 'ES256') {
      // Special handling for ES256
      if (!_key || !verifyES256(signatureBody, this.signature, _key)) {
        throw new Errors.SignatureInvalid();
      }
    } else {
      // Standard verification for other algorithms
      if (this.signature !== sign(signatureBody, this.algorithm)) {
        throw new Errors.SignatureInvalid();
      }
    }

    return true;
  }

  verifyClaims() {
    Verifier.verifyAll(this._body, this.options);
  }

  decodeAndVerify(token: JWTToken, options: DecodingOptions = {}): JWTBody<T> {
    const [encodedHeader, encodedBody, signature] = token.toString().split('.');

    if (!encodedHeader || !encodedBody) {
      throw new Errors.InvalidStructure();
    }

    this.options = options;
    this.header = encodedHeader;
    this.body = encodedBody;
    this.signature = signature;
    this.algorithm = this.getAlgorithm();

    if (_key !== null) {
      this.verifySignature(encodedHeader, encodedBody);
    }
    this.verifyClaims();

    return this._body;
  }
}

export default Decoder;
