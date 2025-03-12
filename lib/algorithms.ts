import { HmacHasherHelper } from 'crypto-js/hmac';
import HmacSHA256 from 'crypto-js/hmac-sha256';
import HmacSHA384 from 'crypto-js/hmac-sha384';
import HmacSHA512 from 'crypto-js/hmac-sha512';
import SHA256 from 'crypto-js/sha256';
import Hex from 'crypto-js/enc-hex';
import elliptic from 'elliptic';

// Interface for algorithm implementations
export interface JWTAlgorithm {
  sign(data: string, key: string): any;
}

// HMAC algorithm implementations
class HMACAlgorithm implements JWTAlgorithm {
  private hmacHasher: HmacHasherHelper;

  constructor(hmacHasher: HmacHasherHelper) {
    this.hmacHasher = hmacHasher;
  }

  sign(data: string, key: string): any {
    return this.hmacHasher(data, key);
  }
}

// ECDSA algorithm implementation for ES256
class ES256Algorithm implements JWTAlgorithm {
  private ec: elliptic.ec;

  constructor() {
    // P-256 curve (also known as secp256r1 or prime256v1)
    this.ec = new elliptic.ec('p256');
  }

  sign(data: string, key: string): any {
    try {
      // Hash the data with SHA-256
      const hash = SHA256(data).toString(Hex);
      
      // Parse the private key
      const keyPair = this.ec.keyFromPrivate(key, 'hex');
      
      // Sign the hash
      const signature = keyPair.sign(hash);
      
      // DER encode the signature
      const derSignature = signature.toDER();
      
      // Convert to hex
      const hexSignature = Buffer.from(derSignature).toString('hex');
      
      return {
        toString: (encoder: any) => {
          if (encoder === Hex) {
            return hexSignature;
          }
          return Buffer.from(hexSignature, 'hex').toString('base64');
        }
      };
    } catch (error) {
      console.error('ES256 signing error:', error);
      throw error;
    }
  }
}

// Create algorithm instances
const hmacSHA256 = new HMACAlgorithm(HmacSHA256);
const hmacSHA384 = new HMACAlgorithm(HmacSHA384);
const hmacSHA512 = new HMACAlgorithm(HmacSHA512);
const es256 = new ES256Algorithm();

// Map algorithm names to implementations
const mapping: Record<string, JWTAlgorithm> = {
  HS256: hmacSHA256,
  HS384: hmacSHA384,
  HS512: hmacSHA512,
  ES256: es256,
};

export const supportedAlgorithms = Object.keys(mapping);

export default mapping;
