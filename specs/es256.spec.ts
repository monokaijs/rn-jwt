import JWT, { SupportedAlgorithms } from '../lib';
import elliptic from 'elliptic';

describe('ES256 algorithm', () => {
  // Generate a new EC key pair for testing
  const generateKeyPair = () => {
    const ec = new elliptic.ec('p256');
    const keyPair = ec.genKeyPair();
    const privateKey = keyPair.getPrivate('hex');
    const publicKey = keyPair.getPublic('hex');
    return { privateKey, publicKey };
  };

  const { privateKey, publicKey } = generateKeyPair();
  const payload = { foo: 'bar', sub: '1234567890', name: 'Test User' };

  it('should encode and decode a JWT using ES256', () => {
    const token = JWT.encode(payload, privateKey, { algorithm: SupportedAlgorithms.ES256 });
    
    // The token should have the correct structure with 3 parts
    expect(token.split('.')).toHaveLength(3);
    
    // The header should specify ES256 algorithm
    const [headerBase64] = token.split('.');
    const headerStr = Buffer.from(headerBase64, 'base64').toString();
    const header = JSON.parse(headerStr);
    expect(header.alg).toBe('ES256');
    
    // Should be able to decode the token
    const decoded = JWT.decode(token, publicKey);
    expect(decoded).toEqual(payload);
  });

  it('should throw an error when decoding with an incorrect key', () => {
    const token = JWT.encode(payload, privateKey, { algorithm: SupportedAlgorithms.ES256 });
    
    // Generate a different key pair
    const { publicKey: wrongPublicKey } = generateKeyPair();
    
    expect(() => {
      JWT.decode(token, wrongPublicKey);
    }).toThrow();
  });

  it('should handle claims verification', () => {
    const now = Math.floor(Date.now() / 1000);
    const payloadWithClaims = {
      ...payload,
      exp: now + 3600, // Expires in 1 hour
      iat: now,        // Issued at now
      nbf: now - 100   // Valid from 100 seconds ago
    };
    
    const token = JWT.encode(payloadWithClaims, privateKey, { algorithm: SupportedAlgorithms.ES256 });
    
    // Should decode successfully with valid claims
    const decoded = JWT.decode(token, publicKey);
    expect(decoded).toEqual(payloadWithClaims);
    
    // Should fail with an expired token
    const expiredPayload = {
      ...payload,
      exp: now - 3600  // Expired 1 hour ago
    };
    
    const expiredToken = JWT.encode(expiredPayload, privateKey, { algorithm: SupportedAlgorithms.ES256 });
    
    expect(() => {
      JWT.decode(expiredToken, publicKey);
    }).toThrow();
  });
}); 