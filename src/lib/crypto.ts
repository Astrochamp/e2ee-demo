import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import type { HexString } from './types/index';

/**
 * Generates random long-term keys for cryptographic operations.
 * Handles encryption, decryption, signing, and verification.
 * Uses 128-bit AES-GCM for encryption and decryption, and Ed25519 for signing and verification.
 */
export class CryptoManager {
  private readonly aesKey: Uint8Array;
  private readonly ed25519KeyPair: { privateKey: Uint8Array, publicKey: Uint8Array; };

  /**
   * Constructs a new instance of the CryptoManager class.
   * Generates random AES and Ed25519 keys.
   */
  constructor() {
    try {
      this.aesKey = CryptoManager.generateAESKey();
      this.ed25519KeyPair = CryptoManager.generateEd25519KeyPair();
    } catch (e) {
      throw new Error("Failed to generate keys\n" + e);
    }
  }

  /**
   * Retrieves the private key of the long-term Ed25519 key pair.
   */
  public getECPrivateKey(): HexString {
    return CryptoUtils.bufferToHex(this.ed25519KeyPair.privateKey).padStart(64, "0") as HexString;
  }

  /**
   * Retrieves the public key of the long-term Ed25519 key pair.
   */
  public getECPublicKey(): HexString {
    return CryptoUtils.bufferToHex(this.ed25519KeyPair.publicKey).padStart(64, "0") as HexString;
  }

  /**
   * Generates a random 128-bit AES-GCM key.
   * 
   * @returns A Uint8Array representing the generated key.
   */
  private static generateAESKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(16)); // 128 bits = 16 bytes
  }

  /**
   * Generates a random Ed25519 key pair.
   * 
   * @returns An object containing the generated private and public keys.
   */
  private static generateEd25519KeyPair(): { privateKey: Uint8Array, publicKey: Uint8Array; } {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);

    return {
      privateKey: privateKey,
      publicKey: publicKey
    };
  }

  /**
   * Encrypts the given plaintext using AES-GCM encryption.
   * @param plaintext The plaintext to be encrypted.
   * @returns A promise, resolving to an object containing the IV and ciphertext, both in hexadecimal string format.
   */
  public async encryptWithLongTermAES(plaintext: string): Promise<{ iv: HexString, ciphertext: HexString; }> {
    return CryptoUtils.encrypt(plaintext, CryptoUtils.bufferToHex(this.aesKey));
  }

  /**
   * Decrypts the given ciphertext using AES-GCM.
   * @param data An object containing the IV and ciphertext, both in hex string format.
   * @returns A promise that resolves to the decrypted plaintext.
   */
  public async decryptWithLongTermAES(data: { iv: HexString, ciphertext: HexString; }): Promise<string> {
    return CryptoUtils.decrypt(data, CryptoUtils.bufferToHex(this.aesKey));
  }

  /**
   * Signs the given text using Ed25519.
   * @param text The text to be signed. If the text is not in hex, it will be converted from UTF-8 to hex.
   * @returns A promise that resolves to the signature, in hexadecimal string format.
   */
  public async signWithLongTermEdDSA(text: string | HexString): Promise<HexString> {
    let textAsHex = text as HexString;

    if (!/^[a-fA-F0-9]+$/gi.test(text)) {
      textAsHex = CryptoUtils.stringToHex(text);
    }

    return CryptoUtils.sign(textAsHex, CryptoUtils.bufferToHex(this.ed25519KeyPair.privateKey));
  }

  /**
   * Verifies the given signature using Ed25519.
   * @param text The text that was signed. If not in hex, it will be converted from UTF-8 to hex.
   * @param signature The signature to be verified, in hexadecimal string format.
   * @param signerPublicKey The signer's public key, in hexadecimal string format.
   * @returns A promise that resolves to a boolean indicating whether the signature is valid.
   */
  public async verifyWithLongTermEdDSA(text: string | HexString, signature: HexString, signerPublicKey: HexString): Promise<boolean> {
    let textAsHex = text as HexString;

    if (!/^[a-fA-F0-9]+$/gi.test(text)) {
      textAsHex = CryptoUtils.stringToHex(text);
    }

    return CryptoUtils.verify(textAsHex, signature, signerPublicKey);
  }
}

/**
 * Cryptography-related utility functions.
 */
export class CryptoUtils {
  /**
   * Converts an ArrayBuffer or Uint8Array to a hexadecimal string representation.
   * 
   * @param buffer The ArrayBuffer or Uint8Array to convert.
   * @returns The hexadecimal string representation of the buffer.
   */
  public static bufferToHex(buffer: ArrayBuffer | Uint8Array): HexString {
    try {
      return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('') as HexString;
    } catch (e) {
      throw new Error("Invalid ArrayBuffer: cannot convert to hexadecimal string");
    }
  }

  /**
   * Converts a hexadecimal string to an ArrayBuffer.
   * 
   * @param hex The hexadecimal string to convert.
   * @returns The ArrayBuffer representation of the string.
   */
  public static hexToBuffer(hex: HexString): ArrayBuffer {
    if (hex.length == 0) {
      return new ArrayBuffer(0);
    }

    try {
      const matches = hex.match(/../g);
      if (!matches) throw new Error("Invalid hex string format");
      return new Uint8Array(matches.map(h => parseInt(h, 16))).buffer;
    } catch (e) {
      throw new Error("Invalid hexadecimal string: cannot convert to ArrayBuffer");
    }
  }

  /**
   * Converts a UTF-8 string to its hexadecimal representation.
   * @param str The string to convert.
   * @returns The hexadecimal representation of the string.
   */
  public static stringToHex(str: string): HexString {
    return CryptoUtils.bufferToHex(new TextEncoder().encode(str));
  }

  /**
   * Converts a hexadecimal string to its UTF-8 representation.
   * @param hex The hexadecimal string to convert.
   * @returns The string representation of the hexadecimal string.
   */
  public static hexToString(hex: HexString): string {
    return new TextDecoder().decode(CryptoUtils.hexToBuffer(hex));
  }

  /**
   * Computes X25519 shared secret using private and public keys.
   * @param privateKey The private key (hexadecimal string format).
   * @param publicKey The public key (hexadecimal string format).
   */
  public static computeX25519SharedSecret(privateKey: HexString, publicKey: HexString): HexString {
    const sharedSecret = x25519.getSharedSecret(
      new Uint8Array(CryptoUtils.hexToBuffer(privateKey)),
      new Uint8Array(CryptoUtils.hexToBuffer(publicKey))
    );

    return CryptoUtils.bufferToHex(sharedSecret);
  }

  /**
   * Generates a random integer within the specified range.
   * 
   * @param min The minimum value of the range (inclusive).
   * @param max The maximum value of the range (inclusive).
   * @returns A random integer within the specified range.
   * @see https://stackoverflow.com/a/42321673/14744522
   */
  public static randomIntInRange(min: number, max: number): number {
    if (min > max) {
      throw new Error("Min must be less than or equal to max");
    }
    if (max - min > 0xffffffff) {
      throw new Error("Range cannot be greater than 32 bits");
    }
    if (min === max) {
      return min;
    }

    const randomBuffer = new Uint32Array(1);
    crypto.getRandomValues(randomBuffer);
    let randomNumber = randomBuffer[0] / (0xffffffff);
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(randomNumber * (max - min + 1)) + min;
  }

  /**
   * Encrypts the given plaintext using AES-GCM encryption.
   * @param plaintext The plaintext to be encrypted.
   * @param key The key used to encrypt the plaintext (hexadecimal string format)
   * @returns A promise that resolves to an object containing the initialisation vector (IV) and the ciphertext, both in hexadecimal string format.
   * 
   * @see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf#page=16 for 96-bit IV reference
   */
  public static async encrypt(plaintext: string, key: HexString): Promise<{ iv: HexString, ciphertext: HexString; }> {
    const aesKey = CryptoUtils.hexToBuffer(key);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesCryptoKey = await crypto.subtle.importKey(
      "raw",
      aesKey,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      aesCryptoKey,
      new TextEncoder().encode(plaintext)
    );

    const ivHex = CryptoUtils.bufferToHex(iv);
    const ciphertextHex = CryptoUtils.bufferToHex(ciphertext);

    return {
      iv: ivHex,
      ciphertext: ciphertextHex
    };
  }

  /**
   * Decrypts the given ciphertext using AES-GCM.
   * @param data An object containing the IV and the ciphertext, both in hexadecimal string format.
   * @param key The key used to decrypt the ciphertext (hexadecimal string format)
   * @returns A promise that resolves to the decrypted plaintext.
   */
  public static async decrypt(data: { iv: HexString, ciphertext: HexString; }, key: HexString): Promise<string> {
    const aesKey = CryptoUtils.hexToBuffer(key);
    const iv = data.iv;
    const ciphertext = data.ciphertext;
    const aesCryptoKey = await crypto.subtle.importKey(
      "raw",
      aesKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: CryptoUtils.hexToBuffer(iv)
      },
      aesCryptoKey,
      CryptoUtils.hexToBuffer(ciphertext)
    );

    return new TextDecoder().decode(plaintext);
  }

  /**
   * Signs the given text using EdDSA and Ed25519.
   * @param text The text to be signed, in hexadecimal string format.
   * @param privateKey The private key (hexadecimal string format).
   * @returns A promise that resolves to the signature, in hexadecimal string format.
   */
  public static async sign(text: HexString, privateKey: HexString): Promise<HexString> {
    const textBytes = new Uint8Array(CryptoUtils.hexToBuffer(text));
    const privateKeyBytes = new Uint8Array(CryptoUtils.hexToBuffer(privateKey));
    const signature = ed25519.sign(textBytes, privateKeyBytes);
    return CryptoUtils.bufferToHex(signature);
  }

  /**
   * Verifies the given signature using EdDSA and Ed25519.
   * @param text The text that was signed, in hexadecimal string format.
   * @param signature The signature to be verified, in hexadecimal string format.
   * @param signerPublicKey The signer's public key, in hexadecimal string format.
   * @returns A promise that resolves to a boolean indicating whether the signature is valid.
   */
  public static async verify(text: HexString, signature: HexString, signerPublicKey: HexString): Promise<boolean> {
    const textBytes = new Uint8Array(CryptoUtils.hexToBuffer(text));
    const signatureBytes = new Uint8Array(CryptoUtils.hexToBuffer(signature));
    const publicKeyBytes = new Uint8Array(CryptoUtils.hexToBuffer(signerPublicKey));
    return ed25519.verify(signatureBytes, textBytes, publicKeyBytes);
  }
}
