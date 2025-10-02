<script lang="ts">
  import { CryptoManager, CryptoUtils } from "$lib/crypto";
  import type { HexString } from "$lib/types";
  import { ed25519, x25519 } from "@noble/curves/ed25519.js";

  // Demo state
  let currentStep = 0;
  let message = "Hello Bob! This is a secret message.";
  let isAnimating = false;

  const aliceCrypto = new CryptoManager();
  const bobCrypto = new CryptoManager();

  let aliceKeys = {
    longTermPrivate: aliceCrypto.getECPrivateKey(),
    longTermPublic: aliceCrypto.getECPublicKey(),
    ephemeralPrivate: null as HexString | null,
    ephemeralPublic: null as HexString | null,
    messageSecret: CryptoUtils.bufferToHex(
      crypto.getRandomValues(new Uint8Array(16)),
    ),
    randomValue: CryptoUtils.bufferToHex(
      crypto.getRandomValues(new Uint8Array(16)),
    ),
    KXsignature: "" as HexString,
  };

  let bobKeys = {
    longTermPrivate: bobCrypto.getECPrivateKey(),
    longTermPublic: bobCrypto.getECPublicKey(),
    ephemeralPrivate: null as HexString | null,
    ephemeralPublic: null as HexString | null,
    randomValue: CryptoUtils.bufferToHex(
      crypto.getRandomValues(new Uint8Array(16)),
    ),
    KXsignature: "" as HexString,
  };

  let sharedSecret = "" as HexString;
  let encryptedMessageSecret = "" as HexString;
  let messageEncryptionKey = "" as HexString;
  let messageSigningPrivateKey = "" as HexString;
  let messageSigningPublicKey = "" as HexString;
  let messageSignature = "" as HexString;
  let encryptedMessage = "" as HexString;
  let decryptedMessage = "";

  let iv1 = crypto.getRandomValues(new Uint8Array(12));
  let iv2 = crypto.getRandomValues(new Uint8Array(12));

  const steps = [
    "Initial Setup",
    "Alice generates secrets",
    "Alice signs & sends key info",
    "Bob verifies & responds",
    "Key exchange complete",
    "Alice encrypts message secret",
    "Alice signs & encrypts message",
    "Bob decrypts message",
  ];

  const transmitSteps = [2, 3, 6];

  function nextStep() {
    if (currentStep < steps.length - 1 && !isAnimating) {
      isAnimating = true;
      currentStep++;

      // Simulate crypto operations based on step
      setTimeout(async () => {
        switch (currentStep) {
          case 1:
            // generate ephemeral info using x25519 from @noble/curves
            const aliceEphemeralPrivate = x25519.utils.randomSecretKey();
            const aliceEphemeralPublic = x25519.getPublicKey(
              aliceEphemeralPrivate,
            );

            aliceKeys.ephemeralPrivate = CryptoUtils.bufferToHex(
              aliceEphemeralPrivate,
            );
            aliceKeys.ephemeralPublic =
              CryptoUtils.bufferToHex(aliceEphemeralPublic);

            const bobEphemeralPrivate = x25519.utils.randomSecretKey();
            const bobEphemeralPublic = x25519.getPublicKey(bobEphemeralPrivate);

            bobKeys.ephemeralPrivate =
              CryptoUtils.bufferToHex(bobEphemeralPrivate);
            bobKeys.ephemeralPublic =
              CryptoUtils.bufferToHex(bobEphemeralPublic);
            break;
          case 2:
            // Alice signs key info
            const aliceKXSignData =
              aliceKeys.randomValue +
              aliceCrypto.getECPublicKey() +
              aliceKeys.ephemeralPublic;
            aliceKeys.KXsignature =
              await aliceCrypto.signWithLongTermEdDSA(aliceKXSignData);
            // In a real scenario, Alice would send (aliceKeys.ephemeralPublic, aliceKeys.randomValue, aliceKXSignature) to Bob
            break;
          case 3:
            // Bob verifies Alice's signature and responds
            const aliceKXSignDataToVerify =
              aliceKeys.randomValue +
              aliceCrypto.getECPublicKey() +
              aliceKeys.ephemeralPublic;
            const isAliceSignatureValid =
              await bobCrypto.verifyWithLongTermEdDSA(
                aliceKXSignDataToVerify,
                aliceKeys.KXsignature,
                aliceCrypto.getECPublicKey(),
              );
            if (!isAliceSignatureValid) {
              throw new Error("Alice's signature verification failed!");
            }
            const bobKXSignData =
              bobKeys.randomValue +
              bobCrypto.getECPublicKey() +
              bobKeys.ephemeralPublic;
            bobKeys.KXsignature =
              await bobCrypto.signWithLongTermEdDSA(bobKXSignData);
            // In a real scenario, Bob would send (bobKeys.ephemeralPublic, bobKeys.randomValue, bobKXSignature) to Alice
            break;
          case 4:
            // Both compute shared secret
            const aliceSharedSecret = CryptoUtils.computeX25519SharedSecret(
              aliceKeys.ephemeralPrivate!,
              bobKeys.ephemeralPublic!,
            );

            const bobSharedSecret = CryptoUtils.computeX25519SharedSecret(
              bobKeys.ephemeralPrivate!,
              aliceKeys.ephemeralPublic!,
            );

            if (aliceSharedSecret !== bobSharedSecret) {
              throw new Error("Shared secrets do not match!");
            }

            sharedSecret = aliceSharedSecret;
            break;
          case 5:
            // Alice derives message keys
            // hkdf
            const sharedSecretBaseKey = await crypto.subtle.importKey(
              "raw",
              CryptoUtils.hexToBuffer(sharedSecret),
              "HKDF",
              false,
              ["deriveBits", "deriveKey"],
            );

            const infoShared = new TextEncoder().encode("shared");
            const infoCipher = new TextEncoder().encode("cipher");
            const infoSign = new TextEncoder().encode("signature");
            const salt = new Uint8Array(16); // all zero salt

            const sharedDerivedBits = await crypto.subtle.deriveBits(
              {
                name: "HKDF",
                hash: "SHA-256",
                salt,
                info: infoShared,
              },
              sharedSecretBaseKey,
              128,
            ); // sdAP

            // encrypt message secret with sdAP
            encryptedMessageSecret = await crypto.subtle
              .importKey("raw", sharedDerivedBits, { name: "AES-GCM" }, false, [
                "encrypt",
              ])
              .then((key) =>
                crypto.subtle.encrypt(
                  {
                    name: "AES-GCM",
                    iv: iv1,
                  },
                  key,
                  CryptoUtils.hexToBuffer(aliceKeys.messageSecret),
                ),
              )
              .then((enc) => CryptoUtils.bufferToHex(new Uint8Array(enc)));

            const messageSecretBaseKey = await crypto.subtle.importKey(
              "raw",
              CryptoUtils.hexToBuffer(aliceKeys.messageSecret),
              "HKDF",
              false,
              ["deriveBits", "deriveKey"],
            );

            messageEncryptionKey = CryptoUtils.bufferToHex(
              await crypto.subtle
                .deriveBits(
                  {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt,
                    info: infoCipher,
                  },
                  messageSecretBaseKey,
                  128,
                )
                .then((bits) => new Uint8Array(bits)),
            ) as HexString;

            messageSigningPrivateKey = CryptoUtils.bufferToHex(
              await crypto.subtle
                .deriveBits(
                  {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt,
                    info: infoSign,
                  },
                  messageSecretBaseKey,
                  256,
                )
                .then((bits) => new Uint8Array(bits)),
            ) as HexString;

            messageSigningPublicKey = CryptoUtils.bufferToHex(
              ed25519.getPublicKey(
                new Uint8Array(
                  CryptoUtils.hexToBuffer(messageSigningPrivateKey),
                ),
              ),
            ) as HexString;
            break;
          case 6: {
            // sign (recipient eph. pub || message) with message signing key
            const dataToSign = new Uint8Array([
              ...new Uint8Array(
                CryptoUtils.hexToBuffer(bobKeys.ephemeralPublic!),
              ),
              ...new TextEncoder().encode(message),
            ]);
            const msig = ed25519.sign(
              dataToSign,
              new Uint8Array(CryptoUtils.hexToBuffer(messageSigningPrivateKey)),
            );
            messageSignature = CryptoUtils.bufferToHex(msig) as HexString;

            // encrypt message with message encryption key
            encryptedMessage = await crypto.subtle
              .importKey(
                "raw",
                CryptoUtils.hexToBuffer(messageEncryptionKey),
                { name: "AES-GCM" },
                false,
                ["encrypt"],
              )
              .then((key) =>
                crypto.subtle.encrypt(
                  {
                    name: "AES-GCM",
                    iv: iv2,
                  },
                  key,
                  new TextEncoder().encode(message),
                ),
              )
              .then((enc) => CryptoUtils.bufferToHex(new Uint8Array(enc)));
            break;
          }
          case 7:
            // Bob decrypts message
            // derive sdAP again
            const bobSharedSecretBaseKey = await crypto.subtle.importKey(
              "raw",
              CryptoUtils.hexToBuffer(sharedSecret),
              "HKDF",
              false,
              ["deriveBits", "deriveKey"],
            );

            const infoSharedBob = new TextEncoder().encode("shared");
            const saltBob = new Uint8Array(16); // all zero salt

            const bobSharedDerivedBits = await crypto.subtle.deriveBits(
              {
                name: "HKDF",
                hash: "SHA-256",
                salt: saltBob,
                info: infoSharedBob,
              },
              bobSharedSecretBaseKey,
              128,
            ); // sdAP

            // decrypt message secret with sdAP
            const decryptedMessageSecret = await crypto.subtle
              .importKey(
                "raw",
                bobSharedDerivedBits,
                { name: "AES-GCM" },
                false,
                ["decrypt"],
              )
              .then((key) =>
                crypto.subtle.decrypt(
                  {
                    name: "AES-GCM",
                    iv: iv1,
                  },
                  key,
                  CryptoUtils.hexToBuffer(encryptedMessageSecret),
                ),
              )
              .then((dec) => CryptoUtils.bufferToHex(new Uint8Array(dec)));

            if (decryptedMessageSecret !== aliceKeys.messageSecret) {
              throw new Error("Decrypted message secret does not match!");
            }

            // derive message keys
            const bobMessageSecretBaseKey = await crypto.subtle.importKey(
              "raw",
              CryptoUtils.hexToBuffer(decryptedMessageSecret),
              "HKDF",
              false,
              ["deriveBits", "deriveKey"],
            );

            const infoCipherBob = new TextEncoder().encode("cipher");
            const infoSignBob = new TextEncoder().encode("signature");
            const saltBob2 = new Uint8Array(16);

            const bobMessageEncryptionKey = CryptoUtils.bufferToHex(
              await crypto.subtle
                .deriveBits(
                  {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: saltBob2,
                    info: infoCipherBob,
                  },
                  bobMessageSecretBaseKey,
                  128,
                )
                .then((bits) => new Uint8Array(bits)),
            ) as HexString;

            const bobMessageSigningPrivateKey = CryptoUtils.bufferToHex(
              await crypto.subtle
                .deriveBits(
                  {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: saltBob2,
                    info: infoSignBob,
                  },
                  bobMessageSecretBaseKey,
                  256,
                )
                .then((bits) => new Uint8Array(bits)),
            ) as HexString;

            const bobMessageSigningPublicKey = CryptoUtils.bufferToHex(
              ed25519.getPublicKey(
                new Uint8Array(
                  CryptoUtils.hexToBuffer(bobMessageSigningPrivateKey),
                ),
              ),
            ) as HexString;

            if (bobMessageEncryptionKey !== messageEncryptionKey) {
              throw new Error("Bob's derived message encryption key mismatch!");
            }

            if (bobMessageSigningPublicKey !== messageSigningPublicKey) {
              throw new Error("Bob's derived message signing key mismatch!");
            }

            // verify signature
            const dataToVerify = new Uint8Array([
              ...new Uint8Array(
                CryptoUtils.hexToBuffer(bobKeys.ephemeralPublic!),
              ),
              ...new TextEncoder().encode(message),
            ]);
            const isMessageSignatureValid = ed25519.verify(
              new Uint8Array(CryptoUtils.hexToBuffer(messageSignature)),
              dataToVerify,
              new Uint8Array(CryptoUtils.hexToBuffer(messageSigningPublicKey)),
            );

            if (!isMessageSignatureValid) {
              throw new Error("Message signature verification failed!");
            }

            // decrypt message
            decryptedMessage = await crypto.subtle
              .importKey(
                "raw",
                CryptoUtils.hexToBuffer(bobMessageEncryptionKey),
                { name: "AES-GCM" },
                false,
                ["decrypt"],
              )
              .then((key) =>
                crypto.subtle.decrypt(
                  {
                    name: "AES-GCM",
                    iv: iv2,
                  },
                  key,
                  CryptoUtils.hexToBuffer(encryptedMessage),
                ),
              )
              .then((dec) => new TextDecoder().decode(dec));

            if (decryptedMessage !== message) {
              throw new Error("Decrypted message does not match original!");
            }
            break;
        }
        isAnimating = false;
      }, 800);
    }
  }

  function resetDemo() {
    currentStep = 0;
    aliceKeys = {
      ...aliceKeys,
      ephemeralPrivate: null, // Reset ephemeral keys
      ephemeralPublic: null,
      messageSecret: CryptoUtils.bufferToHex(
        crypto.getRandomValues(new Uint8Array(16)),
      ),
      randomValue: CryptoUtils.bufferToHex(
        crypto.getRandomValues(new Uint8Array(16)),
      ),
    };
    bobKeys = {
      ...bobKeys,
      ephemeralPrivate: null,
      ephemeralPublic: null,
      randomValue: CryptoUtils.bufferToHex(
        crypto.getRandomValues(new Uint8Array(16)),
      ),
    };
    sharedSecret = "" as HexString;
    encryptedMessageSecret = "" as HexString;
    messageEncryptionKey = "" as HexString;
    messageSigningPrivateKey = "" as HexString;
    messageSigningPublicKey = "" as HexString;
    messageSignature = "" as HexString;
    encryptedMessage = "" as HexString;
    decryptedMessage = "";
  }
</script>

<div class="min-h-screen bg-gray-950">
  <main class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8 lg:py-8">
    <div class="text-center mb-12">
      <h2 class="text-4xl font-bold text-gray-100 mb-4">
        Encrypted Messaging Demo
      </h2>
      <p class="text-xl text-gray-400 max-w-3xl mx-auto mb-6">
        End-to-end encryption with AES-GCM, X25519, Ed25519, and HKDF.
      </p>

      <!-- Step Indicator -->
      <div class="hidden xl:flex justify-center mb-8">
        <div class="bg-gray-800 rounded-full p-1 flex space-x-1">
          {#each steps as step, index}
            <div
              class="p-2 text-sm {index === 0
                ? 'rounded-l-full'
                : ''} {index === currentStep
                ? 'rounded-r-full'
                : 'rounded-r-none'} {index <= currentStep
                ? 'bg-blue-500 text-white'
                : 'text-gray-400'}"
            >
              {index + 1}. {step}
            </div>
          {/each}
        </div>
      </div>

      <!-- Current Step Description -->
      <div
        class="flex flex-col gap-4 mb-4 items-center justify-center gap-x-4 w-full"
      >
        <div
          class="bg-gray-800/50 border border-gray-600 rounded-lg p-4 max-w-2xl"
        >
          <h3 class="text-lg font-semibold text-blue-400 mb-2">
            Step {currentStep + 1}: {steps[currentStep]}
          </h3>
          <p class="text-gray-300 text-sm">
            {#if currentStep === 0}
              Alice and Bob each have long-term Ed25519 keypairs and know each
              other's public keys.
            {:else if currentStep === 1}
              Alice generates a message secret, random value, and ephemeral
              keypair.
            {:else if currentStep === 2}
              Alice signs key information and sends it to Bob.
            {:else if currentStep === 3}
              Bob verifies the signature, generates random value and ephemeral
              keypair, computes shared secret.
            {:else if currentStep === 4}
              Bob signs and sends key info back. Alice verifies. Both compute
              the shared secret.
            {:else if currentStep === 5}
              Alice derives encryption key from shared secret and message keys
              from message secret.
            {:else if currentStep === 6}
              Alice signs message with message signing key and encrypts with
              message encryption key.
            {:else if currentStep === 7}
              Bob decrypts the message secret and then the message itself.
            {/if}
          </p>
        </div>
        <div class="flex space-x-4">
          <button
            on:click={resetDemo}
            class="bg-gray-700 hover:bg-gray-600 text-gray-300 font-medium py-3 px-6 sm:px-8 rounded-lg transition-colors duration-200"
          >
            Reset Demo
          </button>
          <button
            on:click={nextStep}
            disabled={currentStep >= steps.length - 1 || isAnimating}
            class="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-medium py-3 px-6 sm:px-8 rounded-lg transition-colors duration-200"
          >
            {#if isAnimating}
              <svg
                class="animate-spin -ml-1 mr-3 h-5 w-5 text-white inline"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  class="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  stroke-width="4"
                ></circle>
                <path
                  class="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                ></path>
              </svg>
              Processing...
            {:else if currentStep >= steps.length - 1}
              Demo Complete
            {:else}
              Next
            {/if}
          </button>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div class="bg-gray-900/50 border border-gray-700 rounded-xl p-6">
          <div class="flex items-center space-x-3 mb-6">
            <div
              class="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center"
            >
              <span class="text-white font-semibold">A</span>
            </div>
            <h3 class="text-lg font-semibold text-gray-100">Alice</h3>
          </div>

          <div class="space-y-4">
            <!-- Message Input -->
            <div class="bg-gray-800 border border-gray-600 rounded-lg p-4">
              <span class="block text-sm font-medium text-gray-300 mb-2"
                >Message</span
              >
              <textarea
                bind:value={message}
                class="w-full h-20 bg-gray-700 border border-gray-600 rounded p-3 text-gray-100 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter your secret message..."
              ></textarea>
            </div>

            <!-- Alice's Keys & Operations -->
            <div class="bg-gray-800 border border-gray-600 rounded-lg p-4">
              <span class="block text-sm font-medium text-gray-300 mb-3"
                >Alice's Keys & Operations</span
              >
              <div class="space-y-2 text-xs">
                <div class="grid grid-cols-[120px_1fr] gap-2">
                  <span class="text-gray-400">Long-term Key:</span>
                  <span class="font-mono text-blue-300 break-all"
                    >{aliceKeys.longTermPublic}</span
                  >
                </div>
                {#if currentStep >= 1}
                  <div
                    class="grid grid-cols-[120px_1fr] gap-2 transition-all duration-500"
                  >
                    <span class="text-gray-400">Message Secret:</span>
                    <span class="font-mono text-green-300 break-all"
                      >{aliceKeys.messageSecret}</span
                    >
                  </div>
                  <div class="grid grid-cols-[120px_1fr] gap-2">
                    <span class="text-gray-400">Random Value:</span>
                    <span class="font-mono text-yellow-300 break-all"
                      >{aliceKeys.randomValue}</span
                    >
                  </div>
                  <div class="grid grid-cols-[120px_1fr] gap-2">
                    <span class="text-gray-400">Ephemeral Pub:</span>
                    <span class="font-mono text-purple-300 break-all"
                      >{aliceKeys.ephemeralPublic}</span
                    >
                  </div>
                {/if}
                {#if currentStep >= 4}
                  <div
                    class="grid grid-cols-[120px_1fr] gap-2 transition-all duration-500"
                  >
                    <span class="text-gray-400">Shared Secret:</span>
                    <span class="font-mono text-red-300 break-all"
                      >{sharedSecret}</span
                    >
                  </div>
                {/if}
                {#if currentStep >= 5}
                  <div
                    class="grid grid-cols-[120px_1fr] gap-2 transition-all duration-500"
                  >
                    <span class="text-gray-400">Msg Enc Key:</span>
                    <span class="font-mono text-cyan-300 break-all"
                      >{messageEncryptionKey}</span
                    >
                  </div>
                  <div class="grid grid-cols-[120px_1fr] gap-2">
                    <span class="text-gray-400">Msg Sign Key:</span>
                    <span class="font-mono text-orange-300 break-all"
                      >{messageSigningPrivateKey}</span
                    >
                  </div>
                {/if}
              </div>
            </div>

            <!-- Encryption Process -->
            {#if currentStep >= 6}
              <div
                class="bg-gray-800 border border-gray-600 rounded-lg p-4 transition-all duration-500"
              >
                <span class="block text-sm font-medium text-gray-300 mb-3"
                  >Encrypted Output</span
                >
                <div class="space-y-2 text-xs">
                  <div class="grid grid-cols-[100px_1fr] gap-2">
                    <span class="text-gray-400">Signature:</span>
                    <span class="font-mono text-pink-300 break-all"
                      >{messageSignature}</span
                    >
                  </div>
                  <div class="grid grid-cols-[100px_1fr] gap-2">
                    <span class="text-gray-400">Encrypted:</span>
                    <span class="font-mono text-indigo-300 break-all"
                      >{encryptedMessage}</span
                    >
                  </div>
                  <div class="grid grid-cols-[100px_1fr] gap-2">
                    <span class="text-gray-400">Enc. Secret:</span>
                    <span class="font-mono text-teal-300 break-all"
                      >{encryptedMessageSecret}</span
                    >
                  </div>
                </div>
              </div>
            {/if}
          </div>
        </div>

        <div class="bg-gray-900/50 border border-gray-700 rounded-xl p-6">
          <div class="flex items-center space-x-3 mb-6">
            <div
              class="w-10 h-10 bg-emerald-700 rounded-full flex items-center justify-center"
            >
              <span class="text-white font-semibold">B</span>
            </div>
            <h3 class="text-lg font-semibold text-gray-100">Bob</h3>
          </div>

          <div class="space-y-4">
            <!-- Bob's Keys & Operations -->
            <div class="bg-gray-800 border border-gray-600 rounded-lg p-4">
              <span class="block text-sm font-medium text-gray-300 mb-3"
                >Bob's Keys & Operations</span
              >
              <div class="space-y-2 text-xs">
                <div class="grid grid-cols-[120px_1fr] gap-2">
                  <span class="text-gray-400">Long-term Key:</span>
                  <span class="font-mono text-blue-300 break-all"
                    >{bobKeys.longTermPublic}</span
                  >
                </div>
                {#if currentStep >= 3}
                  <div
                    class="grid grid-cols-[120px_1fr] gap-2 transition-all duration-500"
                  >
                    <span class="text-gray-400">Random Value:</span>
                    <span class="font-mono text-yellow-300 break-all"
                      >{bobKeys.randomValue}</span
                    >
                  </div>
                  <div class="grid grid-cols-[120px_1fr] gap-2">
                    <span class="text-gray-400">Ephemeral Pub:</span>
                    <span class="font-mono text-purple-300 break-all"
                      >{bobKeys.ephemeralPublic}</span
                    >
                  </div>
                {/if}
                {#if currentStep >= 4}
                  <div
                    class="grid grid-cols-[120px_1fr] gap-2 transition-all duration-500"
                  >
                    <span class="text-gray-400">Shared Secret:</span>
                    <span class="font-mono text-red-300 break-all"
                      >{sharedSecret}</span
                    >
                  </div>
                {/if}
              </div>
            </div>

            <!-- Decrypted Message -->
            <div class="bg-gray-800 border border-gray-600 rounded-lg p-4">
              <span class="block text-sm font-medium text-gray-300 mb-2"
                >Received Message</span
              >
              <div
                class="h-20 bg-gray-700 border border-gray-600 rounded p-3 flex items-center"
              >
                {#if currentStep >= 7}
                  <span
                    class="text-green-300 font-medium transition-all duration-500"
                    >{decryptedMessage}</span
                  >
                {:else}
                  <span class="text-gray-400 text-sm"
                    >Decrypted message will appear here</span
                  >
                {/if}
              </div>
            </div>

            <!-- Decryption Process -->
            {#if currentStep >= 6}
              <div class="bg-gray-800 border border-gray-600 rounded-lg p-4">
                <span class="block text-sm font-medium text-gray-300 mb-3"
                  >Decryption Process</span
                >
                <div class="space-y-2 text-xs">
                  <div class="grid grid-cols-[120px_1fr] gap-2">
                    <span class="text-gray-400">Received Enc:</span>
                    <span class="font-mono text-indigo-300 break-all"
                      >{encryptedMessage}</span
                    >
                  </div>
                  <div class="grid grid-cols-[120px_1fr] gap-2">
                    <span class="text-gray-400">Enc. Secret:</span>
                    <span class="font-mono text-teal-300 break-all"
                      >{encryptedMessageSecret}</span
                    >
                  </div>
                  {#if currentStep >= 7}
                    <div
                      class="grid grid-cols-[120px_1fr] gap-2 transition-all duration-500"
                    >
                      <span class="text-gray-400">Decrypted:</span>
                      <span class="font-mono text-green-300 break-all"
                        >{decryptedMessage}</span
                      >
                    </div>
                  {/if}
                </div>
              </div>
            {/if}
          </div>
        </div>
      </div>

      <!-- Message Transmission Visualization -->
      <div class="bg-gray-900/50 border border-gray-700 rounded-xl p-6 mb-12">
        <div class="relative">
          <!-- Transmission Arrow -->
          <div class="flex items-center justify-between">
            <div class="text-center">
              <div
                class="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center mb-2"
              >
                <span class="text-white font-semibold">A</span>
              </div>
              <span class="text-sm text-gray-400">Alice</span>
            </div>

            <div class="flex-1 mx-8 relative">
              <!-- Arrow -->
              <div class="h-0.5 bg-gray-600 relative"></div>

              <!-- Transmission Data -->
              {#if transmitSteps.includes(currentStep)}
                <div class="absolute -top-4 left-0 right-0">
                  <div
                    class="bg-gray-800 border border-gray-600 rounded p-2 text-xs"
                  >
                    {#if currentStep === 2}
                      <span class="text-yellow-300">→ Signed key info</span>
                    {:else if currentStep === 3}
                      <span class="text-purple-300">← Bob's key info</span>
                    {:else if currentStep >= 6}
                      <span class="text-green-300"
                        >→ Encrypted message + secret</span
                      >
                    {/if}
                  </div>
                </div>
              {/if}
            </div>

            <div class="text-center">
              <div
                class="w-12 h-12 bg-emerald-700 rounded-full flex items-center justify-center mb-2"
              >
                <span class="text-white font-semibold">B</span>
              </div>
              <span class="text-sm text-gray-400">Bob</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>

  <footer class="border-t border-gray-800 bg-gray-900/30 mt-16">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="text-center">
        <p class="text-gray-400 text-sm">Ivan O'Connor • Cambridge, UK</p>
      </div>
    </div>
  </footer>
</div>

<style>
  /* Additional component-specific styles can go here */
</style>
