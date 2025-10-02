# E2EE Demo

An interactive demonstration of end-to-end encryption using modern cryptographic primitives.

## Features

- **Key Exchange**: X25519 elliptic curve Diffie-Hellman
- **Digital Signatures**: Ed25519 (EdDSA)
- **Symmetric Encryption**: AES-128-GCM
- **Interactive Visualisation**: Step-by-step walkthrough of the encryption process

## Development

```sh
yarn install
yarn dev
```

## Tech Stack

- SvelteKit
- TypeScript
- [@noble/curves](https://github.com/paulmillr/noble-curves)
- Tailwind CSS

## License

MIT
