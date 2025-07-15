# dverse-identity

**Self-Sovereign Identity for the Decentralized Verse.**

`dverse-identity` is a foundational module within the D-Verse framework, providing robust and secure primitives for managing decentralized identities (DIDs). It empowers users and applications with self-sovereign control over their digital presence, enabling verifiable interactions without reliance on centralized authorities.

## ✨ Features

-   **Cryptographic Key Management:** Secure generation and handling of Ed25519 key pairs.
-   **Digital Signing & Verification:** Functions for cryptographically signing data and verifying signatures, ensuring data integrity and authenticity.
-   **`did:dverse` Method Implementation:** Derivation of unique, self-certifying `did:dverse` identifiers directly from public keys, aligning with W3C DID specifications.
-   **Error Handling:** Comprehensive error types for robust application development.

## 🚀 Getting Started

To use `dverse-identity` in your Rust project, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
dverse-identity = "0.1.0" # Or specify a git dependency for the latest development version
```

### Basic Usage

```rust
use dverse_identity::{KeyPair, Did};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate a new KeyPair
    let keypair = KeyPair::generate()?;
    println!("Generated KeyPair: Public Key: {:?}", keypair.public_key.as_bytes());

    // 2. Derive a did:dverse from the Public Key
    let did = Did::from_public_key(&keypair.public_key)?;
    println!("Derived DID: {}", did.as_str());

    // 3. Sign a message
    let message = b"Hello, D-Verse! This is my verifiable message.";
    let signature = keypair.sign(message)?;
    println!("Generated Signature: {:?}", signature);

    // 4. Verify the signature using the public key derived from the DID
    let recovered_public_key = did.to_public_key()?;
    let temp_keypair_for_verification = KeyPair { // Only public key is needed for verification
        private_key: dverse_identity::PrivateKey::from_bytes(vec![0; 32]), // Dummy
        public_key: recovered_public_key,
    };
    temp_keypair_for_verification.verify(message, &signature)?;
    println!("Signature verified successfully!");

    Ok(())
}
```

## 🛠️ Development

### Prerequisites

-   [Rust](https://www.rust-lang.org/tools/install) (latest stable version recommended)
-   [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) (Rust's package manager, installed with Rust)

### Building

To build the `dverse-identity` crate, navigate to its root directory and run:

```bash
cargo build
```

### Testing

Comprehensive unit and integration tests are provided. To run them:

```bash
cargo test
```

## 🤝 Contributing

We welcome contributions to `dverse-identity`! Your involvement helps us build a robust and secure foundation for the D-Verse ecosystem. Please adhere to our [Contributor's Guide](https://github.com/dverse-systems/dverse-docs/blob/main/07-community/01-contributing.md) for general guidelines.

### Reporting Issues

Found a bug or have a feature request? Please open an issue on our [GitHub Issues page](https://github.com/dverse-systems/dverse-identity/issues).

### Pull Requests

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature-name`).
3.  Make your changes, ensuring they adhere to our coding style and pass all tests.
4.  Write clear, concise commit messages.
5.  Push your branch (`git push origin feature/your-feature-name`).
6.  Open a Pull Request to the `main` branch of `dverse-systems/dverse-identity`.

## 📄 License

This project is licensed under the [MIT License](https://github.com/dverse-systems/dverse-identity/blob/main/LICENSE) (or Apache 2.0, TBD). See the `LICENSE` file for details.

## 📞 Contact & Community

-   **GitHub Organization:** [dverse-systems](https://github.com/dverse-systems)
-   **Discord:** [Join our community](https://discord.gg/placeholder) <!-- Placeholder for Discord invite -->