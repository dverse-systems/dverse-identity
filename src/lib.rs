use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand_core::OsRng;
use serde::{Serialize, Deserialize};
use multibase::{encode, decode, Base};

// --- Error Handling ---
#[derive(Debug)]
pub enum IdentityError {
    KeyGenerationError(String),
    SignatureError(String),
    InvalidKey(String),
    InvalidDidFormat(String),
    EncodingError(String),
    DecodingError(String),
    UnsupportedMulticodec(String),
    UnsupportedMultibase(String),
    // Specific errors from external crates
    DalekError(ed25519_dalek::SignatureError),
    MultibaseError(multibase::Error),
    ArrayConversionError(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;

// Implement From traits for easier error conversion
impl From<ed25519_dalek::SignatureError> for IdentityError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        IdentityError::DalekError(err)
    }
}

impl From<multibase::Error> for IdentityError {
    fn from(err: multibase::Error) -> Self {
        IdentityError::MultibaseError(err)
    }
}

// Implement Display for IdentityError
impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::KeyGenerationError(msg) => write!(f, "Key Generation Error: {}", msg),
            IdentityError::SignatureError(msg) => write!(f, "Signature Error: {}", msg),
            IdentityError::InvalidKey(msg) => write!(f, "Invalid Key: {}", msg),
            IdentityError::InvalidDidFormat(msg) => write!(f, "Invalid DID Format: {}", msg),
            IdentityError::EncodingError(msg) => write!(f, "Encoding Error: {}", msg),
            IdentityError::DecodingError(msg) => write!(f, "Decoding Error: {}", msg),
            IdentityError::UnsupportedMulticodec(msg) => write!(f, "Unsupported Multicodec: {}", msg),
            IdentityError::UnsupportedMultibase(msg) => write!(f, "Unsupported Multibase: {}", msg),
            IdentityError::DalekError(err) => write!(f, "Cryptographic Error: {}", err),
            IdentityError::MultibaseError(err) => write!(f, "Multibase Error: {}", err),
            IdentityError::ArrayConversionError(msg) => write!(f, "Array Conversion Error: {}", msg),
        }
    }
}

// --- Key Pair Representation ---
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey(Vec<u8>);

impl PrivateKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        PrivateKey(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        PublicKey(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

// --- DID Representation ---
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

// --- KeyPair Implementation ---
impl KeyPair {
    pub fn generate() -> Result<Self> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        Ok(KeyPair {
            private_key: PrivateKey(signing_key.to_bytes().to_vec()),
            public_key: PublicKey(verifying_key.to_bytes().to_vec()),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let private_key_bytes: &[u8; 32] = self.private_key.0.as_slice()
            .try_into()
            .map_err(|_| IdentityError::ArrayConversionError("Private key bytes are not 32 bytes long".to_string()))?;
        let signing_key = SigningKey::from_bytes(private_key_bytes);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let public_key_bytes: &[u8; 32] = self.public_key.0.as_slice()
            .try_into()
            .map_err(|_| IdentityError::ArrayConversionError("Public key bytes are not 32 bytes long".to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)?;

        let signature_bytes: &[u8; 64] = signature
            .try_into()
            .map_err(|_| IdentityError::ArrayConversionError("Signature bytes are not 64 bytes long".to_string()))?;
        let signature = Signature::from_bytes(signature_bytes);

        verifying_key.verify(message, &signature)?;
        Ok(())
    }
}

// --- DID Implementation ---
impl Did {
    // Multicodec for Ed25519 public keys (0xed01)
    const MULTICODEC_ED25519_PUB: &'static [u8] = &[0xed, 0x01];
    const DID_DVERSE_PREFIX: &'static str = "did:dverse:";

    pub fn from_public_key(public_key: &PublicKey) -> Result<Self> {
        let mut prefixed_key_bytes = Vec::new();
        prefixed_key_bytes.extend_from_slice(Self::MULTICODEC_ED25519_PUB);
        prefixed_key_bytes.extend_from_slice(&public_key.0);

        // multibase::encode returns a String, not a Result, so no `?` operator here.
        let encoded_key = encode(Base::Base58Btc, &prefixed_key_bytes);

        let did_string = format!("{}{}", Self::DID_DVERSE_PREFIX, encoded_key);

        Ok(Did(did_string))
    }

    pub fn to_public_key(&self) -> Result<PublicKey> {
        if !self.0.starts_with(Self::DID_DVERSE_PREFIX) {
            return Err(IdentityError::InvalidDidFormat(format!("DID does not start with expected prefix: {}", self.0)));
        }

        let encoded_part = &self.0[Self::DID_DVERSE_PREFIX.len()..];

        let (base, decoded_bytes) = decode(encoded_part)?;

        if base != Base::Base58Btc {
            return Err(IdentityError::UnsupportedMultibase(format!("Unsupported multibase: {:?}", base)));
        }

        if decoded_bytes.len() < Self::MULTICODEC_ED25519_PUB.len() || 
           &decoded_bytes[0..Self::MULTICODEC_ED25519_PUB.len()] != Self::MULTICODEC_ED25519_PUB {
            return Err(IdentityError::UnsupportedMulticodec(format!("Unsupported or invalid multicodec prefix: {:?}", &decoded_bytes[0..Self::MULTICODEC_ED25519_PUB.len()])));
        }

        let public_key_bytes = decoded_bytes[Self::MULTICODEC_ED25519_PUB.len()..].to_vec();

        Ok(PublicKey(public_key_bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// --- Conversions for convenience ---
impl From<String> for Did {
    fn from(s: String) -> Self {
        Did(s)
    }
}

impl From<&str> for Did {
    fn from(s: &str) -> Self {
        Did(s.to_string())
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
