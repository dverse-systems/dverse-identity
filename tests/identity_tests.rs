use dverse_identity::{
    KeyPair,
    Did,
    IdentityError,
    PrivateKey,
};

#[test]
fn test_keypair_generation() {
    let keypair = KeyPair::generate().expect("Should generate keypair");
    assert_eq!(keypair.private_key.as_bytes().len(), 32, "Private key should be 32 bytes");
    assert_eq!(keypair.public_key.as_bytes().len(), 32, "Public key should be 32 bytes");
}

#[test]
fn test_sign_and_verify_success() {
    let keypair = KeyPair::generate().expect("Should sign message");
    let message = b"Hello, D-Verse!";
    let signature = keypair.sign(message).expect("Should sign message");

    assert_eq!(signature.len(), 64, "Signature should be 64 bytes");

    keypair.verify(message, &signature).expect("Signature should verify successfully");
}

#[test]
fn test_verify_failure_wrong_message() {
    let keypair = KeyPair::generate().expect("Should generate keypair");
    let message = b"Hello, D-Verse!";
    let wrong_message = b"Goodbye, D-Verse!";
    let signature = keypair.sign(message).expect("Should sign message");

    let result = keypair.verify(wrong_message, &signature);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdentityError::DalekError(_)));
}

#[test]
fn test_verify_failure_wrong_signature() {
    let keypair = KeyPair::generate().expect("Should generate keypair");
    let message = b"Hello, D-Verse!";
    let mut signature = keypair.sign(message).expect("Should sign message");
    signature[0] ^= 0x01; // Corrupt the signature

    let result = keypair.verify(message, &signature);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdentityError::DalekError(_)));
}

#[test]
fn test_did_from_public_key() {
    let keypair = KeyPair::generate().expect("Should generate keypair");
    let did = Did::from_public_key(&keypair.public_key).expect("Should derive DID");

    let did_str = did.as_str();
    assert!(did_str.starts_with("did:dverse:z"));
    // A more robust test would decode and verify the multibase/multicodec parts
    // but for a basic check, prefix and length are good.
    // Ed25519 pubkey (32 bytes) + multicodec (2 bytes) = 34 bytes
    // Base58 encoding adds some overhead, so length will be > 34
    assert!(did_str.len() > "did:dverse:z".len() + 34);
}

#[test]
fn test_did_to_public_key_roundtrip() {
    let keypair = KeyPair::generate().expect("Should generate keypair");
    let did = Did::from_public_key(&keypair.public_key).expect("Should derive DID");

    let recovered_public_key = did.to_public_key().expect("Should recover public key from DID");

    assert_eq!(keypair.public_key, recovered_public_key);
}

#[test]
fn test_did_roundtrip_sign_verify() {
    let keypair = KeyPair::generate().expect("Should generate keypair");
    let did = Did::from_public_key(&keypair.public_key).expect("Should derive DID");

    let message = b"This is a test message for DID verification.";
    let signature = keypair.sign(message).expect("Should sign message");

    let recovered_public_key = did.to_public_key().expect("Should recover public key from DID");

    // Create a temporary KeyPair for verification using the recovered public key
    let temp_keypair_for_verification = KeyPair {
        private_key: PrivateKey::from_bytes(vec![0; 32]), // Dummy private key, not used for verification
        public_key: recovered_public_key,
    };

    temp_keypair_for_verification.verify(message, &signature).expect("Signature should verify with recovered public key");
}

#[test]
fn test_did_to_public_key_invalid_format() {
    let invalid_did = Did::from("not:a:did:key");
    let result = invalid_did.to_public_key();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdentityError::InvalidDidFormat(_)));

    let invalid_did_prefix = Did::from("did:key:zABC"); // Wrong prefix
    let result = invalid_did_prefix.to_public_key();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdentityError::InvalidDidFormat(_)));

    let invalid_multibase = Did::from("did:dverse:xABC"); // 'x' is not base58-btc
    let result = invalid_multibase.to_public_key();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdentityError::MultibaseError(_))); // Corrected assertion

    let invalid_multicodec = Did::from("did:dverse:z6NABC"); // '6N' is not Ed25519 multicodec
    let result = invalid_multicodec.to_public_key();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdentityError::UnsupportedMulticodec(_)));
}

#[test]
fn test_did_display_and_from_str() {
    let did_str = "did:dverse:z6Mkk...test";
    let did_from_str: Did = did_str.into();
    assert_eq!(did_from_str.as_str(), did_str);
    assert_eq!(format!("{}", did_from_str), did_str);

    let did_from_string: Did = did_str.to_string().into();
    assert_eq!(did_from_string.as_str(), did_str);
}
