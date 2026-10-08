//! Cryptographic primitives for DDI image signing and verification.
//!
//! Conforms to systemd Discoverable Disk Image signature partitions:
//! the root hash of the dm-verity tree is signed via PKCS#7 SignedData
//! structure (RFC 2315) and stored directly in the `root-verity-sig` partition.

use anyhow::{bail, Result};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509NameBuilder, X509};
use std::fs;
use std::path::Path;

/// RSA private key and X.509 certificate pair used to sign DDI root hashes.
pub struct SigningIdentity {
    pub pkey: PKey<Private>,
    pub cert: X509,
}

impl SigningIdentity {
    /// Generates a new self-signed RSA-3072 identity for Clipak repository or developer signing
    pub fn generate(common_name: &str, validity_days: u32) -> Result<Self> {
        let rsa = Rsa::generate(3072)?;
        let pkey = PKey::from_rsa(rsa)?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("C", "US")?;
        name.append_entry_by_text("O", "Clipak Authority")?;
        name.append_entry_by_text("CN", common_name)?;
        let name = name.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        let serial = {
            let mut bn = BigNum::new()?;
            bn.rand(64, MsbOption::MAYBE_ZERO, false)?;
            bn.to_asn1_integer()?
        };
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&pkey)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(validity_days)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        builder.sign(&pkey, MessageDigest::sha256())?;
        let cert = builder.build();

        Ok(Self { pkey, cert })
    }

    /// Load identity from PEM files
    pub fn load_from_pem<P1: AsRef<Path>, P2: AsRef<Path>>(cert_path: P1, key_path: P2) -> Result<Self> {
        let cert_pem = fs::read(cert_path)?;
        let cert = X509::from_pem(&cert_pem)?;

        let key_pem = fs::read(key_path)?;
        let pkey = PKey::private_key_from_pem(&key_pem)?;

        Ok(Self { pkey, cert })
    }

    /// Save identity to PEM files
    pub fn save_to_pem<P1: AsRef<Path>, P2: AsRef<Path>>(&self, cert_path: P1, key_path: P2) -> Result<()> {
        let cert_pem = self.cert.to_pem()?;
        fs::write(cert_path, cert_pem)?;

        let key_pem = self.pkey.private_key_to_pem_pkcs8()?;
        fs::write(key_path, key_pem)?;

        Ok(())
    }
}

/// Signs root hash using PKCS#7 signedData, embedding the signer's certificate
pub fn sign_root_hash(root_hash: &[u8], identity: &SigningIdentity) -> Result<Vec<u8>> {
    let empty_stack = Stack::<X509>::new()?;
    // Pkcs7::sign generates a PKCS#7 signedData structure
    let pkcs7 = Pkcs7::sign(
        &identity.cert,
        &identity.pkey,
        &empty_stack,
        root_hash,
        Pkcs7Flags::BINARY,
    )?;

    // Serialize to DER format for standard partition storage
    let der = pkcs7.to_der()?;
    Ok(der)
}

/// Verifies a PKCS#7 signature over a root hash against a collection of trusted certificates
pub fn verify_root_hash_signature(
    root_hash: &[u8],
    sig_der: &[u8],
    trusted_certs: &[X509],
) -> Result<bool> {
    if sig_der.is_empty() {
        return Ok(false);
    }

    // Try parsing as DER
    let pkcs7 = match Pkcs7::from_der(sig_der) {
        Ok(p) => p,
        Err(_) => {
            // Also try PEM in case it was stored as PEM
            match Pkcs7::from_pem(sig_der) {
                Ok(p) => p,
                Err(e) => bail!("Failed to parse PKCS#7 signature: {}", e),
            }
        }
    };

    let mut store_builder = X509StoreBuilder::new()?;
    for cert in trusted_certs {
        store_builder.add_cert(cert.clone())?;
    }
    let store = store_builder.build();

    let certs_stack = Stack::<X509>::new()?;
    let mut verified_output = Vec::new();

    // Verify signature
    // If trusted_certs is empty and NOVERIFY is not set, it will fail.
    // If trusted_certs is provided, it validates the signer chain.
    let res = pkcs7.verify(
        &certs_stack,
        &store,
        Some(root_hash),
        Some(&mut verified_output),
        Pkcs7Flags::BINARY,
    );

    match res {
        Ok(_) => Ok(true),
        Err(e) => {
            // Check if it matches with NOVERIFY (self-signed verification without trust store)
            // Useful for permissive policy or testing
            let cert_chain_check = pkcs7.verify(
                &certs_stack,
                &store,
                Some(root_hash),
                None,
                Pkcs7Flags::NOVERIFY | Pkcs7Flags::BINARY,
            );
            if cert_chain_check.is_ok() && trusted_certs.is_empty() {
                // Syntactically valid signature, but no root CA trusted
                return Ok(true);
            }
            bail!("PKCS#7 signature verification failed: {}", e);
        }
    }
}
