// The MIT License (MIT)
//
// Copyright (c) 2016 Marvin Böcker
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use edcert::certificate::Certificate;
use certificate_compressor::CertificateCompressor;

/// This type can be used to load `Certificate`s.
pub struct CertificateLoader;

impl CertificateLoader {
    /// Saves this certificate into a folder: one file for the certificate and one file for the
    /// private key.
    pub fn save_to_folder(cert: &Certificate, folder: &str) -> Result<(), &'static str> {
        use std::fs::DirBuilder;
        use std::fs::metadata;

        if metadata(&folder).is_err() && DirBuilder::new().create(&folder).is_err() {
            return Err("Failed to create folder");
        }

        if cert.has_private_key() {
            try!(CertificateLoader::save_private_key(cert, &format!("{}/private.key", &folder)));
        }

        try!(CertificateLoader::save_to_file(cert, &format!("{}/certificate.edc", &folder)));

        Ok(())
    }

    /// Reads a certificate from a folder like it has been saved with save_to_folder
    pub fn load_from_folder(folder: &str) -> Result<Certificate, &'static str> {

        let mut cert = try!(CertificateLoader::load_from_file(&format!("{}/certificate.edc",
                                                                       &folder)));
        try!(CertificateLoader::load_private_key(&mut cert, &format!("{}/private.key", &folder)));
        Ok(cert)

    }

    /// Saves the certificate in encoded form to a file
    pub fn save_to_file(cert: &Certificate, filename: &str) -> Result<(), &'static str> {
        use std::fs::File;
        use std::io::Write;

        let mut certificate_file: File = match File::create(filename) {
            Ok(x) => x,
            Err(_) => return Err("Failed to create certificate file"),
        };

        let compressed = CertificateCompressor::encode(cert);
        match certificate_file.write(&*compressed) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to write certificate to File."),
        }
    }

    /// Saves the private key to a file. Just the binary string.
    pub fn save_private_key(cert: &Certificate, filename: &str) -> Result<(), &'static str> {
        use std::fs::File;
        use std::io::Write;

        let bytes: &[u8] = match cert.private_key() {
            Some(x) => x,
            None => return Err("The certificate has no private key."),
        };

        let mut private_keyfile: File = match File::create(&filename) {
            Ok(x) => x,
            Err(_) => return Err("Failed to create private key file."),
        };

        match private_keyfile.write_all(bytes) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to write private key file."),
        }
    }

    /// This method loads a certificate from a file.
    pub fn load_from_file(filename: &str) -> Result<Certificate, &'static str> {
        use std::fs::File;
        use std::io::Read;

        let filename: String = filename.to_string();
        let mut certificate_file: File = match File::open(filename) {
            Err(_) => return Err("Failed to open certificate file."),
            Ok(x) => x,
        };
        let mut compressed = Vec::new();
        if let Err(_) = certificate_file.read_to_end(&mut compressed) {
            return Err("Failed to read certificate");
        }
        CertificateCompressor::decode(&*compressed)
    }

    /// This method reads a private key from a file and sets it in this certificate.
    pub fn load_private_key(cert: &mut Certificate, filename: &str) -> Result<(), &'static str> {
        use std::fs::File;
        use std::io::Read;

        let filename: String = filename.to_string();
        let mut private_key_file: File = match File::open(filename) {
            Err(_) => return Err("Failed to open private kye file."),
            Ok(x) => x,
        };
        let mut private_key = Vec::new();
        if let Err(_) = private_key_file.read_to_end(&mut private_key) {
            return Err("Failed to read private key");
        }

        cert.set_private_key(private_key);

        Ok(())
    }
}

#[test]
fn test_save() {
    use edcert::ed25519;
    use edcert::meta::Meta;
    use chrono::Timelike;
    use chrono::UTC;
    use chrono::duration::Duration;
    use edcert::validator::Validator;
    use edcert::root_validator::RootValidator;
    use edcert::revoker::NoRevoker;

    let (mpk, msk) = ed25519::generate_keypair();
    let cv = RootValidator::new(&mpk, NoRevoker);

    let meta = Meta::new_empty();
    let expires = UTC::now()
                      .checked_add(Duration::days(90))
                      .expect("Failed to add a day to expiration date.")
                      .with_nanosecond(0)
                      .unwrap();

    let mut cert = Certificate::generate_random(meta, expires);

    cert.sign_with_master(&msk);

    assert_eq!(true, cv.is_valid(&cert).is_ok());

    CertificateLoader::save_to_folder(&cert, &expires.to_rfc3339()).unwrap();
    let mut cert = CertificateLoader::load_from_file(&format!("{}{}",
                                                              &expires.to_rfc3339(),
                                                              "/certificate.edc"))
                       .expect("Failed to load certificate from file");
    CertificateLoader::load_private_key(&mut cert,
                                        &format!("{}{}", &expires.to_rfc3339(), "/private.key"))
        .expect("Failed to load private key from file");

    assert_eq!(true, cv.is_valid(&cert).is_ok());
}
