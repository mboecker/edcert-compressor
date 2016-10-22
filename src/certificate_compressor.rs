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

use edcert;
use edcert::certificate::Certificate;
use lzma;

static CERTIFICATE_COMPRESSOR_FORMAT_VERSION: [u8; 3] = [1, 1, 0];

/// This type can be used to save `Certificate`s.
pub struct CertificateCompressor;

impl CertificateCompressor {
    fn get_version_from_bytes(bytes: &[u8]) -> String {
        if bytes == b"ert" {
            "1.0.0".to_string()
        } else {
            let major = bytes[0];
            let minor = bytes[1];
            let patch = bytes[2];
            format!("{}.{}.{}", major, minor, patch)
        }
    }

    fn get_bytes_from_version() -> [u8; 3] {
        CERTIFICATE_COMPRESSOR_FORMAT_VERSION
    }

    /// takes a json-encoded byte vector and tries to create a certificate from it.
    pub fn decode(compressed: &[u8]) -> Result<Certificate, &'static str> {
        use rustc_serialize::json;

        use semver::Version;
        use semver::VersionReq;

        // create a byte vector
        let mut bytes: Vec<u8> = Vec::new();

        // load slice into vector
        bytes.extend_from_slice(compressed);

        // read version from the file format
        let version = CertificateCompressor::get_version_from_bytes(&bytes[3..6]);
        let version = Version::parse(&version).expect("Failed to parse file format version");
        let vreq = VersionReq::parse("^1.0.0").expect("Failed to parse version requirement.");

        if vreq.matches(&version) {
            // overwrite with LZMA magic bytes
            let magic: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
            edcert::copy_bytes(&mut bytes[0..6], &magic, 0, 0, 6);

            // decompress the vector
            let o = lzma::decompress(&bytes[..]);
            if o.is_err() {
                return Err("Failed to decompress certificate");
            }

            // read utf8 string
            let o = String::from_utf8(o.unwrap());
            if o.is_err() {
                return Err("Failed to read UTF8 from decompressed vector");
            }

            // decode json object and return Certificate
            let o = json::decode(&o.unwrap());
            if o.is_err() {
                Err("Failed to decode JSON")
            } else {
                Ok(o.unwrap())
            }
        } else {
            Err("Incompatible file format. File corrupted or old Edcert?")
        }
    }

    /// Converts this certificate in a json-encoded byte vector.
    pub fn encode(cert: &Certificate) -> Vec<u8> {
        use rustc_serialize::json;

        let jsoncode = json::encode(cert).expect("Failed to encode certificate");
        let mut compressed = lzma::compress(jsoncode.as_bytes(), 6).expect("failed to compress");
        let magic = b"edc";
        let version = &CertificateCompressor::get_bytes_from_version()[..];
        edcert::copy_bytes(&mut compressed[0..6], magic, 0, 0, 3);
        edcert::copy_bytes(&mut compressed[3..6], version, 0, 0, 3);
        compressed
    }
}

#[test]
fn test_en_and_decoder() {
    use rustc_serialize::json;

    let cert: Certificate = json::decode(r#"
    {
        "meta": {
            "values": {}
        },
        "public_key": "0000000000000000000000000000000000000000000000000000000000000000",
        "private_key": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "expires": "2020-01-01T00:00:00+00:00",
        "signature": null
    }"#).unwrap();

    let bytes = CertificateCompressor::encode(&cert);
    assert_eq!(&bytes[0..3], b"edc");
    assert_eq!(&bytes[3..6], CERTIFICATE_COMPRESSOR_FORMAT_VERSION);

    let cert2 = CertificateCompressor::decode(&bytes).unwrap();

    assert_eq!(cert, cert2);
}

#[test]
fn test_decode_no_version() {
    use rustc_serialize::json;

    let cert: Certificate = json::decode(r#"
    {
        "meta": {
            "values": {}
        },
        "public_key": "0000000000000000000000000000000000000000000000000000000000000000",
        "private_key": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "expires": "2020-01-01T00:00:00+00:00",
        "signature": null
    }"#).unwrap();

    let mut bytes = CertificateCompressor::encode(&cert);

    // these bytes are ASCII for "ert". They are used to simulate an older file format.
    bytes[3] = 0x65;
    bytes[4] = 0x72;
    bytes[5] = 0x74;

    let cert2 = CertificateCompressor::decode(&bytes).unwrap();

    assert_eq!(cert, cert2);
}

#[test]
#[should_panic]
fn test_decode_old_version() {
    use rustc_serialize::json;

    let cert: Certificate = json::decode(r#"
    {
        "meta": {
            "values": {}
        },
        "public_key": "0000000000000000000000000000000000000000000000000000000000000000",
        "private_key": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "expires": "2020-01-01T00:00:00+00:00",
        "signature": null
    }"#).unwrap();

    let mut bytes = CertificateCompressor::encode(&cert);
    bytes[3] = 0;
    bytes[4] = 1;
    bytes[5] = 0;

    // this should panic, since version 0.1.0 is not semver-compatible to any current version
    CertificateCompressor::decode(&bytes).unwrap();
}

#[test]
#[should_panic]
fn test_decode_new_version() {
    use rustc_serialize::json;

    let cert: Certificate = json::decode(r#"
    {
        "meta": {
            "values": {}
        },
        "public_key": "0000000000000000000000000000000000000000000000000000000000000000",
        "private_key": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "expires": "2020-01-01T00:00:00+00:00",
        "signature": null
    }"#).unwrap();

    let mut bytes = CertificateCompressor::encode(&cert);

    let mut version = CERTIFICATE_COMPRESSOR_FORMAT_VERSION;
    version[0] += 1;
    version[1] = 0;
    version[2] = 0;

    edcert::copy_bytes(&mut bytes[3..6], &version, 0, 0, 3);

    // this should panic, since version 0.1.0 is not semver-compatible to any current version
    CertificateCompressor::decode(&bytes).unwrap();
}
