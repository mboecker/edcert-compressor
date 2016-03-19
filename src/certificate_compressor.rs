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

pub struct CertificateCompressor;

impl CertificateCompressor {

    /// takes a json-encoded byte vector and tries to create a certificate from it.
    pub fn decode(compressed: &[u8]) -> Result<Certificate, &'static str> {
        use rustc_serialize::json;

        // create a byte vector
        let mut bytes: Vec<u8> = Vec::new();

        // load slice into vector
        bytes.extend(compressed);

        // overwrite with LZMA magic bytes
        let magic: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
        edcert::copy_bytes(&mut bytes[0..7], &magic, 0, 0, 6);

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
    }

    /// Converts this certificate in a json-encoded byte vector.
    pub fn encode(cert: &Certificate) -> Vec<u8> {
        use rustc_serialize::json;

        let jsoncode = json::encode(cert).expect("Failed to encode certificate");
        let mut compressed = lzma::compress(&jsoncode.as_bytes(), 6).expect("failed to compress");
        let magic = "edcert".as_bytes();
        edcert::copy_bytes(&mut compressed[0..6], magic, 0, 0, 6);
        compressed
    }
}
