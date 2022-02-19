use std::{path::Path, io::Cursor};

use rustls::{Certificate, PrivateKey};

pub(crate) fn read_certs(file: &Path) -> std::io::Result<Vec<Certificate>> {
    let mut file_reader = std::io::BufReader::new(std::fs::File::open(file)?);

    let certs = rustls_pemfile::certs(&mut file_reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}

pub(crate) fn read_key(file: &Path) -> std::io::Result<Option<PrivateKey>> {
    let file_contents = std::fs::read(file)?;

    let keys = rustls_pemfile::pkcs8_private_keys(&mut Cursor::new(&file_contents))?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(Some(PrivateKey(key)));
    }

    let keys = rustls_pemfile::rsa_private_keys(&mut Cursor::new(&file_contents))?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(Some(PrivateKey(key)));
    }

    Ok(None)
}
