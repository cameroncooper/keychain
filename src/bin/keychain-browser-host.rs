use std::io::{self, Read, Write};
use std::path::Path;

use keychain::browser::{MAX_NATIVE_MESSAGE_BYTES, reply_for_message};
use keychain::paths::AppPaths;
use keychain::security::SoftwareFileBackend;
use keychain::store::StateStore;
use keychain::{Error, Result};

fn main() {
    if let Err(error) = run() {
        eprintln!("keychain-browser-host: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let message = read_frame(&mut io::stdin())?;
    let paths = AppPaths::discover()?;
    let backend = SoftwareFileBackend::new(paths.clone());
    let store = StateStore::new(&paths, &backend);
    let reply = reply_for_message(&message, &backend, &store);
    let encoded = serde_json::to_vec(&reply)?;
    write_frame(&mut io::stdout(), &encoded)
}

fn read_frame(reader: &mut dyn Read) -> Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|error| Error::io(Path::new("<native-messaging stdin>"), error))?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_NATIVE_MESSAGE_BYTES {
        return Err(Error::InvalidData(format!(
            "native message length {length} is outside the 1..={MAX_NATIVE_MESSAGE_BYTES} byte limit"
        )));
    }
    let mut message = vec![0_u8; length];
    reader
        .read_exact(&mut message)
        .map_err(|error| Error::io(Path::new("<native-messaging stdin>"), error))?;
    Ok(message)
}

fn write_frame(writer: &mut dyn Write, message: &[u8]) -> Result<()> {
    if message.len() > MAX_NATIVE_MESSAGE_BYTES {
        return Err(Error::InvalidData(format!(
            "native reply exceeds the {MAX_NATIVE_MESSAGE_BYTES}-byte limit"
        )));
    }
    let length = u32::try_from(message.len())
        .map_err(|_| Error::InvalidData("native reply is too large".into()))?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(message))
        .and_then(|()| writer.flush())
        .map_err(|error| Error::io(Path::new("<native-messaging stdout>"), error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_message_framing_is_little_endian_and_bounded() {
        let payload = br#"{"version":1}"#;
        let mut encoded = Vec::new();
        write_frame(&mut encoded, payload).unwrap_or_else(|error| panic!("write: {error}"));
        assert_eq!(&encoded[..4], &(payload.len() as u32).to_le_bytes());
        let decoded =
            read_frame(&mut encoded.as_slice()).unwrap_or_else(|error| panic!("read: {error}"));
        assert_eq!(decoded, payload);

        let mut oversized = ((MAX_NATIVE_MESSAGE_BYTES + 1) as u32)
            .to_le_bytes()
            .to_vec();
        oversized.extend_from_slice(b"ignored");
        assert!(read_frame(&mut oversized.as_slice()).is_err());
    }
}
