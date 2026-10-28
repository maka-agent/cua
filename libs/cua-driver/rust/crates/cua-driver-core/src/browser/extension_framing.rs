// SPDX-License-Identifier: MIT

//! Chrome extension-messaging framing, without process or desktop side effects.
//!
//! The caller must retire the stream after an error. A failed write does not
//! prove that Chrome did not receive the command; this codec never replays it.

use serde::{Serialize, de::IgnoredAny};
use std::{
    collections::TryReserveError,
    io::{self, Read, Write},
    str::Utf8Error,
};

/// Chrome's directional limits are byte limits, including UTF-8 expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    HostToChrome,
    ChromeToHost,
}

impl Direction {
    pub(crate) fn limit(self) -> usize {
        match self {
            Self::HostToChrome => 1024 * 1024,
            Self::ChromeToHost => 64 * 1024 * 1024,
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::HostToChrome => "host to Chrome",
            Self::ChromeToHost => "Chrome to host",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum FrameError {
    #[error("extension-message I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("extension-message header ended after {received} of 4 bytes")]
    TruncatedHeader { received: usize },
    #[error("extension-message body ended after {received} of {expected} bytes")]
    TruncatedBody { expected: usize, received: usize },
    #[error("extension-message body is empty")]
    Empty,
    #[error("extension-message body is at least {at_least} bytes; {direction} limit is {limit}")]
    TooLarge {
        direction: Direction,
        at_least: usize,
        limit: usize,
    },
    #[error("extension-message length cannot fit its 32-bit header")]
    LengthOverflow,
    #[error("extension-message body is not UTF-8: {0}")]
    Utf8(#[from] Utf8Error),
    #[error("extension-message body is not one JSON value: {0}")]
    Json(#[from] serde_json::Error),
    #[error("extension-message body allocation failed: {0}")]
    Allocation(#[from] TryReserveError),
}

fn check_length(length: usize, direction: Direction) -> Result<(), FrameError> {
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > direction.limit() {
        return Err(FrameError::TooLarge {
            direction,
            at_least: length,
            limit: direction.limit(),
        });
    }
    Ok(())
}

fn read_until_full(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut received = 0;
    while received < buffer.len() {
        match reader.read(&mut buffer[received..]) {
            Ok(0) => break,
            Ok(count) => received += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(received)
}

/// Read one complete UTF-8 JSON frame, preserving its exact JSON payload bytes.
///
/// `None` means EOF before any header byte. Length is checked before allocation
/// or body reads. Partial headers, partial bodies, invalid JSON and I/O errors
/// require the caller to retire the stream instead of attempting resynchronization.
///
/// # Errors
/// Returns a framing, allocation, JSON or I/O error without dispatching a command.
pub(crate) fn read_frame(
    reader: &mut impl Read,
    direction: Direction,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0_u8; 4];
    match read_until_full(reader, &mut header)? {
        0 => return Ok(None),
        4 => {}
        received => return Err(FrameError::TruncatedHeader { received }),
    }
    let length = u32::from_ne_bytes(header) as usize;
    check_length(length, direction)?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(length)?;
    payload.resize(length, 0);
    let received = read_until_full(reader, &mut payload)?;
    if received != length {
        return Err(FrameError::TruncatedBody {
            expected: length,
            received,
        });
    }
    std::str::from_utf8(&payload)?;
    // Validation does not build an expanded arbitrary JSON Value tree here.
    serde_json::from_slice::<IgnoredAny>(&payload)?;
    Ok(Some(payload))
}

struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: Option<usize>,
}

impl BoundedJson {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: None,
        }
    }
}

impl Write for BoundedJson {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let length = self.bytes.len().saturating_add(buffer.len());
        if length > self.limit {
            self.exceeded = Some(length);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extension-message byte limit exceeded",
            ));
        }
        self.bytes
            .try_reserve(buffer.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serialize to a bounded JSON payload without performing any wire I/O.
///
/// # Errors
/// Rejects oversized or invalid serialization before any frame is emitted.
pub(crate) fn encode_json(
    value: &impl Serialize,
    direction: Direction,
) -> Result<Vec<u8>, FrameError> {
    let mut payload = BoundedJson::new(direction.limit());
    if let Err(error) = serde_json::to_writer(&mut payload, value) {
        return Err(match payload.exceeded {
            Some(at_least) => FrameError::TooLarge {
                direction,
                at_least,
                limit: direction.limit(),
            },
            None => FrameError::Json(error),
        });
    }
    check_length(payload.bytes.len(), direction)?;
    Ok(payload.bytes)
}

/// Serialize within the directional limit, then emit one frame and flush it.
///
/// A partial write or flush failure is never retried as a logical command.
///
/// # Errors
/// Rejects oversized serialization before output; later I/O errors can occur
/// after some or all of the frame reached Chrome and require stream retirement.
pub(crate) fn write_frame(
    writer: &mut impl Write,
    value: &impl Serialize,
    direction: Direction,
) -> Result<(), FrameError> {
    let payload = encode_json(value, direction)?;
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::LengthOverflow)?;
    writer.write_all(&length.to_ne_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut bytes = u32::try_from(payload.len()).unwrap().to_ne_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn utf8_uses_byte_length_and_preserves_exact_payload() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &json!({"text":"你好"}), Direction::HostToChrome).unwrap();
        let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(
            length,
            bytes.len() - 4,
            "header must count encoded UTF-8 bytes"
        );
        assert_eq!(&bytes[4..], "{\"text\":\"你好\"}".as_bytes());
        assert_eq!(
            read_frame(&mut Cursor::new(bytes), Direction::ChromeToHost).unwrap(),
            Some("{\"text\":\"你好\"}".as_bytes().to_vec())
        );
    }

    #[test]
    fn clean_eof_differs_from_partial_headers() {
        assert!(
            read_frame(&mut Cursor::new([]), Direction::ChromeToHost)
                .unwrap()
                .is_none()
        );
        for received in 1..4 {
            let result = read_frame(&mut Cursor::new(vec![0; received]), Direction::ChromeToHost);
            assert!(
                matches!(result, Err(FrameError::TruncatedHeader { received: actual }) if actual == received),
                "partial prefix {received}"
            );
        }
    }

    #[test]
    fn oversized_header_refuses_before_any_body_read() {
        struct HeaderOnly {
            header: Cursor<[u8; 4]>,
        }
        impl Read for HeaderOnly {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                assert!(
                    self.header.position() < 4,
                    "oversized frame must not cause a payload read"
                );
                self.header.read(output)
            }
        }
        let mut reader = HeaderOnly {
            header: Cursor::new((64_u32 * 1024 * 1024 + 1).to_ne_bytes()),
        };
        assert!(matches!(
            read_frame(&mut reader, Direction::ChromeToHost),
            Err(FrameError::TooLarge {
                direction: Direction::ChromeToHost,
                ..
            })
        ));
    }

    #[test]
    fn exact_host_limit_is_written_but_one_extra_byte_never_reaches_wire() {
        let limit = 1024 * 1024;
        let exact = "x".repeat(limit - 2);
        let mut output = Vec::new();
        write_frame(&mut output, &exact, Direction::HostToChrome).unwrap();
        assert_eq!(
            output.len(),
            limit + 4,
            "JSON quotes count toward the limit"
        );
        let mut refused = Vec::new();
        assert!(matches!(
            write_frame(&mut refused, &(exact + "x"), Direction::HostToChrome),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(
            refused.is_empty(),
            "oversized command must not emit a partial frame"
        );
    }

    #[test]
    fn malformed_payload_and_truncation_are_refusals() {
        assert!(matches!(
            read_frame(&mut Cursor::new([0_u8; 4]), Direction::ChromeToHost),
            Err(FrameError::Empty)
        ));
        assert!(matches!(
            read_frame(
                &mut Cursor::new(framed(b"{\"a\":}")),
                Direction::ChromeToHost
            ),
            Err(FrameError::Json(_))
        ));
        assert!(matches!(
            read_frame(
                &mut Cursor::new(framed(b"\"\xff\"")),
                Direction::ChromeToHost
            ),
            Err(FrameError::Utf8(_))
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new(framed(b"{} {}")), Direction::ChromeToHost),
            Err(FrameError::Json(_))
        ));
        let mut partial = 8_u32.to_ne_bytes().to_vec();
        partial.extend_from_slice(b"{}");
        assert!(matches!(
            read_frame(&mut Cursor::new(partial), Direction::ChromeToHost),
            Err(FrameError::TruncatedBody {
                expected: 8,
                received: 2
            })
        ));
    }

    #[test]
    fn fragmented_and_interrupted_reads_preserve_frame_boundaries() {
        struct Fragmented {
            bytes: Cursor<Vec<u8>>,
            interrupt: bool,
        }
        impl Read for Fragmented {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.interrupt {
                    self.interrupt = false;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.interrupt = true;
                self.bytes.read(&mut output[..1])
            }
        }
        let mut bytes = framed(b"{\"first\":1}");
        bytes.extend_from_slice(&framed(b"[2]"));
        let mut reader = Fragmented {
            bytes: Cursor::new(bytes),
            interrupt: true,
        };
        assert_eq!(
            read_frame(&mut reader, Direction::ChromeToHost).unwrap(),
            Some(b"{\"first\":1}".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader, Direction::ChromeToHost).unwrap(),
            Some(b"[2]".to_vec())
        );
        assert!(
            read_frame(&mut reader, Direction::ChromeToHost)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn partial_write_failure_is_returned_without_replaying_frame() {
        struct Broken {
            output: Vec<u8>,
        }
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.output.len() >= 6 {
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                let count = bytes.len().min(6 - self.output.len());
                self.output.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Broken { output: Vec::new() };
        assert!(
            matches!(write_frame(&mut writer, &json!({"effect":"once"}), Direction::HostToChrome), Err(FrameError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(
            writer.output.len(),
            6,
            "partial header/body must not be restarted"
        );
    }
}
