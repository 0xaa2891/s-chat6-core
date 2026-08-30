//! `media/` — pure byte-processing media pipeline (core-first rule):
//! GIF89a encode, image decode/crop/re-encode + EXIF strip, sticker
//! preparation + thumbnails, magic-byte sniffing. Nothing here touches
//! a camera, a hardware codec, or a screen — clients supply source
//! bytes and render results.
//!
//! Submodule map: `sniff` (magic bytes), `image` (decode/crop/re-encode,
//! profile photos), `gifenc` (GIF89a), `sticker` (pack item prep).

pub mod gifenc;
pub mod image;
pub mod sniff;
pub mod sticker;

pub use gifenc::{encode_gif, GifFrame};
pub use image::{crop_image, prepare_profile_jpeg, strip_and_reencode_image};
pub use sniff::{is_animated_webp, is_image, is_sticker_image, is_video, sniff, MediaKind};
pub use sticker::{prepare_sticker, PreparedSticker};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MediaError {
    /// The bytes are not a supported kind for the operation.
    #[error("unsupported media: {0}")]
    Unsupported(&'static str),
    #[error("decode: {0}")]
    Decode(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("too large: {size} bytes (max {max})")]
    TooLarge { size: usize, max: usize },
}
