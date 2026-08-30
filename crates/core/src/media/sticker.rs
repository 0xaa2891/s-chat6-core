//! Sticker/emoji preparation: validate against the wire limits, normalize
//! to an allowed shape, and produce the preview thumbnail.
//!
//! Rules (from `wire_types::sticker::limits`, enforced on *decoded*
//! pixels, never sender claims):
//! - static PNG/WebP or (animated) GIF — never JPEG (EXIF);
//! - emoji are exactly square, stickers within 1:3..3:1;
//! - edge caps: 160 emoji / 512 sticker (long edge, downscaled to fit);
//! - byte caps: 64 KiB emoji / 512 KiB sticker;
//! - thumbnails: ≤96 px long edge, ≤8 KiB PNG.

use image::DynamicImage;

use schat_wire_types::sticker::limits;

use super::image::{decode_bounded, fit_long_edge};
use super::sniff::{self, MediaKind};
use super::MediaError;

/// A send-ready sticker item plus its preview thumbnail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSticker {
    /// Normalized item bytes (PNG for static images, the original blob
    /// for animated GIF/WebP that already fits).
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// ≤96 px PNG thumbnail, ≤8 KiB.
    pub thumb: Vec<u8>,
}

/// Thumbnail edge ladder when 96 px doesn't fit the byte cap.
const THUMB_EDGES: [u32; 4] = [limits::THUMB_EDGE, 64, 48, 32];

fn make_thumb(img: &DynamicImage) -> Result<Vec<u8>, MediaError> {
    for edge in THUMB_EDGES {
        let scaled = fit_long_edge(img, edge);
        let mut out = std::io::Cursor::new(Vec::new());
        scaled
            .write_to(&mut out, image::ImageFormat::Png)
            .map_err(|e| MediaError::Encode(e.to_string()))?;
        let bytes = out.into_inner();
        if bytes.len() <= limits::MAX_THUMB_BYTES {
            return Ok(bytes);
        }
    }
    Err(MediaError::TooLarge {
        size: usize::MAX,
        max: limits::MAX_THUMB_BYTES,
    })
}

/// Prepare one sticker/emoji item from raw source bytes.
///
/// `kind` is `limits::KIND_EMOJI` or `limits::KIND_STICKER`. Animated
/// sources (GIF, animated WebP) pass through unchanged when they
/// already fit the caps — re-encoding would kill the animation; static
/// sources are decoded, downscaled to the edge cap, and re-encoded PNG.
pub fn prepare_sticker(bytes: &[u8], kind: u8) -> Result<PreparedSticker, MediaError> {
    if !limits::valid_kind(kind) {
        return Err(MediaError::Unsupported("unknown sticker kind"));
    }
    let sniffed = sniff::sniff(bytes);
    if !sniff::is_sticker_image(sniffed) {
        return Err(MediaError::Unsupported(sniffed.as_str()));
    }
    if bytes.len() > limits::max_bytes(kind) {
        return Err(MediaError::TooLarge {
            size: bytes.len(),
            max: limits::max_bytes(kind),
        });
    }

    // Decode (first frame for animations) to get ground-truth pixels.
    let img = decode_bounded(bytes)?;
    let (w, h) = (img.width(), img.height());
    if !limits::aspect_ok(kind, w, h) {
        return Err(MediaError::Unsupported("aspect out of range"));
    }

    let animated =
        sniffed == MediaKind::Gif || (sniffed == MediaKind::Webp && sniff::is_animated_webp(bytes));
    if animated {
        // Pass-through: dims must already be within the edge cap.
        if w.max(h) > limits::max_edge(kind) {
            return Err(MediaError::Unsupported("animated source over edge cap"));
        }
        return Ok(PreparedSticker {
            bytes: bytes.to_vec(),
            width: w,
            height: h,
            thumb: make_thumb(&img)?,
        });
    }

    let scaled = fit_long_edge(&img, limits::max_edge(kind));
    let mut out = std::io::Cursor::new(Vec::new());
    scaled
        .write_to(&mut out, image::ImageFormat::Png)
        .map_err(|e| MediaError::Encode(e.to_string()))?;
    let png = out.into_inner();
    if png.len() > limits::max_bytes(kind) {
        return Err(MediaError::TooLarge {
            size: png.len(),
            max: limits::max_bytes(kind),
        });
    }
    Ok(PreparedSticker {
        bytes: png,
        width: scaled.width(),
        height: scaled.height(),
        thumb: make_thumb(&scaled)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageBuffer;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img: image::RgbaImage = ImageBuffer::from_fn(w, h, |x, y| {
            image::Rgba([(x % 256) as u8, (y % 256) as u8, 128, 255])
        });
        let mut out = std::io::Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(img)
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    #[test]
    fn static_sticker_normalized_to_png() {
        let src = png(1024, 512); // 2:1, over the 512 edge cap
        let prep = prepare_sticker(&src, limits::KIND_STICKER).unwrap();
        assert_eq!(sniff::sniff(&prep.bytes), MediaKind::Png);
        assert_eq!((prep.width, prep.height), (512, 256));
        assert!(prep.bytes.len() <= limits::MAX_BYTES_STICKER);
        assert!(prep.thumb.len() <= limits::MAX_THUMB_BYTES);
        let thumb = decode_bounded(&prep.thumb).unwrap();
        assert!(thumb.width().max(thumb.height()) <= limits::THUMB_EDGE);
    }

    #[test]
    fn emoji_must_be_square() {
        assert!(prepare_sticker(&png(100, 100), limits::KIND_EMOJI).is_ok());
        assert!(prepare_sticker(&png(100, 50), limits::KIND_EMOJI).is_err());
        // And the edge cap shrinks to 160.
        let prep = prepare_sticker(&png(400, 400), limits::KIND_EMOJI).unwrap();
        assert_eq!((prep.width, prep.height), (160, 160));
    }

    #[test]
    fn jpeg_and_garbage_rejected() {
        // JPEG is never a sticker (EXIF).
        let img = DynamicImage::new_rgb8(32, 32);
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Jpeg).unwrap();
        assert!(prepare_sticker(&out.into_inner(), limits::KIND_STICKER).is_err());
        assert!(prepare_sticker(b"not an image", limits::KIND_STICKER).is_err());
        assert!(prepare_sticker(&png(32, 32), 99).is_err());
    }

    #[test]
    fn animated_gif_passes_through() {
        let frames = vec![
            crate::media::gifenc::GifFrame {
                rgba: [255, 0, 0, 255].repeat((64 * 64) as usize),
                width: 64,
                height: 64,
                delay_cs: 10,
            },
            crate::media::gifenc::GifFrame {
                rgba: [0, 0, 255, 255].repeat((64 * 64) as usize),
                width: 64,
                height: 64,
                delay_cs: 10,
            },
        ];
        let gif = crate::media::gifenc::encode_gif(&frames).unwrap();
        let prep = prepare_sticker(&gif, limits::KIND_STICKER).unwrap();
        assert_eq!(prep.bytes, gif, "animation preserved byte-for-byte");
        assert_eq!((prep.width, prep.height), (64, 64));
    }
}
