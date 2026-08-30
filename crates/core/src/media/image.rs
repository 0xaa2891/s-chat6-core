//! Image decode / crop / re-encode / EXIF strip via the `image` crate.
//! Decoding and re-encoding from pixels is what strips metadata — there
//! is no header surgery to get wrong.
//!
//! All decodes are bounded (input bytes + pixel caps) so a hostile blob
//! cannot exhaust memory.

use std::io::Cursor;

use image::{DynamicImage, ImageReader};

use super::sniff::{self, MediaKind};
use super::MediaError;

// Ingress bounds declared in the bounds catalog;
// re-exported so `image::MAX_INPUT_BYTES` etc. keep working.
pub use crate::limits::media::{
    JPEG_TARGET_BYTES, LONG_EDGE, MAX_DECODE_EDGE, MAX_INPUT_BYTES, PROFILE_EDGES,
};

/// Outbound photo prep: JPEG quality ladder
/// until under the byte target.
pub const JPEG_QUALITY: u8 = 40;
pub const JPEG_QUALITY_MIN: u8 = 20;

/// Profile photos: fixed quality while trying
/// `PROFILE_EDGES` until the result fits `profile::MAX_JPEG`.
pub const PROFILE_JPEG_QUALITY: u8 = 40;

pub(crate) fn decode_bounded(bytes: &[u8]) -> Result<DynamicImage, MediaError> {
    if bytes.is_empty() {
        return Err(MediaError::Decode("empty input".into()));
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(MediaError::TooLarge {
            size: bytes.len(),
            max: MAX_INPUT_BYTES,
        });
    }
    let mut reader = ImageReader::new(Cursor::new(bytes));
    let format = match sniff::sniff(bytes) {
        MediaKind::Jpeg => Some(image::ImageFormat::Jpeg),
        MediaKind::Png => Some(image::ImageFormat::Png),
        MediaKind::Webp => Some(image::ImageFormat::WebP),
        MediaKind::Gif => Some(image::ImageFormat::Gif),
        _ => None,
    };
    if let Some(format) = format {
        reader.set_format(format);
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_DECODE_EDGE);
    limits.max_image_height = Some(MAX_DECODE_EDGE);
    reader.limits(limits);
    let reader = reader
        .with_guessed_format()
        .map_err(|e| MediaError::Decode(e.to_string()))?;
    reader
        .decode()
        .map_err(|e| MediaError::Decode(e.to_string()))
}

fn encode_jpeg(img: &DynamicImage, quality: u8) -> Result<Vec<u8>, MediaError> {
    let rgb = img.to_rgb8();
    let mut out = Cursor::new(Vec::new());
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
    use image::ImageEncoder;
    encoder
        .write_image(
            rgb.as_raw(),
            rgb.width(),
            rgb.height(),
            image::ExtendedColorType::Rgb8,
        )
        .map_err(|e| MediaError::Encode(e.to_string()))?;
    Ok(out.into_inner())
}

fn encode_png(img: &DynamicImage) -> Result<Vec<u8>, MediaError> {
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png)
        .map_err(|e| MediaError::Encode(e.to_string()))?;
    Ok(out.into_inner())
}

/// Fit `img` within `max_edge` on the long side, preserving aspect.
/// Never upscales.
pub fn fit_long_edge(img: &DynamicImage, max_edge: u32) -> DynamicImage {
    if img.width().max(img.height()) <= max_edge {
        return img.clone();
    }
    img.resize(max_edge, max_edge, image::imageops::FilterType::Lanczos3)
}

/// Decode + re-encode: the EXIF/metadata strip. Photos (no alpha) come
/// back as JPEG on the quality ladder under the byte
/// target; anything with alpha comes back as PNG.
pub fn strip_and_reencode_image(bytes: &[u8]) -> Result<Vec<u8>, MediaError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(MediaError::TooLarge {
            size: bytes.len(),
            max: MAX_INPUT_BYTES,
        });
    }
    let kind = sniff::sniff(bytes);
    if !sniff::is_image(kind) && kind != MediaKind::Gif {
        return Err(MediaError::Unsupported(kind.as_str()));
    }
    let img = decode_bounded(bytes)?;
    let img = fit_long_edge(&img, LONG_EDGE);
    if img.color().has_alpha() {
        return encode_png(&img);
    }
    let mut quality = JPEG_QUALITY;
    loop {
        let out = encode_jpeg(&img, quality)?;
        if out.len() <= JPEG_TARGET_BYTES || quality <= JPEG_QUALITY_MIN {
            return Ok(out);
        }
        quality -= 5;
    }
}

/// Pack-preview thumbnail: 96px long edge,
/// PNG when alpha is present, JPEG otherwise, under the 8 KiB cap.
pub fn make_thumbnail(bytes: &[u8]) -> Result<Vec<u8>, MediaError> {
    use schat_wire_types::sticker::limits;
    let img = decode_bounded(bytes)?;
    let scaled = fit_long_edge(&img, limits::THUMB_EDGE);
    let out = if scaled.color().has_alpha() {
        encode_png(&scaled)?
    } else {
        encode_jpeg(&scaled, 80)?
    };
    if out.len() > limits::MAX_THUMB_BYTES {
        return Err(MediaError::TooLarge {
            size: out.len(),
            max: limits::MAX_THUMB_BYTES,
        });
    }
    Ok(out)
}

/// Profile photo prep: edge ladder at fixed
/// quality until the JPEG fits the wire cap.
pub fn prepare_profile_jpeg(bytes: &[u8]) -> Result<Vec<u8>, MediaError> {
    let img = decode_bounded(bytes)?;
    let mut last = None;
    for edge in PROFILE_EDGES {
        let scaled = fit_long_edge(&img, edge);
        let out = encode_jpeg(&scaled, PROFILE_JPEG_QUALITY)?;
        if out.len() <= schat_wire_types::profile::MAX_JPEG {
            return Ok(out);
        }
        last = Some(out);
    }
    // Smallest ladder step still over the cap: fail closed.
    let _ = last;
    Err(MediaError::TooLarge {
        size: usize::MAX,
        max: schat_wire_types::profile::MAX_JPEG,
    })
}

/// Crop to a rectangle and re-encode as
/// PNG (lossless; the crop UI's output feeds `prepare_*` next).
pub fn crop_image(bytes: &[u8], x: u32, y: u32, w: u32, h: u32) -> Result<Vec<u8>, MediaError> {
    let img = decode_bounded(bytes)?;
    if w == 0 || h == 0 || x + w > img.width() || y + h > img.height() {
        return Err(MediaError::Decode(format!(
            "crop {x},{y} {w}x{h} outside {}x{}",
            img.width(),
            img.height()
        )));
    }
    encode_png(&img.crop_imm(x, y, w, h))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRC-32/ISO-HDLC (PNG chunk CRC) — tiny local copy so the test
    /// can splice a *valid* tEXt chunk.
    fn crc32_png(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xffff_ffff;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A tiny valid PNG with a tEXt chunk (stands in for EXIF metadata).
    fn png_with_metadata() -> Vec<u8> {
        let img = DynamicImage::new_rgb8(64, 48);
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        let mut bytes = out.into_inner();
        // Splice a tEXt chunk after the 8-byte signature + IHDR.
        // (PNG length covers data only — type bytes excluded.)
        let text = b"tEXtComment\x00sensitive-metadata-here";
        let mut chunk = ((text.len() - 4) as u32).to_be_bytes().to_vec();
        chunk.extend_from_slice(text);
        chunk.extend_from_slice(&crc32_png(text).to_be_bytes());
        let ihdr_end = 8 + 12 + 13;
        bytes.splice(ihdr_end..ihdr_end, chunk);
        bytes
    }

    #[test]
    fn strip_removes_metadata_chunks() {
        let input = png_with_metadata();
        assert!(
            input.windows(9).any(|w| w == b"sensitive"),
            "test input must carry the marker"
        );
        let out = strip_and_reencode_image(&input).unwrap();
        assert_eq!(sniff::sniff(&out), MediaKind::Jpeg, "RGB → JPEG");
        assert!(
            !out.windows(9).any(|w| w == b"sensitive"),
            "metadata must not survive decode+re-encode"
        );
        // And the result is a real image.
        decode_bounded(&out).unwrap();
    }

    /// A real JPEG with an APP1 EXIF segment spliced in after the SOI —
    /// the classic phone-camera shape (GPS, device model, timestamps).
    fn jpeg_with_exif() -> Vec<u8> {
        let img = DynamicImage::new_rgb8(80, 60);
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Jpeg).unwrap();
        let mut bytes = out.into_inner();
        assert_eq!(&bytes[..2], &[0xff, 0xd8], "SOI");
        // APP1: marker FFE1, u16be length (covers the length field
        // itself), "Exif\0\0" + a fake TIFF payload with a GPS-ish
        // marker string.
        let payload = b"Exif\0\0II*\0 GPS: 48.8584 N, 2.2945 E - Eiffel";
        let app1_len = (payload.len() + 2) as u16;
        let mut seg = vec![0xff, 0xe1];
        seg.extend_from_slice(&app1_len.to_be_bytes());
        seg.extend_from_slice(payload);
        bytes.splice(2..2, seg);
        bytes
    }

    #[test]
    fn strip_removes_exif_app1() {
        let input = jpeg_with_exif();
        assert!(
            input.windows(4).any(|w| w == b"Exif"),
            "fixture must carry the EXIF marker"
        );
        // The EXIF-carrying input still decodes (readers skip APP1).
        decode_bounded(&input).unwrap();
        let out = strip_and_reencode_image(&input).unwrap();
        assert_eq!(sniff::sniff(&out), MediaKind::Jpeg);
        assert!(
            !out.windows(4).any(|w| w == b"Exif") && !out.windows(3).any(|w| w == b"GPS"),
            "EXIF/GPS must not survive the pipeline"
        );
        // The fresh JPEG carries no APPn metadata segments at all:
        // after SOI the first marker is a frame/ table segment.
        assert_ne!(&out[2..4], &[0xff, 0xe1], "no APP1 in output");
        decode_bounded(&out).unwrap();
    }

    #[test]
    fn alpha_stays_png() {
        let img = DynamicImage::new_rgba8(32, 32);
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        let stripped = strip_and_reencode_image(&out.into_inner()).unwrap();
        assert_eq!(sniff::sniff(&stripped), MediaKind::Png);
    }

    #[test]
    fn profile_jpeg_fits_wire_cap() {
        // 1024x768 noise-ish gradient: big enough to need the ladder.
        let mut img = image::RgbImage::new(1024, 768);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgb([(x % 251) as u8, (y % 239) as u8, ((x * y) % 233) as u8]);
        }
        let mut buf = Cursor::new(Vec::new());
        DynamicImage::ImageRgb8(img)
            .write_to(&mut buf, image::ImageFormat::Png)
            .unwrap();
        let jpeg = prepare_profile_jpeg(&buf.into_inner()).unwrap();
        assert_eq!(sniff::sniff(&jpeg), MediaKind::Jpeg);
        assert!(jpeg.len() <= schat_wire_types::profile::MAX_JPEG);
        let decoded = decode_bounded(&jpeg).unwrap();
        assert!(decoded.width().max(decoded.height()) <= PROFILE_EDGES[0]);
    }

    #[test]
    fn crop_bounds_checked() {
        let img = DynamicImage::new_rgb8(100, 80);
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        let bytes = out.into_inner();
        let cropped = crop_image(&bytes, 10, 10, 40, 40).unwrap();
        let decoded = decode_bounded(&cropped).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (40, 40));
        assert!(crop_image(&bytes, 90, 0, 20, 20).is_err());
        assert!(crop_image(&bytes, 0, 0, 0, 10).is_err());
    }

    #[test]
    fn rejects_non_images_and_oversize() {
        assert!(strip_and_reencode_image(b"plain text").is_err());
        let huge = vec![0u8; MAX_INPUT_BYTES + 1];
        assert!(matches!(
            strip_and_reencode_image(&huge),
            Err(MediaError::TooLarge { .. })
        ));
    }
}
