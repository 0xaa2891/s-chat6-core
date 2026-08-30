//! Magic-byte media sniffing. Pure byte
//! inspection — no decode, no allocation beyond the caller's buffer.

/// What the first bytes of a blob claim to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    Jpeg,
    Png,
    Webp,
    Heic,
    Mp4,
    Webm,
    Gif,
    /// Unknown or disallowed — fail closed.
    Reject,
}

impl MediaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MediaKind::Jpeg => "jpeg",
            MediaKind::Png => "png",
            MediaKind::Webp => "webp",
            MediaKind::Heic => "heic",
            MediaKind::Mp4 => "mp4",
            MediaKind::Webm => "webm",
            MediaKind::Gif => "gif",
            MediaKind::Reject => "reject",
        }
    }
}

/// Sniff the head of a blob (32 bytes is plenty; more is fine).
pub fn sniff(head: &[u8]) -> MediaKind {
    if head.len() >= 3 && head[0] == 0xff && head[1] == 0xd8 && head[2] == 0xff {
        return MediaKind::Jpeg;
    }
    if head.len() >= 6 && (&head[..6] == b"GIF87a" || &head[..6] == b"GIF89a") {
        return MediaKind::Gif;
    }
    if head.len() >= 8 && head[0] == 0x89 && head[1] == 0x50 && head[2] == 0x4e && head[3] == 0x47 {
        return MediaKind::Png;
    }
    if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return MediaKind::Webp;
    }
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        let brand = String::from_utf8_lossy(&head[8..12.min(head.len())]);
        return if brand.starts_with("heic")
            || brand.starts_with("mif1")
            || brand.starts_with("msf1")
            || brand.starts_with("heif")
        {
            MediaKind::Heic
        } else {
            MediaKind::Mp4
        };
    }
    if head.len() >= 4 && head[0] == 0x1a && head[1] == 0x45 && head[2] == 0xdf && head[3] == 0xa3 {
        return MediaKind::Webm;
    }
    MediaKind::Reject
}

pub fn is_image(kind: MediaKind) -> bool {
    matches!(
        kind,
        MediaKind::Jpeg | MediaKind::Png | MediaKind::Webp | MediaKind::Heic
    )
}

/// Sticker/emoji items: static PNG/WebP or (animated) GIF. Never JPEG
/// (EXIF).
pub fn is_sticker_image(kind: MediaKind) -> bool {
    matches!(kind, MediaKind::Png | MediaKind::Webp | MediaKind::Gif)
}

pub fn is_video(kind: MediaKind) -> bool {
    matches!(kind, MediaKind::Mp4 | MediaKind::Webm)
}

/// VP8X animation flag (animated WebP stickers from Telegram etc.).
pub fn is_animated_webp(bytes: &[u8]) -> bool {
    if sniff(bytes) != MediaKind::Webp || bytes.len() < 21 {
        return false;
    }
    if &bytes[12..16] != b"VP8X" {
        return false;
    }
    bytes[20] & 0x02 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes() {
        assert_eq!(sniff(&[0xff, 0xd8, 0xff, 0xe0]), MediaKind::Jpeg);
        assert_eq!(sniff(b"GIF89a...."), MediaKind::Gif);
        assert_eq!(sniff(b"GIF87a...."), MediaKind::Gif);
        assert_eq!(sniff(&[0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0]), MediaKind::Png);
        assert_eq!(sniff(b"RIFFxxxxWEBP"), MediaKind::Webp);
        assert_eq!(sniff(b"....ftypheic"), MediaKind::Heic);
        assert_eq!(sniff(b"....ftypmp42"), MediaKind::Mp4);
        assert_eq!(sniff(&[0x1a, 0x45, 0xdf, 0xa3]), MediaKind::Webm);
        assert_eq!(sniff(b"plain text"), MediaKind::Reject);
        assert_eq!(sniff(&[]), MediaKind::Reject);
        assert!(is_sticker_image(MediaKind::Gif));
        assert!(!is_sticker_image(MediaKind::Jpeg));
        assert!(is_video(MediaKind::Webm));
    }

    #[test]
    fn animated_webp_flag() {
        let mut bytes = b"RIFFxxxxWEBPVP8X".to_vec();
        bytes.extend_from_slice(&[0u8; 4]); // chunk size
        bytes.push(0x02); // animation flag at offset 20
        assert!(is_animated_webp(&bytes));
        bytes[20] = 0;
        assert!(!is_animated_webp(&bytes));
    }
}
