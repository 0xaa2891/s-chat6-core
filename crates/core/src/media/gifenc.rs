//! GIF89a encode via the `gif` crate. Input is raw RGBA frames;
//! quantization to the 256-color palette is the crate's job.

use super::MediaError;

/// One raw frame: tightly packed RGBA8, `width * height * 4` bytes.
/// `delay_cs` is the frame delay in centiseconds (GIF's native unit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GifFrame {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub delay_cs: u16,
}

impl GifFrame {
    fn validate(&self) -> Result<(), MediaError> {
        let want = self.width as usize * self.height as usize * 4;
        if self.width == 0 || self.height == 0 || self.rgba.len() != want {
            return Err(MediaError::Encode(format!(
                "frame {}x{} wants {want} rgba bytes, got {}",
                self.width,
                self.height,
                self.rgba.len()
            )));
        }
        Ok(())
    }
}

/// Encode frames as an infinitely looping GIF89a. All frames share the
/// first frame's dimensions (the GIF logical screen).
pub fn encode_gif(frames: &[GifFrame]) -> Result<Vec<u8>, MediaError> {
    let Some(first) = frames.first() else {
        return Err(MediaError::Encode("no frames".into()));
    };
    first.validate()?;
    let (w, h) = (first.width, first.height);
    if w > u16::MAX as u32 || h > u16::MAX as u32 {
        return Err(MediaError::Encode(format!("gif dims {w}x{h} exceed u16")));
    }
    let mut out = Vec::new();
    {
        let mut encoder = gif::Encoder::new(&mut out, w as u16, h as u16, &[])
            .map_err(|e| MediaError::Encode(e.to_string()))?;
        encoder
            .set_repeat(gif::Repeat::Infinite)
            .map_err(|e| MediaError::Encode(e.to_string()))?;
        for f in frames {
            f.validate()?;
            if f.width != w || f.height != h {
                return Err(MediaError::Encode(format!(
                    "frame {}x{} does not match logical screen {w}x{h}",
                    f.width, f.height
                )));
            }
            let mut rgba = f.rgba.clone();
            let mut frame = gif::Frame::from_rgba_speed(w as u16, h as u16, &mut rgba, 10);
            frame.delay = f.delay_cs;
            encoder
                .write_frame(&frame)
                .map_err(|e| MediaError::Encode(e.to_string()))?;
        }
    }
    if super::sniff::sniff(&out) != super::sniff::MediaKind::Gif {
        return Err(MediaError::Encode("encoder output failed sniff".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::sniff::{sniff, MediaKind};

    fn solid(w: u32, h: u32, rgb: [u8; 3], delay_cs: u16) -> GifFrame {
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for _ in 0..w * h {
            rgba.extend_from_slice(&rgb);
            rgba.push(255);
        }
        GifFrame {
            rgba,
            width: w,
            height: h,
            delay_cs,
        }
    }

    #[test]
    fn encode_roundtrip_decodes() {
        let frames = vec![
            solid(16, 16, [255, 0, 0], 10),
            solid(16, 16, [0, 0, 255], 10),
        ];
        let gif = encode_gif(&frames).unwrap();
        assert_eq!(sniff(&gif), MediaKind::Gif);
        // The `image` crate reads it back: two frames, right size.
        let decoder = image::codecs::gif::GifDecoder::new(std::io::Cursor::new(&gif)).unwrap();
        use image::AnimationDecoder;
        let decoded: Vec<_> = decoder.into_frames().collect_frames().unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].buffer().width(), 16);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(encode_gif(&[]).is_err());
        let mut bad = solid(8, 8, [0, 0, 0], 10);
        bad.rgba.truncate(10);
        assert!(encode_gif(&[bad]).is_err());
        // Mismatched dims across frames.
        assert!(encode_gif(&[solid(8, 8, [0, 0, 0], 10), solid(4, 4, [0, 0, 0], 10)]).is_err());
    }
}
