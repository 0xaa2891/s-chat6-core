//! Control-port reply parsing (control-spec.txt): `CCC[ -+]` lines, `+`
//! data blocks terminated by a lone `.`, reply complete at the first
//! space-separated line.

use crate::transport::error::TransportError;

/// A parsed control-port reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    /// `KEY=VALUE` payload lines (without the code prefix), in order.
    pub lines: Vec<String>,
    /// Data blocks from `250+KEY=` lines: (key, raw data).
    pub data: Vec<(String, String)>,
}

impl Reply {
    /// Look up `KEY` in single-line `KEY=VALUE` replies and data blocks.
    pub fn get(&self, key: &str) -> Option<&str> {
        let prefix = format!("{key}=");
        for line in &self.lines {
            if let Some(v) = line.strip_prefix(&prefix) {
                return Some(v);
            }
        }
        self.data
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn is_ok(&self) -> bool {
        self.code == 250
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LineKind {
    /// `CCC ` — final line of the reply.
    End,
    /// `CCC-` — more lines follow.
    More,
    /// `CCC+` — a data block follows, terminated by a lone `.`.
    Data,
}

/// Incremental reply parser. Feed raw lines (without CRLF); returns the
/// completed [`Reply`] when the final line arrives.
#[derive(Default)]
pub struct ReplyParser {
    code: Option<u16>,
    lines: Vec<String>,
    data: Vec<(String, String)>,
    /// Key of the in-progress `+` data block, if any.
    data_key: Option<String>,
    data_buf: String,
}

impl ReplyParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one line. Returns `Some(reply)` when the reply is complete.
    /// `Err` on protocol garbage (caller should close the connection).
    pub fn feed(&mut self, line: &str) -> Result<Option<Reply>, TransportError> {
        if let Some(key) = self.data_key.take() {
            if line == "." {
                self.data.push((key, std::mem::take(&mut self.data_buf)));
            } else {
                if !self.data_buf.is_empty() {
                    self.data_buf.push('\n');
                }
                self.data_buf.push_str(line);
                self.data_key = Some(key);
            }
            return Ok(None);
        }

        let bytes = line.as_bytes();
        if bytes.len() < 4 || !bytes[..3].iter().all(|b| b.is_ascii_digit()) {
            return Err(TransportError::Control(format!(
                "malformed reply line: {line:?}"
            )));
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| TransportError::Control(format!("bad reply code in {line:?}")))?;
        let kind = match line.as_bytes()[3] {
            b' ' => LineKind::End,
            b'-' => LineKind::More,
            b'+' => LineKind::Data,
            other => {
                return Err(TransportError::Control(format!(
                    "bad reply separator 0x{other:02x}"
                )))
            }
        };
        match self.code {
            None => self.code = Some(code),
            Some(c) if c == code => {}
            Some(c) => {
                return Err(TransportError::Control(format!(
                    "reply code changed mid-reply: {c} then {code}"
                )))
            }
        }

        let text = &line[4..];
        if kind == LineKind::Data {
            let key = text.split('=').next().unwrap_or_default().to_string();
            // Any inline value after `KEY=` is the first data line.
            if let Some((_, inline)) = text.split_once('=') {
                if !inline.is_empty() {
                    self.data_buf.push_str(inline);
                }
            }
            self.data_key = Some(key);
            return Ok(None);
        }
        self.lines.push(text.to_string());

        if kind == LineKind::End {
            let reply = Reply {
                code: self.code.take().expect("code set"),
                lines: std::mem::take(&mut self.lines),
                data: std::mem::take(&mut self.data),
            };
            return Ok(Some(reply));
        }
        Ok(None)
    }
}
