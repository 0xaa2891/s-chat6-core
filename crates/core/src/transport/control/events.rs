//! Asynchronous control-port events (`650 ...`). Only the three event
//! types s//chat6 subscribes to are structured; anything else is preserved
//! raw.

/// A parsed asynchronous event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TorEvent {
    HsDesc {
        action: String,
        args: Vec<String>,
    },
    StatusGeneral {
        severity: String,
        action: String,
        args: Vec<String>,
    },
    Circ {
        action: String,
        args: Vec<String>,
    },
    Unknown {
        raw: String,
    },
}

pub fn parse_event(line: &str) -> TorEvent {
    let body = line.strip_prefix("650 ").unwrap_or(line);
    let mut parts = body.split(' ');
    let head = parts.next().unwrap_or_default();
    let rest: Vec<String> = parts.map(|s| s.to_string()).collect();
    match head {
        "HS_DESC" => TorEvent::HsDesc {
            action: rest.first().cloned().unwrap_or_default(),
            args: rest.into_iter().skip(1).collect(),
        },
        "STATUS_GENERAL" => TorEvent::StatusGeneral {
            severity: rest.first().cloned().unwrap_or_default(),
            action: rest.get(1).cloned().unwrap_or_default(),
            args: rest.into_iter().skip(2).collect(),
        },
        "CIRC" => TorEvent::Circ {
            action: rest.get(1).cloned().unwrap_or_default(),
            args: rest.into_iter().skip(2).collect(),
        },
        _ => TorEvent::Unknown {
            raw: body.to_string(),
        },
    }
}
