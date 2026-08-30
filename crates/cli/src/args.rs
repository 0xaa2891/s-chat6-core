//! Command-line argument parsing for `schat-cli` (hand-rolled; no clap
//! dependency in the CLI crate).

use std::path::PathBuf;
use std::process;

use schat_core::transport::status::OnionMode;

pub struct Args {
    pub cmd: String,
    pub data_dir: PathBuf,
    pub chutney_nodes: Option<PathBuf>,
    pub to: Option<String>,
    pub text: Option<String>,
    pub alert: bool,
    pub once: bool,
    pub flap: bool,
    pub restricted: bool,
    pub mode: OnionMode,
    pub offer: bool,
    pub accept: Option<String>,
    pub code: Option<String>,
    pub accept_request: bool,
    pub requests: bool,
    pub abort: bool,
    pub out: Option<String>,
    pub rel: Option<String>,
    pub msg_id: Option<String>,
    // Feature flags.
    pub file: Option<String>,
    pub caption: Option<String>,
    pub view_once: bool,
    pub name: Option<String>,
    pub jpeg: Option<String>,
    pub ttl: Option<u32>,
    pub screenshot: Option<bool>,
    pub attach_download: Option<bool>,
    pub cap: Option<String>,
    pub on: bool,
    pub off: bool,
    pub dnd: bool,
    pub pack: Option<String>,
    pub item: Option<u16>,
    pub pk: Option<String>,
    pub title: Option<String>,
    pub files: Option<String>,
    pub kind: Option<String>,
    pub visibility: Option<String>,
    pub remove: bool,
    pub list: bool,
    pub show: bool,
    pub broadcast: bool,
    pub request: bool,
    pub propose: bool,
    pub decline: bool,
    pub set: bool,
    pub create: bool,
    pub send: bool,
    pub fetch: bool,
    pub accept_rules: bool,
    // Vault.
    pub dek_file: Option<PathBuf>,
}

pub fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage(2));
    let mut a = Args {
        cmd,
        data_dir: PathBuf::from("./schat-data"),
        chutney_nodes: None,
        to: None,
        text: None,
        alert: false,
        once: false,
        flap: false,
        restricted: false,
        mode: OnionMode::Normal,
        offer: false,
        accept: None,
        code: None,
        accept_request: false,
        requests: false,
        abort: false,
        out: None,
        rel: None,
        msg_id: None,
        file: None,
        caption: None,
        view_once: false,
        name: None,
        jpeg: None,
        ttl: None,
        screenshot: None,
        attach_download: None,
        cap: None,
        on: false,
        off: false,
        dnd: false,
        pack: None,
        item: None,
        pk: None,
        title: None,
        files: None,
        kind: None,
        visibility: None,
        remove: false,
        list: false,
        show: false,
        broadcast: false,
        request: false,
        propose: false,
        decline: false,
        set: false,
        create: false,
        send: false,
        fetch: false,
        accept_rules: false,
        dek_file: None,
    };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| -> String {
            args.next()
                .unwrap_or_else(|| usage_msg(&format!("{name} needs a value")))
        };
        match arg.as_str() {
            "--data-dir" => a.data_dir = PathBuf::from(value("--data-dir")),
            "--chutney-nodes" => a.chutney_nodes = Some(PathBuf::from(value("--chutney-nodes"))),
            "--to" => a.to = Some(value("--to")),
            "--text" => a.text = Some(value("--text")),
            "--alert" => a.alert = true,
            "--once" => a.once = true,
            "--simulate-network-flap" => a.flap = true,
            "--restricted" => a.restricted = true,
            "--mode" => a.mode = OnionMode::parse(&value("--mode")),
            "--offer" => a.offer = true,
            "--accept" => a.accept = Some(value("--accept")),
            "--code" => a.code = Some(value("--code")),
            "--accept-request" => a.accept_request = true,
            "--requests" => a.requests = true,
            "--abort" => a.abort = true,
            "--out" => a.out = Some(value("--out")),
            "--rel" => a.rel = Some(value("--rel")),
            "--msg-id" => a.msg_id = Some(value("--msg-id")),
            "--file" => a.file = Some(value("--file")),
            "--caption" => a.caption = Some(value("--caption")),
            "--view-once" => a.view_once = true,
            "--name" => a.name = Some(value("--name")),
            "--jpeg" => a.jpeg = Some(value("--jpeg")),
            "--ttl" => {
                a.ttl = Some(
                    value("--ttl")
                        .parse()
                        .unwrap_or_else(|_| usage_msg("--ttl needs seconds (0 = never)")),
                )
            }
            "--screenshot" => a.screenshot = Some(parse_on_off(&value("--screenshot"))),
            "--attach-download" => {
                a.attach_download = Some(parse_on_off(&value("--attach-download")))
            }
            "--cap" => a.cap = Some(value("--cap")),
            "--on" => a.on = true,
            "--off" => a.off = true,
            "--dnd" => a.dnd = true,
            "--pack" => a.pack = Some(value("--pack")),
            "--item" => {
                a.item = Some(
                    value("--item")
                        .parse()
                        .unwrap_or_else(|_| usage_msg("--item needs a number")),
                )
            }
            "--pk" => a.pk = Some(value("--pk")),
            "--title" => a.title = Some(value("--title")),
            "--files" => a.files = Some(value("--files")),
            "--kind" => a.kind = Some(value("--kind")),
            "--visibility" => a.visibility = Some(value("--visibility")),
            "--remove" => a.remove = true,
            "--list" => a.list = true,
            "--show" => a.show = true,
            "--broadcast" => a.broadcast = true,
            "--request" => a.request = true,
            "--propose" => a.propose = true,
            "--decline" => a.decline = true,
            "--set" => a.set = true,
            "--create" => a.create = true,
            "--send" => a.send = true,
            "--fetch" => a.fetch = true,
            "--accept-rules" => a.accept_rules = true,
            "--dek-file" => a.dek_file = Some(PathBuf::from(value("--dek-file"))),
            other => usage_msg(&format!("unknown flag {other}")),
        }
    }
    a
}

pub fn usage_msg(msg: &str) -> ! {
    eprintln!("error: {msg}");
    usage(2)
}

pub fn parse_on_off(v: &str) -> bool {
    match v {
        "on" | "true" | "1" | "yes" => true,
        "off" | "false" | "0" | "no" => false,
        _ => usage_msg("expected on|off"),
    }
}

/// Hex-decode a fixed-size id (`--pack`, `--pk`, msg ids).
pub fn hex_id<const N: usize>(s: &str) -> [u8; N] {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|_| usage_msg("invalid hex id"));
    bytes
        .try_into()
        .unwrap_or_else(|_| usage_msg("hex id has the wrong length"))
}

pub fn usage(code: i32) -> ! {
    eprintln!(
        "usage:\n  \
         schat-cli ping\n  \
         schat-cli daemon --data-dir DIR [--chutney-nodes DIR] [--simulate-network-flap] \\\n         \
             [--mode MODE] [--restricted]\n  \
         schat-cli send --data-dir DIR (--to ONION | --rel REL_ID) [--chutney-nodes DIR] \\\n         \
             [--text TEXT] [--msg-id ID] [--alert]\n  \
         schat-cli status --data-dir DIR [--chutney-nodes DIR] [--once]\n  \
         schat-cli pair --data-dir DIR (--offer [--out FILE] | --accept FILE | --code CODE | \\\n         \
             --accept-request [--rel REL_ID] | --requests | --abort)\n  \
         schat-cli edit --data-dir DIR --rel REL_ID --msg-id ID --text TEXT\n  \
         schat-cli delete --data-dir DIR --rel REL_ID --msg-id ID\n  \
         schat-cli read --data-dir DIR --rel REL_ID --msg-id ID\n  \
         schat-cli typing --data-dir DIR --rel REL_ID (--on | --off)\n  \
         schat-cli presence --data-dir DIR (--on | --off) [--dnd]\n  \
         schat-cli thread --data-dir DIR --rel REL_ID\n  \
         schat-cli attach --data-dir DIR --rel REL_ID --file PATH [--caption TEXT] [--view-once]\n  \
         schat-cli attach-save --data-dir DIR --msg-id HEAD_ID --out FILE\n  \
         schat-cli profile --data-dir DIR [--set --name NAME [--jpeg FILE] | --show [--rel REL_ID] | \\\n         \
             --broadcast | --request --rel REL_ID]\n  \
         schat-cli policy --data-dir DIR --rel REL_ID [--show | --propose --ttl SEC \\\n         \
             --screenshot on|off --attach-download on|off | --accept-rules | --decline | \\\n         \
             --cap NAME on|off]\n  \
         schat-cli sticker --data-dir DIR [--create --title T [--kind emoji|sticker] \\\n         \
             [--visibility public|private] --files A,B,.. | --list | \\\n         \
             --send --rel REL_ID --pack PACK_ID --item N | \\\n         \
             --fetch --rel REL_ID --pack PACK_ID --pk PACK_PK | --remove --pack PACK_ID]\n  \
         schat-cli close --data-dir DIR --rel REL_ID\n  \
         schat-cli lock --data-dir DIR\n  \
         schat-cli unlock --data-dir DIR [--dek-file PATH]\n  \
         schat-cli panic-wipe --data-dir DIR\n  \
         schat-cli sweep-expired --data-dir DIR\n  \
         schat-cli media-sniff --file PATH\n  \
         schat-cli media-strip --file PATH --out FILE\n  \
         schat-cli media-prepare-sticker --file PATH [--kind sticker|emoji] [--out FILE]"
    );
    process::exit(code)
}
