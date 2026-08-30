//! The full feature matrix between **ten** headless
//! instances (five disjoint pairs) over real onion services on the
//! Chutney testnet — text, edit, delete, read receipts, typing,
//! presence, attachments (chunked), profiles, chat policy, stickers,
//! and contact close, plus the no-cross-talk invariant (I4/I9).
//!
//! Skips unless `SCHAT_CHUTNEY_NODES` points at a running Chutney nodes
//! dir (see `tools/testnet/run-testnet.sh`) and a `tor` binary is
//! available.

use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use schat_core::engine::{Engine, EngineEvent};
use schat_core::pairing::{self, Ingest};
use schat_core::store::messages::MessagesRepository;
use schat_core::store::Db;
use schat_core::transport::inbound::InboundDrop;
use schat_test_harness::{chutney_nodes, tor_binary, TestInstance};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::TryRecvError;

const ONLINE_TIMEOUT: Duration = Duration::from_secs(240);
const PAIR_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(240);
const PUMP_INTERVAL: Duration = Duration::from_secs(2);

/// A real 64x64 PNG, generated at test time — valid sticker input.
fn sticker_png() -> Vec<u8> {
    use image::ImageEncoder;
    let img = image::RgbImage::from_fn(64, 64, |x, y| {
        image::Rgb([(x * 4) as u8, (y * 4) as u8, 128])
    });
    let mut buf = Vec::new();
    image::codecs::png::PngEncoder::new(&mut buf)
        .write_image(img.as_raw(), 64, 64, image::ExtendedColorType::Rgb8)
        .expect("encode png");
    buf
}

macro_rules! require_testnet {
    () => {
        match chutney_nodes() {
            Some(dir) if tor_binary().is_some() => dir,
            _ => {
                eprintln!(
                    "skip: set SCHAT_CHUTNEY_NODES to a running Chutney nodes dir \
                     (tools/testnet/run-testnet.sh s-chat6-min)"
                );
                return;
            }
        }
    };
}

/// One instance: transport + engine + its event log.
struct Node {
    name: String,
    inst: TestInstance,
    engine: Engine,
    drops: broadcast::Receiver<InboundDrop>,
    events: Vec<EngineEvent>,
    /// rel_ids that arrived as message requests (inviter's bucket).
    requests: Vec<String>,
}

impl Node {
    async fn new(name: &str, nodes: &Path) -> Self {
        let inst = TestInstance::new(name, nodes).await.expect("instance");
        let db = Db::open_in_memory().expect("db");
        let engine = Engine::new(db, inst.transport.clone());
        let drops = inst.drops();
        Self {
            name: name.to_string(),
            inst,
            engine,
            drops,
            events: Vec::new(),
            requests: Vec::new(),
        }
    }

    fn rel_state(&self, rel_id: &str) -> Option<String> {
        pairing::load_relationship(self.engine.db.conn(), rel_id)
            .ok()
            .flatten()
            .map(|r| r.state)
    }

    fn has_event(&self, f: impl Fn(&EngineEvent) -> bool) -> bool {
        self.events.iter().any(f)
    }
}

async fn dispatch(node: &mut Node, rel_id: &str, plaintext: &[u8]) {
    match node.engine.handle_plaintext(rel_id, plaintext).await {
        Ok(events) => node.events.extend(events),
        Err(e) => eprintln!("{} handle: {e}", node.name),
    }
}

/// One upkeep round for every node: drain outbox, sweep, ingest all
/// pending drops into the engine.
async fn pump(nodes: &mut [Node]) {
    for node in nodes.iter_mut() {
        if let Err(e) = node.engine.drain_outbox().await {
            eprintln!("{} drain: {e}", node.name);
        }
        match node.engine.sweep().await {
            Ok(events) => node.events.extend(events),
            Err(e) => eprintln!("{} sweep: {e}", node.name),
        }
        loop {
            match node.drops.try_recv() {
                Ok(drop) => {
                    let outcome = pairing::ingest_frame(
                        node.engine.db.conn(),
                        &node.engine.transport,
                        &drop.service_id,
                        drop.frame.intro.as_deref(),
                        &drop.frame.frame,
                        SystemTime::now(),
                    )
                    .await;
                    match outcome {
                        Ok(Ingest::RequestReceived {
                            rel_id, plaintext, ..
                        }) => {
                            if !node.requests.contains(&rel_id) {
                                node.requests.push(rel_id.clone());
                            }
                            dispatch(node, &rel_id, &plaintext).await;
                        }
                        Ok(Ingest::Message { rel_id, plaintext }) => {
                            dispatch(node, &rel_id, &plaintext).await;
                        }
                        Ok(_) => {}
                        Err(e) => eprintln!("{} ingest: {e}", node.name),
                    }
                    node.inst.transport.note_inbound_drain();
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
                Err(TryRecvError::Lagged(_)) => continue,
            }
        }
    }
}

async fn run_until(
    nodes: &mut [Node],
    timeout: Duration,
    what: &str,
    pred: impl Fn(&[Node]) -> bool,
) {
    let deadline = Instant::now() + timeout;
    loop {
        pump(nodes).await;
        if pred(nodes) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(PUMP_INTERVAL).await;
    }
}

/// Deterministic 40 KiB payload — forces the chunked attachment path.
fn attachment_bytes() -> Vec<u8> {
    (0..40 * 1024u32).map(|i| (i % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn feature_matrix_ten_instances() {
    let nodes_dir = require_testnet!();

    // -- ten instances online ------------------------------------------
    let mut nodes: Vec<Node> = Vec::new();
    for i in 0..10 {
        nodes.push(Node::new(&format!("n{i}"), &nodes_dir).await);
    }
    for node in &nodes {
        assert!(
            node.inst.wait_online(ONLINE_TIMEOUT).await,
            "{} online",
            node.name
        );
    }
    eprintln!("all ten instances online");

    // -- five disjoint pairs --------------------------------------------
    // (0,1) (2,3) (4,5) (6,7) (8,9): even = inviter, odd = accepter.
    let mut rel_ids: Vec<String> = Vec::new();
    for pair in 0..5 {
        let (a, b) = (pair * 2, pair * 2 + 1);
        let now = SystemTime::now();
        let offer = pairing::offer(nodes[a].engine.db.conn(), &nodes[a].engine.transport, now)
            .await
            .expect("offer");
        let accepted = pairing::accept(
            nodes[b].engine.db.conn(),
            &nodes[b].engine.transport,
            &offer.qr_bytes,
            now,
        )
        .await
        .expect("accept");
        nodes[b]
            .engine
            .send_text(&accepted.rel_id, "hi, add me?", None)
            .await
            .expect("intro message");
        rel_ids.push(accepted.rel_id);
    }

    // Every inviter receives the request (intro rode the first frame).
    run_until(&mut nodes, PAIR_TIMEOUT, "requests", |nodes| {
        (0..5).all(|p| nodes[p * 2].requests.contains(&rel_ids[p]))
    })
    .await;
    eprintln!("all five requests landed");

    // Inviters accept (activation burst); accepters' bursts fire on the
    // inviter's first inbound frame.
    for pair in 0..5 {
        nodes[pair * 2]
            .engine
            .accept_request(&rel_ids[pair])
            .await
            .expect("accept request");
    }
    run_until(&mut nodes, PAIR_TIMEOUT, "activation", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2]
                .rel_state(&rel_ids[p])
                .is_some_and(|s| s == "active")
                && nodes[p * 2 + 1]
                    .rel_state(&rel_ids[p])
                    .is_some_and(|s| s == "active")
        })
    })
    .await;
    eprintln!("all five pairs active");

    // -- text + edit + delete + read ------------------------------------
    let mut text_ids: Vec<[u8; 16]> = Vec::new();
    for (pair, rel) in rel_ids.iter().enumerate() {
        let id = nodes[pair * 2]
            .engine
            .send_text(rel, "hello over tor", None)
            .await
            .expect("send text");
        text_ids.push(id);
    }
    run_until(&mut nodes, STEP_TIMEOUT, "text", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2 + 1].has_event(
                |e| matches!(e, EngineEvent::Message { msg_id, .. } if *msg_id == text_ids[p]),
            )
        })
    })
    .await;
    for pair in 0..5 {
        let rows = nodes[pair * 2 + 1]
            .engine
            .db
            .thread_visible(&rel_ids[pair], 10, None)
            .expect("thread");
        assert!(
            rows.iter().any(|r| r.payload == b"hello over tor"),
            "pair {pair}: body in the rendered thread"
        );
    }
    eprintln!("text delivered on all pairs");

    // Edits.
    for (pair, rel) in rel_ids.iter().enumerate() {
        nodes[pair * 2]
            .engine
            .send_edit(rel, &text_ids[pair], "hello, edited")
            .await
            .expect("edit");
    }
    run_until(&mut nodes, STEP_TIMEOUT, "edits", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2 + 1].has_event(
                |e| matches!(e, EngineEvent::Edited { msg_id, .. } if *msg_id == text_ids[p]),
            )
        })
    })
    .await;
    eprintln!("edits landed on all pairs");

    // Read receipts back to the sender.
    for (pair, rel) in rel_ids.iter().enumerate() {
        nodes[pair * 2 + 1]
            .engine
            .send_read(rel, &text_ids[pair])
            .await
            .expect("read");
    }
    run_until(&mut nodes, STEP_TIMEOUT, "read receipts", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2].has_event(
                |e| matches!(e, EngineEvent::Read { msg_id, .. } if *msg_id == text_ids[p]),
            )
        })
    })
    .await;
    eprintln!("read receipts landed on all pairs");

    // Deletes (after the read, so the row exists on both sides).
    for (pair, rel) in rel_ids.iter().enumerate() {
        nodes[pair * 2]
            .engine
            .send_delete(rel, &text_ids[pair])
            .await
            .expect("delete");
    }
    run_until(&mut nodes, STEP_TIMEOUT, "deletes", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2 + 1].has_event(
                |e| matches!(e, EngineEvent::Deleted { msg_id, .. } if *msg_id == text_ids[p]),
            )
        })
    })
    .await;
    eprintln!("deletes landed on all pairs");

    // -- typing + presence (ephemeral) ----------------------------------
    for (pair, rel) in rel_ids.iter().enumerate() {
        nodes[pair * 2 + 1]
            .engine
            .send_typing(rel, true)
            .await
            .expect("typing");
        nodes[pair * 2]
            .engine
            .send_presence(rel, true, false)
            .await
            .expect("presence");
    }
    run_until(&mut nodes, STEP_TIMEOUT, "typing+presence", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2].has_event(|e| matches!(e, EngineEvent::Typing { typing: true, .. }))
                && nodes[p * 2 + 1]
                    .has_event(|e| matches!(e, EngineEvent::Presence { in_app: true, .. }))
        })
    })
    .await;
    eprintln!("typing + presence landed on all pairs");

    // -- attachments (chunked, 40 KiB) ----------------------------------
    let payload = attachment_bytes();
    // Video class: byte-exact pass-through plumbing (still-image sends
    // are stripped/re-encoded by the media hygiene gate — covered by
    // core's media hygiene tests).
    let class = schat_core::attach::class_for_mime("video/mp4");
    let mut head_ids: Vec<[u8; 16]> = Vec::new();
    for (pair, rel) in rel_ids.iter().enumerate() {
        let head = nodes[pair * 2]
            .engine
            .send_attachment(
                rel,
                &schat_core::attach::AttachmentSpec {
                    media_class: class,
                    mime_hint: "video/mp4".into(),
                    orig_ext: "mp4".into(),
                    bytes: payload.clone(),
                    caption: "file".into(),
                    view_once: false,
                },
            )
            .await
            .expect("send attachment");
        head_ids.push(head);
    }
    run_until(&mut nodes, STEP_TIMEOUT, "attachments", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2 + 1].has_event(|e| matches!(e, EngineEvent::AttachmentComplete { head_id, .. } if *head_id == head_ids[p]))
        })
    })
    .await;
    for pair in 0..5 {
        let got = nodes[pair * 2 + 1]
            .engine
            .attachment_bytes(&head_ids[pair])
            .expect("bytes")
            .expect("complete");
        assert_eq!(got, payload, "pair {pair}: reassembled bytes match");
    }
    eprintln!("attachments reassembled on all pairs");

    // -- profiles ---------------------------------------------------------
    for (pair, rel) in rel_ids.iter().enumerate() {
        schat_core::profile::set_our_profile(
            &nodes[pair * 2].engine.db,
            &format!("user-{pair}"),
            &[],
        )
        .expect("set profile");
        nodes[pair * 2]
            .engine
            .send_profile(rel)
            .await
            .expect("send profile");
    }
    run_until(&mut nodes, STEP_TIMEOUT, "profiles", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2 + 1].has_event(|e| matches!(e, EngineEvent::ProfileUpdated { .. }))
        })
    })
    .await;
    eprintln!("profiles landed on all pairs");

    // -- chat policy: propose → accept ------------------------------------
    for (pair, rel) in rel_ids.iter().enumerate() {
        nodes[pair * 2]
            .engine
            .propose_rules(rel, 3600, true, true)
            .await
            .expect("propose");
    }
    run_until(&mut nodes, STEP_TIMEOUT, "proposals", |nodes| {
        (0..5)
            .all(|p| nodes[p * 2 + 1].has_event(|e| matches!(e, EngineEvent::PolicyChanged { .. })))
    })
    .await;
    for (pair, rel) in rel_ids.iter().enumerate() {
        nodes[pair * 2 + 1]
            .engine
            .accept_rules(rel)
            .await
            .expect("accept rules");
    }
    run_until(&mut nodes, STEP_TIMEOUT, "accepts", |nodes| {
        (0..5).all(|p| {
            schat_core::policy::load_policy(nodes[p * 2].engine.db.conn(), &rel_ids[p])
                .is_ok_and(|s| s.ttl_sec == 3600)
        })
    })
    .await;
    eprintln!("policy agreed (ttl=3600) on all pairs");

    // -- stickers: create a pack, send an item -----------------------------
    use schat_core::wire_types::sticker::limits;
    let png = sticker_png();
    let mut pack_ids: Vec<[u8; 16]> = Vec::new();
    for (pair, rel) in rel_ids.iter().enumerate() {
        let item = schat_core::media::prepare_sticker(&png, limits::KIND_STICKER)
            .expect("prepare sticker");
        let doc_item = schat_core::wire_types::sticker::PackDocItem {
            item_id: 1,
            w: item.width as u16,
            h: item.height as u16,
            sha256: schat_core::util::sha256(&item.bytes),
            bytes: item.bytes,
        };
        let (pack_id, _) = nodes[pair * 2]
            .engine
            .create_pack(
                &format!("pack-{pair}"),
                limits::KIND_STICKER,
                limits::VISIBILITY_PUBLIC,
                1,
                vec![doc_item],
            )
            .expect("create pack");
        nodes[pair * 2]
            .engine
            .send_sticker(rel, &pack_id, 1)
            .await
            .expect("send sticker");
        pack_ids.push(pack_id);
    }
    run_until(&mut nodes, STEP_TIMEOUT, "stickers", |nodes| {
        (0..5).all(|p| {
            nodes[p * 2 + 1].has_event(|e| matches!(e, EngineEvent::Sticker { ready: true, .. }))
        })
    })
    .await;
    eprintln!("stickers landed on all pairs");

    // -- contact close (last pair) -----------------------------------------
    nodes[8]
        .engine
        .close_contact(&rel_ids[4])
        .await
        .expect("close");
    run_until(&mut nodes, STEP_TIMEOUT, "contact close", |nodes| {
        nodes[9].has_event(|e| matches!(e, EngineEvent::ContactClosed { .. }))
            && nodes[8].rel_state(&rel_ids[4]).is_none()
    })
    .await;
    eprintln!("contact close burned pair 4 both sides");

    // -- no cross-talk (I4/I9): every event's rel_id belongs to THIS node --
    for (i, node) in nodes.iter().enumerate() {
        let mine: Vec<&String> = match i % 2 {
            0 => vec![&rel_ids[i / 2]],
            _ => vec![&rel_ids[i / 2]],
        };
        for e in &node.events {
            let rel = match e {
                EngineEvent::Message { rel_id, .. }
                | EngineEvent::Edited { rel_id, .. }
                | EngineEvent::Deleted { rel_id, .. }
                | EngineEvent::Read { rel_id, .. }
                | EngineEvent::Typing { rel_id, .. }
                | EngineEvent::Presence { rel_id, .. }
                | EngineEvent::ProfileUpdated { rel_id }
                | EngineEvent::ProfileRequested { rel_id }
                | EngineEvent::PeerPrefs { rel_id }
                | EngineEvent::Sticker { rel_id, .. }
                | EngineEvent::AttachmentProgress { rel_id, .. }
                | EngineEvent::AttachmentComplete { rel_id, .. }
                | EngineEvent::AttachmentFailed { rel_id, .. }
                | EngineEvent::PolicyChanged { rel_id }
                | EngineEvent::ContactClosed { rel_id }
                | EngineEvent::GapDetected { rel_id }
                | EngineEvent::HistoryCleared { rel_id } => rel_id,
                _ => continue,
            };
            assert!(
                mine.contains(&rel),
                "{} saw event for foreign relationship {rel}",
                node.name
            );
        }
    }
    eprintln!("no cross-talk across the ten instances");

    for node in nodes {
        node.inst.stop().await;
    }
}
