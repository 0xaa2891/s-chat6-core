//! `schat-cli status`: print the transport status once or follow it.

use schat_core::transport::Transport;

use crate::args::Args;
use crate::util::{make_daemon, render_status};

pub async fn run(a: &Args) -> i32 {
    let transport = Transport::new(&a.data_dir);
    transport
        .set_daemon(make_daemon(&a.data_dir, a.chutney_nodes.as_ref()))
        .await;
    if let Err(e) = transport.start().await {
        eprintln!("error: start: {e}");
        return 1;
    }
    if a.once {
        println!("{}", render_status(&transport.status()));
        transport.stop().await;
        return 0;
    }
    let mut rx = transport.subscribe();
    loop {
        println!("{}", render_status(&rx.borrow()));
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() { break; }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    transport.stop().await;
    0
}
