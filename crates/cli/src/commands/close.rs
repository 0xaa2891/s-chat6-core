//! `schat-cli close`: the contact-close flow — DELETE_ALL +
//! CONTACT_CLOSE go out, the local burn completes once they settle
//! (the daemon's sweeper finishes it).

use crate::args::{usage_msg, Args};
use crate::util::{finish, start_engine_or_report};

pub async fn run(a: &Args) -> i32 {
    let rel = a
        .rel
        .clone()
        .unwrap_or_else(|| usage_msg("needs --rel REL_ID"));
    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };
    let result = engine
        .close_contact(&rel)
        .await
        .map(|()| format!("closing {rel}: history erased, close frames queued"))
        .map_err(|e| e.to_string());
    finish(&transport, result).await
}
