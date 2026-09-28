//! Keep unanswered challenges independently of the discovery cursor. Restarting
//! reconstructs pending work by rewinding the on-chain challenge window.
use perp_core::hash::Digest;
use std::{collections::BTreeSet, future::Future};

const MAX_PENDING: usize = 16_384;
type Page = (Vec<String>, u64, Option<Digest>);

#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Cursor {
    next: Option<u64>,
    anchor: Option<(u64, Digest)>,
    pending: BTreeSet<String>,
}

pub(crate) async fn advance<Start, SF, Check, CF, Fetch, FF, Answer, AF>(
    cursor: &mut Cursor,
    start: Start,
    mut check: Check,
    fetch: Fetch,
    mut answer: Answer,
) -> Result<(), String>
where
    Start: FnOnce() -> SF,
    SF: Future<Output = Result<u64, String>>,
    Check: FnMut(u64, Digest) -> CF,
    CF: Future<Output = Result<bool, String>>,
    Fetch: FnOnce(u64) -> FF,
    FF: Future<Output = Result<Page, String>>,
    Answer: FnMut(String) -> AF,
    AF: Future<Output = Result<(), String>>,
{
    let mut first_error = None;
    let discovery = async {
        if let Some((height, hash)) = cursor.anchor {
            if !check(height, hash).await? {
                // Both providers confirmed a replacement branch. Rewind instead
                // of silently missing events introduced behind the numeric cursor.
                cursor.next = None;
                cursor.anchor = None;
            }
        }
        let from = match cursor.next {
            Some(from) => from,
            None => {
                let from = start().await?;
                cursor.next = Some(from);
                from
            }
        };
        let (hashes, next, anchor) = fetch(from).await?;
        // A reorg may begin between the first check and discovery. Do not
        // replace our old anchor with the new fork and hide events behind it.
        if let Some((height, hash)) = cursor.anchor {
            if !check(height, hash).await? {
                cursor.next = None;
                cursor.anchor = None;
                return Err(
                    "challenge scan: branch changed during discovery; rewind required".to_string(),
                );
            }
        }
        if (anchor.is_none() && (next != from || !hashes.is_empty()))
            || (anchor.is_some() && next <= from)
        {
            return Err("challenge scan: invalid page cursor".to_string());
        }
        let additions: BTreeSet<_> = hashes.into_iter().collect();
        if cursor.pending.union(&additions).count() > MAX_PENDING {
            // Drain existing attempts below; retry this page after space opens.
            return Err("challenge scan: pending capacity reached".to_string());
        }
        cursor.pending.extend(additions);
        cursor.next = Some(next);
        if let Some(hash) = anchor {
            cursor.anchor = Some((next - 1, hash));
        }
        Ok(())
    }
    .await;
    if let Err(error) = discovery {
        first_error = Some(error);
    }
    // Discovery failure must not prevent retrying already discovered work. Each
    // answer callback independently verifies current chain state before sending.
    for hash in cursor.pending.iter().cloned().collect::<Vec<_>>() {
        match answer(hash.clone()).await {
            Ok(()) => {
                cursor.pending.remove(&hash);
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    async fn unchanged(_: u64, _: Digest) -> Result<bool, String> {
        Ok(true)
    }
    async fn never_start() -> Result<u64, String> {
        panic!("must preserve cursor")
    }

    #[tokio::test]
    async fn bootstrap_and_fetch_failures_never_guess_or_advance_cursor() {
        let mut cursor = Cursor::default();
        assert!(advance(
            &mut cursor,
            || async { Err("witness unavailable".into()) },
            unchanged,
            |_| async { panic!("must not scan a guessed head") },
            |_| async { Ok(()) },
        )
        .await
        .is_err());
        assert_eq!(cursor, Cursor::default());
        assert!(advance(
            &mut cursor,
            || async { Ok(550) },
            unchanged,
            |from| async move {
                assert_eq!(from, 550);
                Err("inconsistent logs".into())
            },
            |_| async { Ok(()) },
        )
        .await
        .is_err());
        assert_eq!(cursor.next, Some(550));
        assert!(cursor.pending.is_empty());
    }

    #[tokio::test]
    async fn failed_or_unsettled_answer_remains_pending_without_starving_later_pages() {
        let mut cursor = Cursor {
            next: Some(550),
            ..Default::default()
        };
        let answered = RefCell::new(Vec::new());
        assert!(advance(
            &mut cursor,
            never_start,
            unchanged,
            |_| async { Ok((vec!["first".into(), "second".into()], 600, Some([1; 32]))) },
            |hash| {
                let answered = &answered;
                async move {
                    if hash == "first" {
                        return Err("batch not yet retained or transient send failure".into());
                    }
                    answered.borrow_mut().push(hash);
                    Ok(())
                }
            },
        )
        .await
        .is_err());
        assert_eq!(cursor.next, Some(600));
        assert_eq!(cursor.pending, BTreeSet::from(["first".into()]));
        advance(
            &mut cursor,
            never_start,
            unchanged,
            |from| async move {
                assert_eq!(from, 600);
                Ok((vec!["third".into()], 601, Some([2; 32])))
            },
            |hash| {
                let answered = &answered;
                async move {
                    answered.borrow_mut().push(hash);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert!(cursor.pending.is_empty());
        assert_eq!(*answered.borrow(), vec!["second", "first", "third"]);
    }

    #[tokio::test]
    async fn confirmed_cross_poll_reorg_rewinds_but_rpc_error_preserves_cursor() {
        let mut cursor = Cursor {
            next: Some(600),
            anchor: Some((599, [1; 32])),
            ..Default::default()
        };
        assert!(advance(
            &mut cursor,
            never_start,
            |_, _| async { Err("witness unavailable".into()) },
            |_| async { panic!("must not advance on inconclusive anchor") },
            |_| async { Ok(()) },
        )
        .await
        .is_err());
        assert_eq!(cursor.next, Some(600));
        let answered = RefCell::new(Vec::new());
        advance(
            &mut cursor,
            || async { Ok(400) },
            |height, hash| async move {
                assert_eq!((height, hash), (599, [1; 32]));
                Ok(false)
            },
            |from| async move {
                assert_eq!(from, 400);
                Ok((vec!["replacement-log".into()], 601, Some([2; 32])))
            },
            |hash| {
                let answered = &answered;
                async move {
                    answered.borrow_mut().push(hash);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(*answered.borrow(), vec!["replacement-log"]);
        assert_eq!(cursor.anchor, Some((600, [2; 32])));
    }

    #[tokio::test]
    async fn reorg_between_anchor_check_and_fetch_cannot_replace_cursor_silently() {
        let mut cursor = Cursor {
            next: Some(600),
            anchor: Some((599, [1; 32])),
            ..Default::default()
        };
        let calls = std::cell::Cell::new(0);
        assert!(advance(
            &mut cursor,
            never_start,
            |_, _| {
                let calls = &calls;
                async move {
                    calls.set(calls.get() + 1);
                    Ok(calls.get() == 1)
                }
            },
            |_| async { Ok((vec!["new-fork-later-log".into()], 601, Some([2; 32]))) },
            |_| async { panic!("uncommitted page must be rediscovered after rewind") },
        )
        .await
        .is_err());
        assert_eq!(cursor.next, None);
        assert_eq!(cursor.anchor, None);
        assert_eq!(calls.get(), 2);
        let found = RefCell::new(Vec::new());
        advance(
            &mut cursor,
            || async { Ok(400) },
            unchanged,
            |from| async move {
                assert_eq!(from, 400);
                Ok((
                    vec!["replacement-at-595".into(), "new-fork-later-log".into()],
                    601,
                    Some([2; 32]),
                ))
            },
            |hash| {
                let found = &found;
                async move {
                    found.borrow_mut().push(hash);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert!(found.borrow().contains(&"replacement-at-595".into()));
        assert_eq!(found.borrow().len(), 2);
    }

    #[tokio::test]
    async fn failed_discovery_still_retries_pending_and_terminal_entries_do_not_stall() {
        let mut cursor = Cursor {
            next: Some(600),
            pending: BTreeSet::from(["expired".into(), "live".into()]),
            ..Default::default()
        };
        let attempted = RefCell::new(Vec::new());
        assert!(advance(
            &mut cursor,
            never_start,
            unchanged,
            |_| async { Err("temporary logs error".into()) },
            |hash| {
                let attempted = &attempted;
                async move {
                    // Production checks canonical eligibility; expired/closed is a
                    // successful no-op, while a live challenge is actually attempted.
                    if hash != "expired" {
                        attempted.borrow_mut().push(hash);
                    }
                    Ok(())
                }
            },
        )
        .await
        .is_err());
        assert_eq!(*attempted.borrow(), vec!["live"]);
        assert!(cursor.pending.is_empty());
        assert_eq!(cursor.next, Some(600));
    }

    #[tokio::test]
    async fn capacity_does_not_discard_page_and_can_drain_existing_pending() {
        let mut cursor = Cursor {
            next: Some(600),
            pending: (0..MAX_PENDING).map(|n| n.to_string()).collect(),
            ..Default::default()
        };
        assert!(advance(
            &mut cursor,
            never_start,
            unchanged,
            |_| async { Ok((vec!["new".into()], 601, Some([3; 32]))) },
            |_| async { Ok(()) },
        )
        .await
        .is_err());
        assert!(cursor.pending.is_empty());
        assert_eq!(cursor.next, Some(600));
    }
}
