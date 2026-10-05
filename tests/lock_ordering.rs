//! Controlled host tests for the lock-ordering fixes from issue #269 and the
//! attached MUTEX_LOCK_AUDIT.md.
//!
//! These exercise the real `DebugRwLock` / `DebugMutex` guard semantics using the
//! exact acquisition sequences found at the patched call sites, with the
//! CloudKit/IDS network calls replaced by short sleeps and minimal stand-in
//! state. They are deliberately *controlled pattern tests*: a full end-to-end
//! run of `sync_keychain` against a real Cuttlefish server requires authenticated
//! device behavior and is out of scope for host CI. Every test is bounded by a
//! timeout so a deadlock fails the test instead of stalling CI.
//!
//! Covered sites:
//!   1. `KeychainClient::sync_keychain` / `fetch_shares_for`   (issue #269)
//!   2. `KeychainClient::join_clique`                           (reentrant read)
//!   3. `KeychainClient::invoke_escrow` / `get_escrow_headers`  (reentrant read)
//!   4. `SharedStreamClient::request_me` / `get_headers`        (reentrant read)
//!   5. `IdentityResource::get_possible_handles` vs `ensure_private_self` (order)

use rustpush::{DebugMutex, DebugRwLock};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::timeout;

/// Generous bound for the "must complete" tests. A correct pattern finishes in
/// milliseconds; a deadlock would hang forever, so any real completion is far
/// under this.
const BOUND: Duration = Duration::from_secs(10);

/// Short bound for the canary tests, which assert that a known-bad pattern
/// deadlocks. If the bad pattern ever completes, the harness is not actually
/// exercising the race.
const CANARY_BOUND: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Stand-in state mirroring the locking-relevant fields of the real structs.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct UserIdentity {
    identifier: String,
}

struct KeychainState {
    keystore_empty: bool,
    user: UserIdentity,
}

struct SharedStreamsState {
    host: String,
    dsid: String,
}

struct ApsState {
    token: String,
}

// ---------------------------------------------------------------------------
// Helpers mirroring the real reentrant helpers (network call -> re-acquire read).
// ---------------------------------------------------------------------------

/// Mirrors `KeychainClient::fetch_shares_for`: after a (simulated) CloudKit call
/// it re-acquires `state.read()`.
async fn fetch_shares_for(state: &DebugRwLock<KeychainState>, user: &UserIdentity) -> Vec<String> {
    tokio::time::sleep(Duration::from_millis(30)).await; // simulated CloudKit RPC
    let _guard = state.read().await; // reentrant read (the #269 site)
    vec![user.identifier.clone()]
}

/// Mirrors `KeychainClient::get_escrow_headers`: re-acquires `state.read()` and
/// reads a field while building headers.
async fn get_escrow_headers(state: &DebugRwLock<KeychainState>) -> String {
    let guard = state.read().await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    guard.user.identifier.clone()
}

/// Mirrors `SharedStreamClient::get_headers`: re-acquires `state.read()` and
/// reads `dsid` while building headers.
async fn get_headers(state: &DebugRwLock<SharedStreamsState>) -> String {
    let guard = state.read().await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    guard.dsid.clone()
}

/// Mirrors `IDSUser::get_handle_data`: a (simulated) IDS network call. Takes
/// `&APSState` (a reference, not a guard) and acquires no locks, so holding the
/// identity locks across it is safe.
async fn get_handle_data(_aps: &ApsState) -> Vec<String> {
    tokio::time::sleep(Duration::from_millis(10)).await;
    vec!["handle".to_string()]
}

// ---------------------------------------------------------------------------
// Issue #269: sync_keychain re-enters KeychainClient.state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_keychain_fixed_pattern_completes_with_concurrent_writer() {
    let state = DebugRwLock::new(KeychainState {
        keystore_empty: true,
        user: UserIdentity { identifier: "me".into() },
    });

    // Task A: the fixed sync_keychain pattern. Clone the identity, drop the
    // read guard, then await fetch_shares_for (which re-acquires read).
    let a = {
        let state = &state;
        async move {
            let guard = state.read().await;
            if guard.keystore_empty {
                let user = guard.user.clone();
                drop(guard);
                let _ = fetch_shares_for(state, &user).await;
            } else {
                drop(guard);
            }
        }
    };

    // Task B: a concurrent writer (is_in_clique -> sync_trust -> state.write()).
    let b = {
        let state = &state;
        async move {
            // Let A acquire its read guard and enter fetch_shares_for first.
            tokio::time::sleep(Duration::from_millis(10)).await;
            let mut guard = state.write().await;
            guard.keystore_empty = false;
        }
    };

    timeout(BOUND, async { tokio::join!(a, b) })
        .await
        .expect("fixed sync_keychain pattern deadlocked");
}

/// Canary proving the harness detects the #269 deadlock. Runs the OLD reentrant
/// pattern (hold the read guard across the await) against a writer that is
/// queued between the two read acquisitions via a oneshot signal.
#[tokio::test]
async fn reentrant_read_canary_deadlocks() {
    let state = DebugRwLock::new(KeychainState {
        keystore_empty: true,
        user: UserIdentity { identifier: "me".into() },
    });
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    // Task A: the OLD reentrant pattern (READ #1 held across the await).
    let a = {
        let state = &state;
        async move {
            let guard = state.read().await; // READ #1 held across the await
            tokio::time::sleep(Duration::from_millis(10)).await; // simulated RPC
            tx.send(()).unwrap();
            // Give B time to queue its write before the reentrant read.
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = fetch_shares_for(state, &guard.user).await; // reentrant READ #2
            drop(guard);
        }
    };

    // Task B: queue a writer between READ #1 and READ #2.
    let b = {
        let state = &state;
        async move {
            rx.await.unwrap();
            let mut guard = state.write().await;
            guard.keystore_empty = false;
        }
    };

    let result = timeout(CANARY_BOUND, async { tokio::join!(a, b) }).await;
    assert!(
        result.is_err(),
        "canary: expected the reentrant-read pattern to deadlock, but it completed"
    );
}

// ---------------------------------------------------------------------------
// Site 2: join_clique re-enters KeychainClient.state via downgrade
// ---------------------------------------------------------------------------

#[tokio::test]
async fn join_clique_fixed_pattern_completes_with_concurrent_writer() {
    let state = DebugRwLock::new(KeychainState {
        keystore_empty: true,
        user: UserIdentity { identifier: "me".into() },
    });

    // Task A: the fixed join_clique pattern. Downgrade write->read, clone the
    // identity, drop the guard, then await fetch_shares_for.
    let a = {
        let state = &state;
        async move {
            let write_guard = state.write().await;
            let guard = write_guard.downgrade();
            let user = guard.user.clone();
            drop(guard);
            let _ = fetch_shares_for(state, &user).await;
        }
    };

    let b = {
        let state = &state;
        async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let mut guard = state.write().await;
            guard.keystore_empty = false;
        }
    };

    timeout(BOUND, async { tokio::join!(a, b) })
        .await
        .expect("fixed join_clique pattern deadlocked");
}

// ---------------------------------------------------------------------------
// Site 3: invoke_escrow re-enters KeychainClient.state via get_escrow_headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_escrow_fixed_pattern_completes_with_concurrent_writer() {
    let state = DebugRwLock::new(KeychainState {
        keystore_empty: true,
        user: UserIdentity { identifier: "me".into() },
    });

    // Task A: the fixed invoke_escrow pattern. Clone the needed field, drop the
    // read guard, then await get_escrow_headers (which re-acquires read).
    let a = {
        let state = &state;
        async move {
            let guard = state.read().await;
            let _host = guard.user.identifier.clone(); // stand-in for state.host
            drop(guard);
            let _ = get_escrow_headers(state).await;
        }
    };

    let b = {
        let state = &state;
        async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let mut guard = state.write().await;
            guard.keystore_empty = false;
        }
    };

    timeout(BOUND, async { tokio::join!(a, b) })
        .await
        .expect("fixed invoke_escrow pattern deadlocked");
}

// ---------------------------------------------------------------------------
// Site 4: SharedStreamClient::request_me re-enters SharedStreamClient.state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn request_me_fixed_pattern_completes_with_concurrent_writer() {
    let state = DebugRwLock::new(SharedStreamsState {
        host: "https://example.com".into(),
        dsid: "dsid".into(),
    });

    // Task A: the fixed request_me pattern. Clone host+dsid, drop the read
    // guard, then await get_headers (which re-acquires read).
    let a = {
        let state = &state;
        async move {
            let guard = state.read().await;
            let host = guard.host.clone();
            let dsid = guard.dsid.clone();
            drop(guard);
            let _ = get_headers(state).await;
            let _ = (host, dsid);
        }
    };

    let b = {
        let state = &state;
        async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let mut guard = state.write().await;
            guard.dsid = "changed".into();
        }
    };

    timeout(BOUND, async { tokio::join!(a, b) })
        .await
        .expect("fixed request_me pattern deadlocked");
}

// ---------------------------------------------------------------------------
// Site 5: get_possible_handles vs ensure_private_self lock order
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_lock_order_fixed_pattern_completes() {
    let users = DebugRwLock::new(vec!["me".to_string()]);
    let aps = DebugRwLock::new(ApsState { token: "tok".into() });
    let cache = DebugMutex::new(HashSet::<String>::new());

    // Task A: the fixed get_possible_handles order (cache -> users -> aps).
    let a = {
        let (users, aps, cache) = (&users, &aps, &cache);
        async move {
            let mut _cache_lock = cache.lock().await;
            let users_locked = users.read().await;
            let state = aps.read().await;
            for user in &*users_locked {
                let handles = get_handle_data(&state).await;
                for h in handles {
                    _cache_lock.insert(h);
                }
            }
        }
    };

    // Task B: the ensure_private_self order (cache -> users -> aps).
    let b = {
        let (users, aps, cache) = (&users, &aps, &cache);
        async move {
            let mut _cache_lock = cache.lock().await;
            let _user_lock = users.read().await;
            let _state = aps.read().await;
        }
    };

    timeout(BOUND, async { tokio::join!(a, b) })
        .await
        .expect("fixed identity lock order deadlocked");
}

/// Canary proving the harness detects the lock-order cycle. Task A uses the OLD
/// get_possible_handles order (users -> aps -> cache) while task B takes the
/// reverse order (cache -> users.write, as update_users / reregistration can
/// queue). Together they form the users -> cache -> users cycle.
#[tokio::test]
async fn identity_lock_order_canary_deadlocks() {
    let users = DebugRwLock::new(vec!["me".to_string()]);
    let aps = DebugRwLock::new(ApsState { token: "tok".into() });
    let cache = DebugMutex::new(HashSet::<String>::new());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    // Task A: OLD get_possible_handles order (users -> aps -> cache). Holds
    // users.read + aps.read, then wants cache.
    let a = {
        let (users, aps, cache) = (&users, &aps, &cache);
        async move {
            let users_locked = users.read().await;
            let state = aps.read().await;
            tx.send(()).unwrap();
            // Give B time to acquire the cache lock first.
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut _cache_lock = cache.lock().await; // wants cache, holds users+aps
            for _ in &*users_locked {
                _ = &state;
            }
        }
    };

    // Task B: reverse order (cache -> users.write).
    let b = {
        let (users, aps, cache) = (&users, &aps, &cache);
        async move {
            rx.await.unwrap();
            let _cache_lock = cache.lock().await;
            let _user_write = users.write().await; // wants users.write, holds cache
            let _state = aps.read().await;
        }
    };

    let result = timeout(CANARY_BOUND, async { tokio::join!(a, b) }).await;
    assert!(
        result.is_err(),
        "canary: expected the lock-order cycle to deadlock, but it completed"
    );
}
