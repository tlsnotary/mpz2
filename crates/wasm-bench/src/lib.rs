//! WASM benchmarks for mpz libraries.
//!
//! This crate exposes benchmarks as WASM-callable functions
//! for browser performance testing.
//!
//! Modules:
//! - `garble`: Garbled circuits benchmarks (core + protocol)
//! - `zk`: QuickSilver ZK benchmarks (core + protocol + prover/verifier)
//! - `ot`: Oblivious transfer benchmarks (Ferret)

// wasm_bindgen's `getter_with_clone` codegen calls `.clone()` on Copy fields.
#![cfg_attr(target_arch = "wasm32", allow(clippy::clone_on_copy))]

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
mod garble;
#[cfg(target_arch = "wasm32")]
mod ot;
#[cfg(target_arch = "wasm32")]
mod zk;

// Re-export all wasm_bindgen functions
#[cfg(target_arch = "wasm32")]
pub use garble::*;
#[cfg(target_arch = "wasm32")]
pub use ot::*;
#[cfg(target_arch = "wasm32")]
pub use zk::*;

/// Common benchmark result containing timing and work done.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone))]
pub struct BenchResult {
    pub elapsed_ms: f64,
    pub and_gates: u64,
}

/// Initialize the web_spawn spawner and rayon thread pool for MT benchmarks.
/// Must be called before running any MT benchmarks.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn init_thread_pool(thread_count: usize) -> Result<(), JsValue> {
    use std::sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    };
    use wasm_bindgen_futures::JsFuture;

    const INIT_PENDING: u8 = 0;
    const INIT_SUCCESS: u8 = 1;
    const INIT_FAILED: u8 = 2;

    web_sys::console::log_1(&"[rust] init_thread_pool: starting web_spawn spawner...".into());

    // Check if SharedArrayBuffer is available (requires COOP/COEP headers)
    let sab_available =
        ::js_sys::Reflect::has(&::js_sys::global(), &"SharedArrayBuffer".into()).unwrap_or(false);
    web_sys::console::log_1(
        &format!("[rust] SharedArrayBuffer available: {}", sab_available).into(),
    );

    if !sab_available {
        return Err(JsValue::from_str(
            "SharedArrayBuffer not available - check COOP/COEP headers",
        ));
    }

    // Initialize web_spawn spawner
    web_sys::console::log_1(&"[rust] Calling web_spawn::start_spawner()...".into());
    JsFuture::from(web_spawn::start_spawner()).await?;

    web_sys::console::log_1(&"[rust] init_thread_pool: web_spawn spawner ready".into());
    web_sys::console::log_1(
        &format!(
            "[rust] init_thread_pool: building rayon pool with {} threads in worker...",
            thread_count
        )
        .into(),
    );

    // Initialize rayon in a worker thread (Atomics.wait is allowed there)
    let init_status = Arc::new(AtomicU8::new(INIT_PENDING));
    let init_status_clone = init_status.clone();

    web_spawn::spawn(move || {
        web_sys::console::log_1(&"[rust] worker: starting rayon init...".into());
        let result = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .spawn_handler(|thread| {
                web_sys::console::log_1(&"[rust] rayon spawn_handler called".into());
                let _ = web_spawn::spawn(move || thread.run());
                Ok(())
            })
            .build_global();

        match result {
            Ok(_) => {
                web_sys::console::log_1(&"[rust] worker: rayon init success".into());
                init_status_clone.store(INIT_SUCCESS, Ordering::SeqCst);
            }
            Err(e) => {
                web_sys::console::log_1(&format!("[rust] worker: rayon init failed: {}", e).into());
                init_status_clone.store(INIT_FAILED, Ordering::SeqCst);
            }
        }
    });

    // Poll for completion (non-blocking on main thread)
    loop {
        match init_status.load(Ordering::SeqCst) {
            INIT_SUCCESS => {
                web_sys::console::log_1(&"[rust] init_thread_pool: complete".into());
                return Ok(());
            }
            INIT_FAILED => {
                return Err(JsValue::from_str("rayon thread pool initialization failed"));
            }
            _ => {
                // Yield to event loop
                JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL)).await?;
            }
        }
    }
}

/// Test if MT context works at all - minimal ping-pong test.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn test_mt_context_only() -> Result<u32, JsValue> {
    use mpz_common::context::test_mt_context_with_spawn;
    use serio::{SinkExt, stream::IoStreamExt};

    let (mt1, mt2) = test_mt_context_with_spawn(8, |f| {
        let _ = web_spawn::spawn(f);
        Ok(())
    });

    web_sys::console::log_1(&"Created MT contexts".into());

    let mut ctx1 = mt1
        .new_context()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut ctx2 = mt2
        .new_context()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    web_sys::console::log_1(&"Got contexts from MT".into());

    // Simple ping-pong: ctx1 sends, ctx2 receives
    let (res1, res2) = futures::join!(
        async {
            web_sys::console::log_1(&"ctx1: sending...".into());
            ctx1.io_mut().send(42u32).await.map_err(|e| e.to_string())?;
            web_sys::console::log_1(&"ctx1: send done".into());
            Ok::<_, String>(42u32)
        },
        async {
            web_sys::console::log_1(&"ctx2: receiving...".into());
            let val: u32 = ctx2
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| e.to_string())?;
            web_sys::console::log_1(&"ctx2: receive done".into());
            Ok::<_, String>(val)
        }
    );

    let v1 = res1.map_err(|e| JsValue::from_str(&e))?;
    let v2 = res2.map_err(|e| JsValue::from_str(&e))?;

    web_sys::console::log_1(&format!("Test complete: {} + {} = {}", v1, v2, v1 + v2).into());
    Ok(v1 + v2)
}
