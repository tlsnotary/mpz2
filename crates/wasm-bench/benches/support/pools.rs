//! Shared browser pool setup for the wasm benches.
//!
//! Included via `#[path]` by each bench target (they're separate crates), so
//! it's compiled once per target. Kept dependency-light: `mpz-common`,
//! `rayon`, `web-spawn`, `crossbeam-channel` and the wasm-bindgen crates.
#![allow(dead_code)]

use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
};

use crossbeam_channel::{Receiver, Sender};
use js_sys::Promise;
use mpz_common::{ThreadPool, ThreadPoolBuildError};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Completion counter: the worker bumps it (and notifies) once a job's result
/// is stored. Lives in wasm linear memory, which is shared across the web
/// workers spawned by `web_spawn`, so it doubles as the `Atomics` word.
static JOB_DONE: AtomicI32 = AtomicI32::new(0);

fn signal_array() -> js_sys::Int32Array {
    let mem = wasm_bindgen::memory().unchecked_into::<js_sys::WebAssembly::Memory>();
    js_sys::Int32Array::new(&mem.buffer())
}

fn signal_index() -> u32 {
    (&JOB_DONE as *const AtomicI32 as usize / core::mem::size_of::<i32>()) as u32
}

/// Worker side of the hand-off: make the result visible, then wake the main
/// thread instead of making it poll.
fn signal_job_done() {
    JOB_DONE.fetch_add(1, Ordering::SeqCst);
    let _ = js_sys::Atomics::notify_with_count(&signal_array(), signal_index(), 1);
}

/// Main-thread side: sleep until [`JOB_DONE`] leaves `expected`, or
/// `timeout_ms` elapses. Falls back to a timer yield where `Atomics.waitAsync`
/// is unavailable.
async fn wait_job_done(expected: i32, timeout_ms: f64) {
    match js_sys::Atomics::wait_async_with_timeout(
        &signal_array(),
        signal_index(),
        expected,
        timeout_ms,
    ) {
        Ok(result) => {
            let pending = js_sys::Reflect::get(&result, &JsValue::from_str("async"))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if pending
                && let Ok(value) = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
                && let Ok(promise) = value.dyn_into::<js_sys::Promise>()
            {
                let _ = JsFuture::from(promise).await;
            }
        }
        Err(_) => yield_to_event_loop().await,
    }
}

/// `web_spawn::start_spawner` panics if invoked more than once, so guard it.
static SPAWNER_STARTED: AtomicBool = AtomicBool::new(false);

/// Sizes pools off the browser's hardware concurrency.
fn num_threads() -> usize {
    web_spawn::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
}

/// Starts the `web_spawn` spawner. Must run before any pool spawns workers.
/// Idempotent: `web_spawn::start_spawner` panics if called twice.
async fn start_spawner() {
    if SPAWNER_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    JsFuture::from(web_spawn::start_spawner()).await.unwrap();
}

/// Starts the spawner and installs the process-wide mpz `ThreadPool` with a
/// browser (Web Worker) spawn callback, so every replay session reuses the same
/// workers. Idempotent.
pub async fn init_mpz() {
    start_spawner().await;

    let builder = ThreadPool::builder().num_threads(num_threads()).spawn(|f| {
        let _ = web_spawn::spawn(f);
        Ok(())
    });

    match builder.build_global() {
        Ok(()) | Err(ThreadPoolBuildError::AlreadyInitialized) => {}
        Err(e) => panic!("failed to build global mpz thread pool: {e}"),
    }
}

/// Panics unless the current rayon context exposes as many threads as the
/// browser reports CPUs.
///
/// Rayon silently degrades to a single-thread "use current thread" pool when no
/// pool is installed (notably on `wasm32-unknown-unknown`). That makes a
/// benchmark that forgets [`submit_rayon`] produce plausible-looking but
/// single-threaded numbers. [`submit_rayon`] calls this inside every job, so
/// the degradation becomes a loud failure instead of a measurement.
pub fn assert_rayon_parallelism() {
    let expected = num_threads();
    let actual = rayon::current_num_threads();
    assert!(
        actual == expected,
        "rayon exposes {actual} thread(s) but web_spawn reports {expected} \
         (`available_parallelism`); rayon work is not running inside the \
         persistent worker pool, so it would silently execute single-threaded"
    );
}

type RayonJob = Box<dyn FnOnce() + Send>;

/// Give up if the worker reports no progress (no iteration tick) for this
/// long. wasm is built with `panic_abort`, so a dying worker cannot be
/// caught; the watchdog turns the ensuing hang into a visible failure.
const ITER_TIMEOUT_MS: u64 = 2 * 60 * 1000;

/// Last time an iteration boundary was reported from inside a job.
static LAST_TICK_MS: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

/// Marks an iteration boundary inside a [`submit_rayon`] job.
///
/// The main-thread watchdog fails the job if no tick arrives within
/// [`ITER_TIMEOUT_MS`], so a hung iteration is detected without waiting for
/// the whole sample.
pub fn tick() {
    LAST_TICK_MS.store(now_ms(), Ordering::SeqCst);
}

struct RayonWorker {
    tx: Sender<RayonJob>,
}

static RAYON_WORKER: OnceLock<RayonWorker> = OnceLock::new();
static RAYON_WORKER_FAILED: AtomicBool = AtomicBool::new(false);

/// Starts the persistent rayon worker (once). The worker builds a single
/// Web-Worker-backed rayon pool and then serves jobs from a queue, so the
/// pool is not rebuilt for every criterion sample.
pub async fn init_rayon_worker() {
    if RAYON_WORKER.get().is_some() {
        return;
    }
    start_spawner().await;

    let (tx, rx) = crossbeam_channel::unbounded::<RayonJob>();
    let n = num_threads();
    let _ = web_spawn::spawn(move || rayon_worker_loop(rx, n));

    let _ = RAYON_WORKER.set(RayonWorker { tx });

    // Wait until the worker has built its pool and is serving jobs, so the
    // first measured sample does not pay the multi-hundred-millisecond pool
    // construction. This is setup, and it costs one `Atomics.waitAsync` rather
    // than a poll storm.
    submit_rayon(|| ()).await;
}

fn rayon_worker_loop(rx: Receiver<RayonJob>, n: usize) {
    let pool = match rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .spawn_handler(|thread| {
            web_spawn::spawn(move || thread.run());
            Ok(())
        })
        .build()
    {
        Ok(pool) => pool,
        Err(_) => {
            RAYON_WORKER_FAILED.store(true, Ordering::SeqCst);
            return;
        }
    };

    // Fail fast if the pool we just built does not expose real parallelism.
    pool.install(assert_rayon_parallelism);

    while let Ok(job) = rx.recv() {
        pool.install(job);
    }
}

/// Submits `f` to the persistent rayon worker and awaits its result.
///
/// Reuses one pool across calls (i.e. across criterion samples). If the worker
/// dies, the watchdog panics here instead of hanging.
pub async fn submit_rayon<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let worker = RAYON_WORKER
        .get()
        .expect("init_rayon_worker must be called first");

    let result: Arc<Mutex<Option<R>>> = Arc::new(Mutex::new(None));
    let result_clone = result.clone();

    LAST_TICK_MS.store(now_ms(), Ordering::SeqCst);
    worker
        .tx
        .send(Box::new(move || {
            // Every job is checked, so a bench cannot silently run rayon work
            // outside the real pool (see `assert_rayon_parallelism`).
            assert_rayon_parallelism();
            *result_clone.lock().unwrap() = Some(f());
            signal_job_done();
        }))
        .expect("persistent rayon worker has exited");

    let start = now_ms();
    loop {
        if RAYON_WORKER_FAILED.load(Ordering::SeqCst) {
            panic!("failed to start the persistent rayon worker pool");
        }
        if let Some(value) = result.lock().unwrap().take() {
            return value;
        }
        let last = LAST_TICK_MS.load(Ordering::SeqCst);
        if now_ms().saturating_sub(start.max(last)) > ITER_TIMEOUT_MS {
            panic!(
                "persistent rayon worker made no progress for {}s \
                 (worker panicked/aborted or an iteration hung)",
                ITER_TIMEOUT_MS / 1000
            );
        }
        // Sleep until the worker signals (or the wait times out, which lets
        // the watchdog above re-check for progress).
        let expected = JOB_DONE.load(Ordering::SeqCst);
        wait_job_done(expected, 1_000.0).await;
    }
}

async fn yield_to_event_loop() {
    let promise = Promise::new(&mut |resolve, _| {
        web_sys::window()
            .expect("window exists on the main thread")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 0)
            .expect("failed to schedule timeout");
    });
    JsFuture::from(promise).await.expect("setTimeout promise");
}
