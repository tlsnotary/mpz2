//! Chromiumoxide-based WASM benchmark runner.
//!
//! Launches headless Chrome and runs benchmarks.
//! Requires WASM to be built first with ./build-wasm.sh
//!
//! Usage:
//!   ./build-wasm.sh
//!   cargo run --release --bin wasm-bench-runner -- [OPTIONS]
//!
//! Options:
//!   --iterations <N>   Number of iterations per benchmark (default: 100)
//!   --samples <N>      Number of samples per benchmark (default: 10)
//!   --verbose, -v      Print browser console logs to terminal

use std::{convert::Infallible, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use chromiumoxide::{
    Page,
    browser::{Browser, BrowserConfig},
    cdp::{
        browser_protocol::page::NavigateParams,
        js_protocol::runtime::{
            ConsoleApiCalledType, EnableParams as RuntimeEnableParams, EventConsoleApiCalled,
            EventExceptionThrown,
        },
    },
};
use futures::{FutureExt, StreamExt};
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpListener;

/// All available benchmark groups
const ALL_GROUPS: &[&str] = &[
    "garbler_core",
    "evaluator_core",
    "zk_prover_core",
    "zk_verifier_core",
    "zk_prover",
    "zk_verifier",
    "garble",
    "ferret_sender",
];

/// All available benchmarks
const ALL_BENCHMARKS: &[&str] = &[
    "garbler_core/half_gates",
    "evaluator_core/half_gates",
    "evaluator_core/half_gates_batched",
    "evaluator_core/half_gates_parallel",
    "zk_prover_core/execute",
    "zk_prover_core/check_200k",
    "zk_prover_core/check_400k",
    "zk_prover_core/check_600k",
    "zk_verifier_core/execute",
    "zk_verifier_core/check_200k",
    "zk_verifier_core/check_400k",
    "zk_verifier_core/check_600k",
    "zk_prover/100k",
    "zk_prover/1m",
    "zk_prover/10m",
    "zk_verifier/100k",
    "zk_verifier/1m",
    "zk_verifier/10m",
    "garble/garbler_100k",
    "garble/garbler_1m",
    "garble/garbler_10m",
    "garble/evaluator_100k",
    "garble/evaluator_1m",
    "garble/evaluator_10m",
    "ferret_sender/100k",
    "ferret_sender/1m",
    "ferret_sender/10m",
];

/// Get all benchmarks in a group
fn benchmarks_in_group(group: &str) -> Vec<&'static str> {
    let prefix = format!("{}/", group);
    ALL_BENCHMARKS
        .iter()
        .filter(|b| b.starts_with(&prefix))
        .copied()
        .collect()
}

/// Check if a benchmark is multi-threaded (uses concurrency parameter)
fn is_mt_benchmark(name: &str) -> bool {
    // MT groups: all benchmarks in these groups are MT
    let mt_groups = ["zk_prover", "zk_verifier", "garble", "ferret_sender"];
    for group in mt_groups {
        if name.starts_with(&format!("{}/", group)) {
            // Exclude specific ST benchmarks
            if name == "zk_prover/replay_throughput" || name == "zk_prover/channel_throughput" {
                return false;
            }
            return true;
        }
    }
    // Individual MT benchmarks (including zk_core check which uses rayon
    // internally)
    matches!(
        name,
        "zk/zk_mt_batched"
            | "ferret/sender_mt"
            | "test/mt_context_only"
            | "garble_core/half_gates_evaluate_parallel"
    ) || name.starts_with("zk_core/prover_check_")
        || name.starts_with("zk_core/verifier_check_")
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BenchResult {
    name: String,
    iterations: u32,
    samples: u32,
    min_ms: f64,
    max_ms: f64,
    median_ms: f64,
    mean_ms: f64,
    per_iter_ms: f64,
    per_iter_us: f64,
    throughput: f64,
}

/// Dynamic benchmark results by category
type BenchResults = std::collections::HashMap<String, Vec<BenchResult>>;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BenchOutput {
    results: BenchResults,
    formatted: String,
}

fn get_crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Register console log listeners for a page via CDP
async fn register_console_listeners(
    page: &Page,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    // Enable Runtime domain to receive console API events
    page.execute(RuntimeEnableParams::default()).await?;

    let mut console_events = page.event_listener::<EventConsoleApiCalled>().await?;
    let mut exceptions = page.event_listener::<EventExceptionThrown>().await?;

    let handle = tokio::spawn(
        futures::future::join(
            async move {
                while let Some(event) = console_events.next().await {
                    // Format console arguments into a string
                    let args: Vec<String> = event
                        .args
                        .iter()
                        .filter_map(|arg| {
                            arg.value
                                .as_ref()
                                .map(|v| v.to_string())
                                .or_else(|| arg.description.clone())
                        })
                        .collect();
                    let message = args.join(" ");

                    match event.r#type {
                        ConsoleApiCalledType::Error => eprintln!("[browser:error] {}", message),
                        ConsoleApiCalledType::Warning => eprintln!("[browser:warn] {}", message),
                        _ => println!("[browser] {}", message),
                    }
                }
            },
            async move {
                while let Some(event) = exceptions.next().await {
                    eprintln!("[browser:exception] {:?}", event);
                }
            },
        )
        .map(|_| ()),
    );

    Ok(handle)
}

/// Run benchmarks with a specific concurrency setting, returns the results
async fn run_benchmarks_with_concurrency(
    browser: &Browser,
    server_addr: std::net::SocketAddr,
    benchmarks: &[String],
    iterations: u32,
    samples: u32,
    concurrency: Option<u32>,
    verbose: bool,
) -> Result<BenchResults, Box<dyn std::error::Error>> {
    let page = browser.new_page("about:blank").await?;

    // Register console listeners if verbose mode is enabled
    let _console_handle = if verbose {
        Some(register_console_listeners(&page).await?)
    } else {
        None
    };

    let benchmarks_param = benchmarks.join(",");
    let concurrency_param = concurrency
        .map(|c| format!("&concurrency={}", c))
        .unwrap_or_default();
    let url = format!(
        "http://{}/?autorun=true&iterations={}&samples={}&benchmarks={}{}",
        server_addr, iterations, samples, benchmarks_param, concurrency_param
    );

    if let Some(c) = concurrency {
        println!("\n=== Running with {} threads ===", c);
    }
    page.goto(NavigateParams::builder().url(&url).build()?)
        .await?;

    page.wait_for_navigation().await?;

    let timeout = Duration::from_secs(300);
    let start = std::time::Instant::now();
    let mut last_status = String::new();
    let result: BenchOutput = loop {
        if start.elapsed() > timeout {
            return Err("Benchmark timed out after 5 minutes".into());
        }

        // Poll console logs (track count but don't print - reduces noise)
        let logs_check = page
            .evaluate("window.__consoleLogs ? JSON.stringify(window.__consoleLogs) : '[]'")
            .await?;
        if let Ok(logs_json) = logs_check.into_value::<String>()
            && let Ok(logs) = serde_json::from_str::<Vec<String>>(&logs_json)
        {
            let _ = logs.len();
        }

        // Check for errors
        let error_check = page.evaluate("window.__benchError || null").await?;
        if let Ok(Some(error)) = error_check.into_value::<Option<String>>() {
            return Err(format!("JavaScript error: {}", error).into());
        }

        // Check progress
        let progress_check = page.evaluate("window.__benchProgress || null").await?;
        if let Ok(Some(progress)) = progress_check.into_value::<Option<String>>()
            && progress != last_status
        {
            print!("\r\x1b[K{}", progress);
            use std::io::Write;
            std::io::stdout().flush().ok();
            last_status = progress;
        }

        // Check if results are available
        let check = page
            .evaluate("window.__benchResults ? JSON.stringify(window.__benchResults) : null")
            .await?;

        match check.into_value::<Option<String>>() {
            Ok(Some(json_str)) => {
                println!();
                break serde_json::from_str(&json_str)?;
            }
            Ok(None) => {}
            Err(_) => {}
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    drop(page);
    Ok(result.results)
}

fn print_results(results: &BenchResults) {
    fn print_section(name: &str, benchmarks: &[BenchResult]) {
        println!("\n=== {} ===", name);
        println!(
            "{:<40} {:>12} {:>14} {:>12}",
            "Name", "Median (ms)", "Per-iter (us)", "AND gates/s"
        );
        println!("{}", "-".repeat(82));
        for b in benchmarks {
            println!(
                "{:<40} {:>12.2} {:>14.2} {:>10.2}M",
                b.name,
                b.median_ms,
                b.per_iter_us,
                b.throughput / 1_000_000.0
            );
        }
    }

    for (category, benchmarks) in results {
        print_section(category, benchmarks);
    }
}

/// Simple static file server
async fn serve_file(
    req: Request<hyper::body::Incoming>,
    base_dir: Arc<PathBuf>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let path = if path == "/" { "/index.html" } else { path };

    // Remove leading slash and resolve path
    let file_path = base_dir.join(path.trim_start_matches('/'));

    // Security: ensure path is within base_dir
    let file_path = match file_path.canonicalize() {
        Ok(p) if p.starts_with(base_dir.as_ref()) => p,
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap());
        }
    };

    match tokio::fs::read(&file_path).await {
        Ok(contents) => {
            let mime = mime_guess::from_path(&file_path)
                .first_or_octet_stream()
                .to_string();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", mime)
                .header("Cross-Origin-Opener-Policy", "same-origin")
                .header("Cross-Origin-Embedder-Policy", "require-corp")
                .body(Full::new(Bytes::from(contents)))
                .unwrap())
        }
        Err(_) => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap()),
    }
}

/// Start HTTP server and return the bound address
async fn start_server(base_dir: PathBuf) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base_dir = Arc::new(base_dir);

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };

            let base_dir = base_dir.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| serve_file(req, base_dir.clone()));

                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    Ok(addr)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut iterations = 100u32;
    let mut samples = 10u32;
    let mut verbose = false;
    let mut concurrency: Option<u32> = None;
    let mut sweep_concurrency = false;
    let mut selected_benchmarks: Vec<String> = Vec::new();

    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iterations" => {
                i += 1;
                iterations = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(100);
            }
            "--samples" => {
                i += 1;
                samples = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(10);
            }
            "--concurrency" | "-c" => {
                i += 1;
                concurrency = args.get(i).and_then(|s| s.parse().ok());
            }
            "--sweep" => {
                sweep_concurrency = true;
            }
            "--verbose" | "-v" => {
                verbose = true;
            }
            "--list" | "-l" => {
                println!("Available groups:");
                for group in ALL_GROUPS {
                    println!("  {}", group);
                }
                println!();
                println!("Available benchmarks:");
                for name in ALL_BENCHMARKS {
                    println!("  {}", name);
                }
                println!();
                println!("Notes:");
                println!(
                    "  zk_isolated/prover_batch_Xk: 'batch' is the number of AND gates processed"
                );
                println!(
                    "    before a consistency check is triggered. Smaller batch = more frequent"
                );
                println!("    checks = lower latency but higher overhead.");
                return Ok(());
            }
            "--group" | "-g" => {
                i += 1;
                if let Some(group) = args.get(i) {
                    if ALL_GROUPS.contains(&group.as_str()) {
                        for bench in benchmarks_in_group(group) {
                            selected_benchmarks.push(bench.to_string());
                        }
                    } else {
                        eprintln!("Unknown group: {}", group);
                        eprintln!("Available groups: {}", ALL_GROUPS.join(", "));
                        return Ok(());
                    }
                }
            }
            "--bench" | "-b" => {
                i += 1;
                if let Some(name) = args.get(i) {
                    if ALL_BENCHMARKS.contains(&name.as_str()) {
                        selected_benchmarks.push(name.clone());
                    } else {
                        eprintln!("Unknown benchmark: {}", name);
                        eprintln!("Use --list to see available benchmarks.");
                        return Ok(());
                    }
                }
            }
            "--help" | "-h" => {
                println!("WASM Benchmark Runner");
                println!();
                println!("Usage: wasm-bench-runner [OPTIONS]");
                println!();
                println!("Options:");
                println!(
                    "  --iterations <N>     Number of iterations per benchmark (default: 100)"
                );
                println!("  --samples <N>        Number of samples per benchmark (default: 10)");
                println!("  --concurrency, -c <N> Thread count for MT benchmarks (default: auto)");
                println!("  --sweep              Run MT benchmarks with 2,3,4,6,8,12,16 threads");
                println!("  --group, -g <GROUP>  Run all benchmarks in a group (can be repeated)");
                println!("  --bench, -b <NAME>   Run specific benchmark (can be repeated)");
                println!("  --list, -l           List available groups and benchmarks");
                println!("  --verbose, -v        Print browser console logs to terminal");
                println!("  --help, -h           Show this help");
                println!();
                println!("Groups: {}", ALL_GROUPS.join(", "));
                println!();
                println!("Examples:");
                println!("  wasm-bench-runner                    # Run all benchmarks");
                println!("  wasm-bench-runner -g garble_core     # Run all garble_core benchmarks");
                println!("  wasm-bench-runner -g zk_core         # Run all zk_core benchmarks");
                println!("  wasm-bench-runner -g garble --sweep  # Sweep thread counts for garble");
                println!("  wasm-bench-runner -b zk_core/prover_execute  # Run one benchmark");
                println!();
                println!("Note: Run ./build-wasm.sh first to build the WASM module.");
                return Ok(());
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                eprintln!("Use --help to see available options.");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // If no benchmarks specified, run all
    let benchmarks: Vec<String> = if selected_benchmarks.is_empty() {
        ALL_BENCHMARKS.iter().map(|s| s.to_string()).collect()
    } else {
        selected_benchmarks
    };

    // Validate concurrency for MT benchmarks (need at least 2 threads)
    let has_mt_benchmarks = benchmarks.iter().any(|b| is_mt_benchmark(b));
    if has_mt_benchmarks
        && let Some(c) = concurrency
        && c < 2
    {
        return Err(
            "MT benchmarks require at least 2 threads (garbler uses try_join). Use -c 2 or higher."
                .into(),
        );
    }

    let crate_dir = get_crate_dir();
    let index_path = crate_dir.join("index.html");

    if !index_path.exists() {
        return Err(format!("index.html not found at {:?}", index_path).into());
    }

    let pkg_dir = crate_dir.join("pkg");
    if !pkg_dir.exists() {
        return Err(
            "pkg/ directory not found. Run ./build-wasm.sh first to build the WASM module.".into(),
        );
    }

    // Start HTTP server
    let server_addr = start_server(crate_dir).await?;

    // Configure headless browser.
    let builder = BrowserConfig::builder()
        .no_sandbox() // CI runners block the unprivileged user namespaces the sandbox needs
        .arg("disable-dev-shm-usage")
        .arg("disable-gpu")
        .arg("disable-cache")
        .arg("disable-application-cache")
        .window_size(1200, 800);

    let config = builder.build()?;

    let (browser, mut handler) = Browser::launch(config).await?;

    // Spawn handler (filter out known false-positive error from chromiumoxide)
    // See: https://github.com/mattsse/chromiumoxide/issues/167
    let handle = tokio::spawn(async move {
        while let Some(event) = handler.next().await {
            if let Err(e) = event {
                if e.to_string() == "data did not match any variant of untagged enum Message" {
                    continue;
                }
                eprintln!("Browser event error: {:?}", e);
            }
        }
    });

    // Get available CPU count for sweep
    let available_cpus = std::thread::available_parallelism()
        .map(|p| p.get() as u32)
        .unwrap_or(16);

    if sweep_concurrency {
        // Only run MT benchmarks in sweep mode
        let mt_benchmarks: Vec<String> = benchmarks
            .iter()
            .filter(|b| is_mt_benchmark(b))
            .cloned()
            .collect();

        if mt_benchmarks.is_empty() {
            return Err(
                "No MT benchmarks selected for sweep. Use -b to select MT benchmarks.".into(),
            );
        }

        // MT context needs at least 2 threads (garbler uses try_join which
        // forks into 2)
        let thread_counts: Vec<u32> = vec![2, 3, 4, 6, 8, 12, 16]
            .into_iter()
            .filter(|&c| c <= available_cpus)
            .collect();

        println!(
            "Sweeping thread counts: {:?} (max available: {})",
            thread_counts, available_cpus
        );

        // Collect results for summary table
        let mut sweep_results: Vec<(u32, BenchResults)> = Vec::new();

        for thread_count in &thread_counts {
            match run_benchmarks_with_concurrency(
                &browser,
                server_addr,
                &mt_benchmarks,
                iterations,
                samples,
                Some(*thread_count),
                verbose,
            )
            .await
            {
                Ok(results) => {
                    print_results(&results);
                    sweep_results.push((*thread_count, results));
                }
                Err(e) => {
                    eprintln!("Error with {} threads: {}", thread_count, e);
                }
            }
        }

        // Print summary table
        println!("\n\n=== CONCURRENCY SWEEP SUMMARY ===");
        println!(
            "{:<10} {:>15} {:>15}",
            "Threads", "Median (ms)", "AND gates/s"
        );
        println!("{}", "-".repeat(42));
        for (threads, results) in &sweep_results {
            for benchmarks in results.values() {
                for b in benchmarks {
                    println!(
                        "{:<10} {:>15.2} {:>13.2}M",
                        threads,
                        b.median_ms,
                        b.throughput / 1_000_000.0
                    );
                }
            }
        }
    } else {
        // Normal single run
        let results = run_benchmarks_with_concurrency(
            &browser,
            server_addr,
            &benchmarks,
            iterations,
            samples,
            concurrency,
            verbose,
        )
        .await?;

        print_results(&results);
    }

    // Cleanup
    drop(browser);
    handle.abort();

    println!("\nBenchmark complete.");
    Ok(())
}
