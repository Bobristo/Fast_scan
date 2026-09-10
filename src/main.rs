use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;
use rand::thread_rng;
use rlimit::{getrlimit, setrlimit, Resource};
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::Command;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout, Duration, Instant};

#[derive(Parser, Debug)]
#[command(author, version, about = "Высокоточный асинхронный сканер портов")]
struct Args {
    /// Целевой IP-адрес или доменное имя
    target: String,

    /// Диапазон портов (по умолчанию: 1-65535)
    #[arg(short = 'p', long, default_value = "1-65535")]
    ports: String,

    /// Явно задать таймаут в мс
    #[arg(short = 't', long)]
    timeout: Option<u64>,

    /// Автоматически запустить Nmap по найденным портам
    #[arg(short = 'n', long)]
    nmap: bool,

    /// Флаги для Nmap
    #[arg(short = 'A', long, default_value = "-sV -sC")]
    nmap_args: String,

    /// Сохранить результаты в файл (.json или .txt)
    #[arg(short = 'o', long)]
    output: Option<String>,
}

enum ScanResult {
    Open(u16),
    Closed,
    Retryable(u16),
}

fn tune_system_limits() -> usize {
    if let Ok((_soft, hard)) = getrlimit(Resource::NOFILE) {
        let target_limit = 8000.min(hard);
        let _ = setrlimit(Resource::NOFILE, target_limit, hard);
    }
    // Фиксированная безопасная планка для предотвращения исчерпания ephemeral-портов
    450
}

fn parse_ports(port_arg: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in port_arg.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() == 2 {
                if let (Ok(start), Ok(end)) = (bounds[0].parse::<u16>(), bounds[1].parse::<u16>()) {
                    ports.extend(start..=end);
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }
    ports
}

fn resolve_target(target: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }
    let host_with_port = format!("{}:80", target);
    if let Ok(mut addrs) = host_with_port.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(addr.ip());
        }
    }
    Err(format!("Не удалось разрешить адрес: {}", target))
}

async fn measure_rtt(ip: IpAddr) -> u64 {
    let test_ports = [80, 443, 22, 8080, 53];
    for port in test_ports {
        let start = Instant::now();
        let addr = SocketAddr::new(ip, port);
        if timeout(Duration::from_millis(1500), TcpStream::connect(&addr)).await.is_ok() {
            let rtt = start.elapsed().as_millis() as u64;
            return (rtt * 4).clamp(650, 1800);
        }
    }
    750
}

async fn check_port_detailed(ip: IpAddr, port: u16, timeout_ms: u64) -> ScanResult {
    let socket_addr = SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&socket_addr)).await {
        Ok(Ok(_stream)) => ScanResult::Open(port),
        Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => ScanResult::Closed,
        _ => ScanResult::Retryable(port),
    }
}

async fn confirm_port(ip: IpAddr, port: u16) -> bool {
    let socket_addr = SocketAddr::new(ip, port);
    for _ in 0..3 {
        if timeout(Duration::from_millis(1500), TcpStream::connect(&socket_addr))
            .await
            .is_ok_and(|res| res.is_ok())
        {
            return true;
        }
        sleep(Duration::from_millis(100)).await;
    }
    false
}

fn save_results(path: &str, target: &str, ip: IpAddr, ports: &[u16]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    if path.ends_with(".json") {
        let json_data = serde_json::json!({
            "target": target,
            "ip": ip.to_string(),
            "open_ports": ports
        });
        file.write_all(serde_json::to_string_pretty(&json_data)?.as_bytes())?;
    } else {
        writeln!(file, "Результаты сканирования для {} ({})", target, ip)?;
        writeln!(file, "Открытые порты:")?;
        for port in ports {
            writeln!(file, "- {}", port)?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let target_ip = match resolve_target(&args.target) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("[!] Ошибка: {}", e);
            return;
        }
    };

    let concurrency = tune_system_limits();
    println!("[+] Цель: {} ({})", args.target, target_ip);

    let auto_timeout = match args.timeout {
        Some(t) => {
            println!("[+] Установлен пользовательский таймаут: {}ms", t);
            t
        }
        None => {
            print!("[+] Измерение задержки сети (RTT)... ");
            let calculated = measure_rtt(target_ip).await;
            println!("Рассчитан оптимальный таймаут: {}ms", calculated);
            calculated
        }
    };

    let mut ports = parse_ports(&args.ports);
    if ports.is_empty() {
        eprintln!("[!] Нет портов для сканирования.");
        return;
    }

    let mut rng = thread_rng();
    ports.shuffle(&mut rng);

    let total_ports = ports.len() as u64;
    println!("[+] Фаза 1: Основное сканирование {} портов...", total_ports);

    let pb = ProgressBar::new(total_ports);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} портов ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let start_time = Instant::now();

    let mut handles = Vec::with_capacity(ports.len());

    for &port in &ports {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let pb_clone = pb.clone();

        handles.push(tokio::spawn(async move {
            let res = check_port_detailed(target_ip, port, auto_timeout).await;
            drop(permit);
            pb_clone.inc(1);
            res
        }));
    }

    let mut open_ports = Vec::new();
    let mut retry_ports = Vec::new();

    for handle in handles {
        if let Ok(res) = handle.await {
            match res {
                ScanResult::Open(port) => open_ports.push(port),
                ScanResult::Retryable(port) => retry_ports.push(port),
                ScanResult::Closed => {}
            }
        }
    }

    pb.finish_and_clear();

    // Фаза 2: Контрольный повтор для сомнительных портов (Smart Retry)
    if !retry_ports.is_empty() {
        println!(
            "[+] Фаза 2: Повторная проверка {} спорных/неответивших портов...",
            retry_ports.len()
        );
        sleep(Duration::from_millis(1000)).await;

        let retry_timeout = 1000.max(auto_timeout + 300);
        let retry_semaphore = Arc::new(Semaphore::new(concurrency / 2));
        let mut retry_handles = Vec::new();

        for &port in &retry_ports {
            let permit = retry_semaphore.clone().acquire_owned().await.unwrap();
            retry_handles.push(tokio::spawn(async move {
                let res = check_port_detailed(target_ip, port, retry_timeout).await;
                drop(permit);
                res
            }));
        }

        for handle in retry_handles {
            if let Ok(ScanResult::Open(port)) = handle.await {
                open_ports.push(port);
            }
        }
    }

    open_ports.sort();
    open_ports.dedup();

    // Фаза 3: Валидация найденных открытых портов
    println!("[+] Фаза 3: Финальная валидация найденных портов...");
    let mut verified_ports = Vec::new();
    for &port in &open_ports {
        if confirm_port(target_ip, port).await {
            println!("[OPEN] Порт {} открыт", port);
            verified_ports.push(port);
        }
    }

    let elapsed = start_time.elapsed();

    println!("\n[+] Сканирование завершено за {:.2?}", elapsed);
    println!("[+] Найдено открытых портов: {}", verified_ports.len());

    if let Some(ref output_path) = args.output {
        match save_results(output_path, &args.target, target_ip, &verified_ports) {
            Ok(_) => println!("[+] Результаты сохранены в файл: {}", output_path),
            Err(e) => eprintln!("[!] Ошибка сохранения файла: {}", e),
        }
    }

    if args.nmap && !verified_ports.is_empty() {
        let ports_str = verified_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!("\n[+] Запуск Nmap по портам: {}...", ports_str);

        let _ = Command::new("nmap")
            .args(args.nmap_args.split_whitespace())
            .arg("-p")
            .arg(&ports_str)
            .arg(target_ip.to_string())
            .status();
    }
}
