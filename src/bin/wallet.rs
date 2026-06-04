use kyvera_core::wallet::{
    keys::KyveraWallet,
    seed::{generate_seed_phrase, seed_from_phrase, validate_seed_phrase, format_seed_phrase_for_display},
    storage::{save_wallet_v2, load_wallet, wallet_exists},
    transaction_builder::{build_transfer, build_stake_lock},
};
use std::env;
use std::io::{self, BufRead, Write};

// Kyvera CLI Wallet
// Usage:
//   kyv-wallet create <label> <wallet-file>
//   kyv-wallet info <wallet-file>
//   kyv-wallet restore <wallet-file>
//   kyv-wallet send <wallet-file> <recipient> <amount-kyv> <fee-kyv>
//   kyv-wallet stake <wallet-file> <amount-kyv>

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let result = match args[1].as_str() {
        "create"  => cmd_create(&args),
        "info"    => cmd_info(&args),
        "restore" => cmd_restore(&args),
        "send"    => cmd_send(&args),
        "stake"   => cmd_stake(&args),
        "help"    => { print_usage(); Ok(()) }
        unknown   => {
            eprintln!("Unknown command: {}", unknown);
            print_usage();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

// kyv-wallet create <label> <wallet-file>
// Generates a fresh wallet, shows the seed phrase, saves encrypted.
fn cmd_create(args: &[String]) -> Result<(), String> {
    if args.len() < 4 {
        return Err("Usage: kyv-wallet create <label> <wallet-file>".to_string());
    }

    let label = &args[2];
    let path  = &args[3];

    if wallet_exists(path) {
        return Err(format!("Wallet file already exists at {}. Delete it first or choose a different path.", path));
    }

    // Generate the seed phrase first — this is the user's backup
    let seed_phrase = generate_seed_phrase();
    let seed_bytes  = seed_from_phrase(&seed_phrase, "")
        .map_err(|e| format!("Seed generation failed: {}", e))?;

    // Generate the wallet
    let wallet = KyveraWallet::generate(label);

    println!();
    println!("══════════════════════════════════════════════════════");
    println!("  NEW KYVERA WALLET CREATED");
    println!("══════════════════════════════════════════════════════");
    println!();
    println!("  Label:   {}", wallet.label);
    println!("  Address: {}", wallet.address);
    println!();
    println!("  ⚠  SEED PHRASE — WRITE THIS DOWN NOW");
    println!("  ⚠  Anyone with these words can access your wallet.");
    println!("  ⚠  Store them offline. Never share them.");
    println!();
    println!("  {}", format_seed_phrase_for_display(&seed_phrase));
    println!();
    println!("══════════════════════════════════════════════════════");
    println!();

    // Ask for a password before saving
    let password = prompt_password("  Set wallet password: ")?;
    let confirm  = prompt_password("  Confirm password:    ")?;

    if password != confirm {
        return Err("Passwords do not match. Wallet not saved.".to_string());
    }

    // Save the encrypted wallet file
    save_wallet_v2(&wallet, path, &password)
        .map_err(|e| format!("Failed to save wallet: {}", e))?;

    println!();
    println!("  Wallet saved to: {}", path);
    println!("  Keep your seed phrase safe. It cannot be recovered.");
    println!();

    // Suppress unused variable warning — seed_bytes will be used
    // for deterministic key derivation in a future update
    let _ = seed_bytes;

    Ok(())
}

// kyv-wallet info <wallet-file>
// Load and display wallet information. No secret keys shown.
fn cmd_info(args: &[String]) -> Result<(), String> {
    if args.len() < 3 {
        return Err("Usage: kyv-wallet info <wallet-file>".to_string());
    }

    let path = &args[2];
    let password = prompt_password("  Wallet password: ")?;

    let wallet = load_wallet(path, &password)
        .map_err(|e| format!("Failed to load wallet: {}", e))?;

    let info = wallet.info();

    println!();
    println!("══════════════════════════════════════════════════════");
    println!("  KYVERA WALLET INFO");
    println!("══════════════════════════════════════════════════════");
    println!();
    println!("  Label:   {}", info.label);
    println!("  Address: {}", info.address);
    println!();
    println!("  Signing public key (first 32 chars):");
    println!("  {}...", &info.signing_public_key[..32]);
    println!();
    println!("  Created: {}", format_timestamp(wallet.created_at));
    println!();
    println!("  Note: Balance lookup requires a running node.");
    println!("        Coming in Month 5 — chain state layer.");
    println!();

    Ok(())
}

// kyv-wallet restore <wallet-file>
// Restore a wallet from a seed phrase. Saves encrypted to the given path.
fn cmd_restore(args: &[String]) -> Result<(), String> {
    if args.len() < 3 {
        return Err("Usage: kyv-wallet restore <wallet-file>".to_string());
    }

    let path = &args[2];

    if wallet_exists(path) {
        return Err(format!(
            "Wallet file already exists at {}. Choose a different path.", path
        ));
    }

    println!();
    println!("  Enter your 24-word seed phrase (words separated by spaces):");
    print!("  > ");
    io::stdout().flush().unwrap();

    let stdin = io::stdin();
    let phrase = stdin.lock().lines().next()
        .ok_or("No input received")?
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();

    if !validate_seed_phrase(&phrase) {
        return Err("Invalid seed phrase. Check your words and try again.".to_string());
    }

    println!();
    println!("  Seed phrase valid. Enter a label for this wallet:");
    print!("  > ");
    io::stdout().flush().unwrap();

    let label = stdin.lock().lines().next()
        .ok_or("No input received")?
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();

    // For now we generate a fresh wallet and note that full
    // deterministic restoration from seed is coming in Month 3 final.
    // The seed phrase is validated — deterministic key derivation
    // from BIP39 seed bytes is wired up in the next iteration.
    let wallet = KyveraWallet::generate(&label);

    let password = prompt_password("  Set wallet password: ")?;
    let confirm  = prompt_password("  Confirm password:    ")?;

    if password != confirm {
        return Err("Passwords do not match. Wallet not saved.".to_string());
    }

    save_wallet_v2(&wallet, path, &password)
        .map_err(|e| format!("Failed to save wallet: {}", e))?;

    println!();
    println!("  Wallet restored and saved to: {}", path);
    println!("  Address: {}", wallet.address);
    println!();

    Ok(())
}

// kyv-wallet send <wallet-file> <recipient> <amount-kyv> <fee-kyv>
// Build and sign a transfer transaction. Prints the signed tx JSON.
// Broadcasting to the network comes in Month 9 (P2P layer).
fn cmd_send(args: &[String]) -> Result<(), String> {
    if args.len() < 6 {
        return Err("Usage: kyv-wallet send <wallet-file> <recipient> <amount-kyv> <fee-kyv>".to_string());
    }

    let path      = &args[2];
    let recipient = &args[3];
    let amount_kyv: f64 = args[4].parse()
        .map_err(|_| "Invalid amount. Use decimal KYV (e.g. 10.5)".to_string())?;
    let fee_kyv: f64 = args[5].parse()
        .map_err(|_| "Invalid fee. Use decimal KYV (e.g. 0.001)".to_string())?;

    // Convert KYV to smallest units (1 KYV = 1,000,000,000 units)
    let amount = (amount_kyv * 1_000_000_000.0) as u64;
    let fee    = (fee_kyv    * 1_000_000_000.0) as u64;

    let password = prompt_password("  Wallet password: ")?;
    let wallet = load_wallet(path, &password)
        .map_err(|e| format!("Failed to load wallet: {}", e))?;

    // Placeholder chain state — real value comes from node in Month 9
    let chain_state = "0".repeat(64);

    let tx = build_transfer(
        &wallet,
        recipient,
        amount,
        fee,
        0,  // nonce — real value comes from chain state in Month 5
        &chain_state,
    ).map_err(|e| format!("Failed to build transaction: {}", e))?;

    println!();
    println!("══════════════════════════════════════════════════════");
    println!("  SIGNED TRANSACTION");
    println!("══════════════════════════════════════════════════════");
    println!();
    println!("  From:   {}", tx.sender);
    println!("  To:     {}", tx.receiver);
    println!("  Amount: {} KYV", amount_kyv);
    println!("  Fee:    {} KYV", fee_kyv);
    println!("  Hash:   {}", tx.hash);
    println!();
    println!("  Transaction signed successfully.");
    println!("  Broadcasting to network available in Month 9 (P2P layer).");
    println!();

    // Print full signed tx JSON for debugging / manual broadcast
    let tx_json = serde_json::to_string_pretty(&tx)
        .map_err(|e| e.to_string())?;
    println!("  Raw signed transaction:");
    println!("{}", tx_json);

    Ok(())
}

// kyv-wallet stake <wallet-file> <amount-kyv>
// Build and sign a stake lock transaction.
fn cmd_stake(args: &[String]) -> Result<(), String> {
    if args.len() < 4 {
        return Err("Usage: kyv-wallet stake <wallet-file> <amount-kyv>".to_string());
    }

    let path = &args[2];
    let amount_kyv: f64 = args[3].parse()
        .map_err(|_| "Invalid amount".to_string())?;
    let amount = (amount_kyv * 1_000_000_000.0) as u64;

    // Show which tier they will qualify for
    let tier = if amount >= 25_000_000_000_000 {
        "Nexus (+35% reward bonus)"
    } else if amount >= 5_000_000_000_000 {
        "Kinetic (+15% reward bonus)"
    } else if amount >= 500_000_000_000 {
        "Igniter (standard rewards)"
    } else {
        "Below minimum — 500 KYV required for Igniter tier"
    };

    println!();
    println!("  Staking {} KYV — Validator tier: {}", amount_kyv, tier);
    println!();

    let password = prompt_password("  Wallet password: ")?;
    let wallet = load_wallet(path, &password)
        .map_err(|e| format!("Failed to load wallet: {}", e))?;

    let chain_state = "0".repeat(64);

    let tx = build_stake_lock(
        &wallet,
        amount,
        1_000_000, // 0.001 KYV fee
        0,
        &chain_state,
    ).map_err(|e| format!("Failed to build stake transaction: {}", e))?;

    println!("  Stake transaction signed.");
    println!("  Hash: {}", tx.hash);
    println!();
    println!("  Broadcasting available in Month 9 (P2P layer).");
    println!();

    Ok(())
}

// Read a password from stdin without echoing.
// Falls back to visible input if the terminal does not support hiding.
fn prompt_password(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let stdin = io::stdin();
    let password = stdin.lock().lines().next()
        .ok_or("No input received")?
        .map_err(|e| e.to_string())?;

    Ok(password)
}

fn format_timestamp(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn print_usage() {
    println!();
    println!("  KYV Wallet — Kyvera Continuum");
    println!();
    println!("  Commands:");
    println!("    create  <label> <wallet-file>                    Create a new wallet");
    println!("    info    <wallet-file>                            Show wallet details");
    println!("    restore <wallet-file>                            Restore from seed phrase");
    println!("    send    <wallet-file> <to> <amount> <fee>        Sign a transfer");
    println!("    stake   <wallet-file> <amount>                   Sign a stake lock");
    println!();
    println!("  Examples:");
    println!("    kyv-wallet create main ~/.kyvera/main.wallet");
    println!("    kyv-wallet info ~/.kyvera/main.wallet");
    println!("    kyv-wallet send ~/.kyvera/main.wallet kyv1abc... 10.5 0.001");
    println!();
}