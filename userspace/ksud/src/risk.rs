use crate::assets;
use crate::defs;
use const_format::concatcp;
use log::warn;
use serde::Deserialize;
use std::path::Path;
use std::process::Command;
use unicode_normalization::UnicodeNormalization;

const DEFAULT_RISK_JSON: &str = include_str!("../../../risk/risk.json");
const REMOTE_RISK_URL: &str =
    "https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/risk/risk/risk.json";
const RISK_CACHE_PATH: &str = concatcp!(defs::CACHE_DIR, "risk.json");
const RISK_FETCH_TIMEOUT_SECONDS: &str = "10";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Extreme,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RiskGroup {
    pub reason: String,
    pub severity: RiskSeverity,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskMatch {
    pub reason: String,
    pub severity: RiskSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RiskCatalog {
    hash: String,
    rules: Vec<RiskGroup>,
}

fn parse_risk_catalog(json: &[u8]) -> Result<RiskCatalog, serde_json::Error> {
    serde_json::from_slice(json)
}

pub fn should_update_risk_cache(local_json: &[u8], remote_json: &[u8]) -> bool {
    let Ok(remote) = parse_risk_catalog(remote_json) else {
        return false;
    };
    let Ok(local) = parse_risk_catalog(local_json) else {
        return true;
    };

    local.hash != remote.hash
}

fn fetch_remote_risk_json() -> Option<Vec<u8>> {
    let output = Command::new(assets::BUSYBOX_PATH)
        .args([
            "timeout",
            RISK_FETCH_TIMEOUT_SECONDS,
            assets::BUSYBOX_PATH,
            "wget",
            "-q",
            "-O",
            "-",
            "--",
            REMOTE_RISK_URL,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        warn!("Failed to fetch risk rules from {REMOTE_RISK_URL}");
        return None;
    }

    if let Err(err) = parse_risk_catalog(&output.stdout) {
        warn!("Ignoring invalid risk rules fetched from {REMOTE_RISK_URL}: {err}");
        return None;
    }

    Some(output.stdout)
}

fn select_risk_json(local: Option<Vec<u8>>, remote: Option<Vec<u8>>) -> (Vec<u8>, bool) {
    let valid_local = local.filter(|local| parse_risk_catalog(local).is_ok());
    let valid_remote = remote.filter(|remote| parse_risk_catalog(remote).is_ok());

    match (valid_local, valid_remote) {
        (Some(local), Some(remote)) => {
            if should_update_risk_cache(&local, &remote) {
                (remote, true)
            } else {
                (local, false)
            }
        }
        (Some(local), None) => (local, false),
        (None, Some(remote)) => (remote, true),
        (None, None) => (DEFAULT_RISK_JSON.as_bytes().to_vec(), false),
    }
}

fn load_risk_json() -> Vec<u8> {
    let cache_path = Path::new(RISK_CACHE_PATH);
    if let Err(err) = crate::utils::ensure_dir_exists(defs::CACHE_DIR) {
        warn!("Failed to ensure risk cache dir exists: {err}");
    }

    let (selected, should_cache) =
        select_risk_json(std::fs::read(cache_path).ok(), fetch_remote_risk_json());
    if should_cache && let Err(err) = std::fs::write(cache_path, &selected) {
        warn!(
            "Failed to update risk cache at {}: {err}",
            cache_path.display()
        );
    }
    selected
}

pub fn contains_risk(module_prop: &str) -> Option<RiskMatch> {
    let risk_json = load_risk_json();
    let risk: Vec<RiskGroup> = match parse_risk_catalog(&risk_json) {
        Ok(catalog) => catalog.rules,
        Err(err) => {
            warn!("Failed to parse risk catalog from cache: {err}. Falling back to bundled rules.");
            serde_json::from_str::<RiskCatalog>(DEFAULT_RISK_JSON)
                .map(|catalog| catalog.rules)
                .unwrap_or_default()
        }
    };

    find_risk_match(module_prop, &risk)
}

fn find_risk_match(module_prop: &str, risk: &[RiskGroup]) -> Option<RiskMatch> {
    let normalized_properties: Vec<String> = normalize_risk_text(module_prop)
        .split_whitespace()
        .map(str::to_owned)
        .collect();

    risk.iter()
        .filter(|group| {
            group.patterns.iter().any(|pattern| {
                let normalized_pattern: Vec<String> = normalize_risk_text(pattern)
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect();
                !normalized_pattern.is_empty()
                    && normalized_properties
                        .windows(normalized_pattern.len())
                        .any(|window| window == normalized_pattern.as_slice())
            })
        })
        .map(|group| RiskMatch {
            reason: group.reason.clone(),
            severity: group.severity,
        })
        .reduce(|best, candidate| {
            if candidate.severity > best.severity {
                candidate
            } else {
                best
            }
        })
}

fn build_risk_block_message(severity: RiskSeverity, reason: &str) -> String {
    format!(
        "\n❌ Installation Blocked\n┌────────────────────────────────\n│ Module flagged by a security rule\n│\n│ Severity: {severity:?}\n│ Reason: {reason}\n└─────────────────────────────────\n"
    )
}

pub fn print_risk_block(severity: RiskSeverity, reason: &str) {
    print!("{}", build_risk_block_message(severity, reason));
}

fn build_risk_timeout_block_message() -> String {
    "\n❌ Installation Stopped\n┌────────────────────────────────\n│ Permission confirmation timed out\n│ Module installation was not confirmed in time.\n└─────────────────────────────────\n"
        .to_owned()
}

pub fn print_risk_timeout_block() {
    print!("{}", build_risk_timeout_block_message());
}

fn build_risk_pause_prompt_message(severity: RiskSeverity, reason: &str) -> String {
    format!(
        "\n⚠️  Installation Paused\n┌────────────────────────────────\n│ Module flagged by a security rule\n│\n│ Severity: {severity:?}\n│ Reason: {reason}\n│\n│ Press the volume-down key within 5 seconds to continue.\n└─────────────────────────────────\n"
    )
}

pub fn print_risk_pause_prompt(severity: RiskSeverity, reason: &str) {
    print!("{}", build_risk_pause_prompt_message(severity, reason));
}

fn normalize_risk_text(text: &str) -> String {
    text.nfkc()
        .flat_map(char::to_lowercase)
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_cache_diff_detects_change() {
        let local =
            br#"{"hash":"abc","rules":[{"reason":"demo","severity":"low","patterns":["alpha"]}]}"#;
        let remote_same =
            br#"{"hash":"abc","rules":[{"reason":"demo","severity":"low","patterns":["alpha"]}]}"#;
        let remote_diff =
            br#"{"hash":"def","rules":[{"reason":"demo","severity":"low","patterns":["beta"]}]}"#;

        assert!(!should_update_risk_cache(local, remote_same));
        assert!(should_update_risk_cache(local, remote_diff));
    }

    #[test]
    fn invalid_remote_risk_cache_is_never_selected() {
        let local = br#"{"hash":"abc","rules":[]}"#;
        let invalid_remote = br#"{"hash":"def","rules":not-json}"#;
        let invalid_local = br#"not-json"#;
        let valid_remote = br#"{"hash":"def","rules":[]}"#;

        assert!(!should_update_risk_cache(local, invalid_remote));
        assert!(should_update_risk_cache(invalid_local, valid_remote));
    }

    #[test]
    fn valid_remote_replaces_invalid_cache() {
        let invalid_local = br#"not-json"#.to_vec();
        let valid_remote = br#"{"hash":"def","rules":[]}"#.to_vec();

        let (selected, should_cache) =
            select_risk_json(Some(invalid_local), Some(valid_remote.clone()));
        assert_eq!(selected, valid_remote);
        assert!(should_cache);
    }

    #[test]
    fn remote_failure_keeps_valid_cache() {
        let valid_local = br#"{"hash":"abc","rules":[]}"#.to_vec();

        let (selected, should_cache) = select_risk_json(Some(valid_local.clone()), None);
        assert_eq!(selected, valid_local);
        assert!(!should_cache);
    }

    #[test]
    fn invalid_inputs_fall_back_to_bundled_rules() {
        let invalid_local = br#"not-json"#.to_vec();
        let invalid_remote = br#"{"hash":"def","rules":not-json}"#.to_vec();

        let (selected, should_cache) = select_risk_json(Some(invalid_local), Some(invalid_remote));
        assert_eq!(selected.as_slice(), DEFAULT_RISK_JSON.as_bytes());
        assert!(!should_cache);
    }

    #[test]
    fn highest_matching_severity_wins() {
        let rules = vec![
            RiskGroup {
                reason: "generic match".to_owned(),
                severity: RiskSeverity::Low,
                patterns: vec!["demo module".to_owned()],
            },
            RiskGroup {
                reason: "critical match".to_owned(),
                severity: RiskSeverity::Extreme,
                patterns: vec!["dangerous payload".to_owned()],
            },
        ];

        let matched = find_risk_match("name=Demo Module Dangerous Payload", &rules).unwrap();
        assert_eq!(matched.severity, RiskSeverity::Extreme);
        assert_eq!(matched.reason, "critical match");
    }

    #[test]
    fn timeout_block_omits_duplicate_risk_details() {
        let message = build_risk_timeout_block_message();

        assert!(message.contains("Installation Stopped"));
        assert!(!message.contains("Severity:"));
        assert!(!message.contains("Reason:"));
    }
}
