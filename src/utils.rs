use crate::key_parameter::KeyParameter;
use std::collections::HashMap;

pub fn count_key_entries(entries: &[(String, Vec<KeyParameter>)]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for (alias, _) in entries {
        *counts.entry(alias.clone()).or_insert(0) += 1;
    }
    counts
}

pub fn list_key_entries(
    entries: &[(String, Vec<KeyParameter>)],
    start_after: Option<&str>,
    count: Option<usize>,
) -> Vec<(String, Vec<KeyParameter>)> {
    let mut result: Vec<_> = entries
        .iter()
        .filter(
            |(alias, _)| if let Some(start) = start_after { alias.as_str() > start } else { true },
        )
        .cloned()
        .collect();

    result.sort_by_key(|(alias, _)| alias.clone());

    if let Some(limit) = count {
        result.truncate(limit);
    }

    result
}

pub fn uid_to_android_user(uid: u32) -> u32 {
    uid / 100000
}

pub fn log_security_safe_params(params: &[KeyParameter]) {
    log::debug!("Security safe parameters: {:?}", params);
}
