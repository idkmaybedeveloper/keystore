use crate::error::ResponseCode;
use log::info;

pub fn log_key_deleted(alias: &str, namespace: i64) {
    info!("Key deleted: alias={}, namespace={}", alias, namespace);
}

pub fn log_key_generated(alias: &str, namespace: i64, key_id: i64) {
    info!("Key generated: alias={}, namespace={}, key_id={}", alias, namespace, key_id);
}

pub fn log_key_imported(alias: &str, namespace: i64, key_id: i64) {
    info!("Key imported: alias={}, namespace={}, key_id={}", alias, namespace, key_id);
}

pub fn log_key_integrity_violation(alias: &str, namespace: i64, reason: &str) {
    log::warn!(
        "Key integrity violation: alias={}, namespace={}, reason={}",
        alias,
        namespace,
        reason
    );
}

pub fn log_operation_started(operation_id: i64, key_id: i64) {
    info!("Operation started: operation_id={}, key_id={}", operation_id, key_id);
}

pub fn log_operation_finished(operation_id: i64, key_id: i64, result: Result<(), ResponseCode>) {
    match result {
        Ok(()) => info!("Operation finished: operation_id={}, key_id={}", operation_id, key_id),
        Err(code) => log::warn!(
            "Operation failed: operation_id={}, key_id={}, error={:?}",
            operation_id,
            key_id,
            code
        ),
    }
}
