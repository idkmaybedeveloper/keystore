use keystore::{
    Keystore,
    key_parameter::{KeyParameter, Tag, KeyParameterValue},
    crypto::{generate_aes256_key, generate_aes128_key, generate_salt, generate_random_data, hmac_sha256, aes_gcm_encrypt, aes_gcm_decrypt, hkdf_extract, hkdf_expand, Password},
    boot_level_keys::{BootLevelKeyCache, get_level_zero_key},
    permission::{KeyPerm, KeyPermSet, check_key_permission, check_grant_permission},
    utils::{count_key_entries, list_key_entries, uid_to_android_user},
    operation::{Operation, OperationDb, OperationState},
    metrics::Metrics,
    security_level::SecurityLevel,
    database::Domain,
};
use log::{error, info};
use std::io::Write;
use std::ffi::CString;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
            writeln!(
                buf,
                "{}:{} - {}",
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();

    std::panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    info!("Keystore is starting.");

    test_keystore()?;
    test_crypto()?;
    test_boot_level_keys()?;
    test_permission()?;
    test_utils()?;
    test_operation()?;
    test_metrics()?;

    info!("All tests completed successfully.");

    Ok(())
}

fn test_keystore() -> anyhow::Result<()> {
    info!("Testing Keystore...");

    let db_path = std::env::temp_dir().join("keystore_test");
    std::fs::create_dir_all(&db_path)?;

    let db_file = db_path.join("persistent.sqlite");
    if db_file.exists() {
        std::fs::remove_file(&db_file)?;
    }

    let keystore = Keystore::new(db_path)?;

    let params = vec![
        KeyParameter {
            tag: Tag::Algorithm,
            value: KeyParameterValue::Algorithm(1),
        },
        KeyParameter {
            tag: Tag::KeySize,
            value: KeyParameterValue::KeySize(256),
        },
    ];

    let key_blob = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let metadata = keystore.generate_key("test_key", 1000, params.clone(), key_blob.clone())?;
    info!("Generated key with ID: {}", metadata.key_id);

    let retrieved = keystore.get_key("test_key", 1000)?;
    info!("Retrieved key: {} bytes", retrieved.len());

    let operation = keystore.create_operation(metadata.key_id);
    info!("Created operation for key ID: {}", operation.key_id());

    let operation_db = keystore.operation_db();
    info!("Operation DB count: {}", operation_db.count());

    keystore.delete_key("test_key", 1000)?;
    info!("Key deleted successfully");

    Ok(())
}

fn test_crypto() -> anyhow::Result<()> {
    info!("Testing crypto functions...");

    let key256 = generate_aes256_key()?;
    info!("Generated AES-256 key: {} bytes", key256.len());

    let key128 = generate_aes128_key()?;
    info!("Generated AES-128 key: {} bytes", key128.len());

    let salt = generate_salt()?;
    info!("Generated salt: {} bytes", salt.len());

    let random = generate_random_data(32)?;
    info!("Generated random data: {} bytes", random.len());

    let hmac = hmac_sha256(&key256.as_ref(), b"test message")?;
    info!("HMAC-SHA256: {} bytes", hmac.len());

    let plaintext = b"test plaintext data";
    let (ciphertext, iv, tag) = aes_gcm_encrypt(plaintext, key256.as_ref())?;
    info!("AES-GCM encrypted: {} bytes", ciphertext.len());

    let decrypted = aes_gcm_decrypt(&ciphertext, &iv, &tag, key256.as_ref())?;
    info!("AES-GCM decrypted: {} bytes", decrypted.len());
    assert_eq!(decrypted.as_ref(), plaintext);

    let prk = hkdf_extract(b"secret", &salt)?;
    info!("HKDF extract: {} bytes", prk.len());

    let expanded = hkdf_expand(32, &prk, b"info")?;
    info!("HKDF expand: {} bytes", expanded.len());

    let password = Password::Ref(b"test_password_1234567890123456");
    let derived_pbkdf2 = password.derive_key_pbkdf2(&salt, 32)?;
    info!("PBKDF2 derived key: {} bytes", derived_pbkdf2.len());

    let derived_hkdf = password.derive_key_hkdf(&salt, 32)?;
    info!("HKDF derived key: {} bytes", derived_hkdf.len());

    Ok(())
}

fn test_boot_level_keys() -> anyhow::Result<()> {
    info!("Testing boot level keys...");

    let mut cache = BootLevelKeyCache::new();
    let key1 = cache.get_or_create_key(0)?;
    info!("Boot level key 0: {} bytes", key1.len());

    let key2 = cache.get_or_create_key(0)?;
    assert_eq!(key1.as_ref(), key2.as_ref());

    let key3 = cache.get_or_create_key(1)?;
    info!("Boot level key 1: {} bytes", key3.len());
    assert_ne!(key1.as_ref(), key3.as_ref());

    cache.clear();
    let key4 = cache.get_or_create_key(0)?;
    assert_ne!(key1.as_ref(), key4.as_ref());

    let level_key = get_level_zero_key(SecurityLevel::Software)?;
    info!("Level zero key: {} bytes", level_key.len());

    Ok(())
}

fn test_permission() -> anyhow::Result<()> {
    info!("Testing permission functions...");

    let perm = KeyPerm::Delete;
    info!("KeyPerm name: {}", perm.name());

    let set1 = KeyPermSet::from(KeyPerm::Use);
    let set2 = KeyPermSet::from(KeyPerm::Use as i32 | KeyPerm::Delete as i32);
    assert!(set2.includes(set1));
    assert!(!set1.includes(set2));

    let perms: Vec<_> = set2.iter().collect();
    info!("KeyPermSet iter: {} permissions", perms.len());

    let key_desc = keystore::database::KeyDescriptor {
        domain: Domain::App,
        namespace: 1000,
        alias: Some("test_key".to_string()),
    };

    let ctx = CString::new("test_context")?;
    check_key_permission(1000, &ctx, KeyPerm::Use, &key_desc, &None)?;

    let access_vec = Some(KeyPermSet::from(KeyPerm::Use));
    check_key_permission(1000, &ctx, KeyPerm::Use, &key_desc, &access_vec)?;

    check_grant_permission(1000, &ctx, KeyPermSet::from(KeyPerm::Use), &key_desc)?;

    Ok(())
}

fn test_utils() -> anyhow::Result<()> {
    info!("Testing utils functions...");

    let entries = vec![
        ("key1".to_string(), vec![]),
        ("key2".to_string(), vec![]),
        ("key1".to_string(), vec![]),
    ];
    let counts = count_key_entries(&entries);
    info!("Count key entries: {:?}", counts);
    assert_eq!(counts.get("key1"), Some(&2));
    assert_eq!(counts.get("key2"), Some(&1));

    let listed = list_key_entries(&entries, None, None);
    info!("List key entries: {} entries", listed.len());

    let listed_filtered = list_key_entries(&entries, Some("key1"), Some(1));
    info!("List key entries filtered: {} entries", listed_filtered.len());

    let user = uid_to_android_user(100000);
    info!("UID to Android user: {}", user);
    assert_eq!(user, 1);

    Ok(())
}

fn test_operation() -> anyhow::Result<()> {
    info!("Testing operation functions...");

    let op = Operation::new(123);
    assert_eq!(op.key_id(), 123);
    assert_eq!(op.state(), OperationState::Unknown);

    op.set_state(OperationState::Success);
    assert_eq!(op.state(), OperationState::Success);

    op.update_usage();
    let age = op.age();
    info!("Operation age: {:?}", age);

    let op_db = OperationDb::new();
    assert_eq!(op_db.count(), 0);

    let op_arc = std::sync::Arc::new(op);
    op_db.add_operation(&op_arc);
    assert_eq!(op_db.count(), 1);

    let op2 = Operation::new(456);
    let op2_arc = std::sync::Arc::new(op2);
    op_db.add_operation(&op2_arc);
    assert_eq!(op_db.count(), 2);

    std::thread::sleep(Duration::from_millis(10));
    let pruned = op_db.prune_oldest();
    assert!(pruned.is_some());
    if let Some(p) = pruned {
        assert_eq!(p.state(), OperationState::Pruned);
    }

    Ok(())
}

fn test_metrics() -> anyhow::Result<()> {
    info!("Testing metrics functions...");

    let metrics = Metrics::new();
    metrics.record("test_metric", 1.0);
    metrics.record("test_metric", 2.0);
    metrics.record("other_metric", 3.0);

    let test_metrics = metrics.get_metrics("test_metric");
    info!("Test metrics count: {}", test_metrics.len());
    assert_eq!(test_metrics.len(), 2);

    let all_metrics = metrics.get_all_metrics();
    info!("All metrics keys: {}", all_metrics.len());
    assert_eq!(all_metrics.len(), 2);

    metrics.clear_old_metrics(Duration::from_secs(1));
    let cleared = metrics.get_metrics("test_metric");
    info!("Metrics after clear: {}", cleared.len());

    Ok(())
}