use keystore::{
    Keystore,
    boot_level_keys::{BootLevelKeyCache, get_level_zero_key},
    crypto::{
        Password, aes_gcm_decrypt, aes_gcm_encrypt, generate_aes128_key, generate_aes256_key,
        generate_random_data, generate_salt, hkdf_expand, hkdf_extract, hmac_sha256,
    },
    database::Domain,
    key_parameter::{KeyParameter, KeyParameterValue, Tag},
    metrics::Metrics,
    operation::{Operation, OperationDb, OperationState},
    permission::{KeyPerm, KeyPermSet, check_grant_permission, check_key_permission},
    security_level::SecurityLevel,
    utils::{count_key_entries, list_key_entries, uid_to_android_user},
};
use log::{error, info};
use std::ffi::CString;
use std::io::Write;
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
    test_crypto_edge_cases()?;
    test_crypto_error_handling()?;
    test_keystore_multiple_keys()?;
    test_keystore_namespaces()?;
    test_boot_level_keys()?;
    test_permission()?;
    test_utils()?;
    test_operation()?;
    test_operation_concurrency()?;
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
        KeyParameter { tag: Tag::Algorithm, value: KeyParameterValue::Algorithm(1) },
        KeyParameter { tag: Tag::KeySize, value: KeyParameterValue::KeySize(256) },
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

fn test_crypto_edge_cases() -> anyhow::Result<()> {
    info!("Testing crypto edge cases...");

    let key = generate_aes256_key()?;
    let empty: Vec<u8> = vec![];
    let (ciphertext, iv, tag) = aes_gcm_encrypt(&empty, key.as_ref())?;
    let decrypted = aes_gcm_decrypt(&ciphertext, &iv, &tag, key.as_ref())?;
    assert_eq!(decrypted.as_ref(), empty.as_slice());
    info!("Empty plaintext encryption: OK");
    let large_data = vec![0xABu8; 1024 * 1024];
    let (ciphertext, iv, tag) = aes_gcm_encrypt(&large_data, key.as_ref())?;
    let decrypted = aes_gcm_decrypt(&ciphertext, &iv, &tag, key.as_ref())?;
    assert_eq!(decrypted.as_ref(), large_data.as_slice());
    info!("Large plaintext (1MB) encryption: OK");
    let key128 = generate_aes128_key()?;
    let key256 = generate_aes256_key()?;
    let plaintext: Vec<u8> = b"test data for key size comparison".to_vec();

    let (ct128, iv128, tag128) = aes_gcm_encrypt(&plaintext, key128.as_ref())?;
    let (ct256, iv256, tag256) = aes_gcm_encrypt(&plaintext, key256.as_ref())?;

    assert_eq!(ct128.len(), ct256.len());
    assert_ne!(ct128, ct256);
    info!("AES-128 vs AES-256 produce different ciphertexts: OK");

    let dec128 = aes_gcm_decrypt(&ct128, &iv128, &tag128, key128.as_ref())?;
    let dec256 = aes_gcm_decrypt(&ct256, &iv256, &tag256, key256.as_ref())?;
    assert_eq!(dec128.as_ref(), plaintext.as_slice());
    assert_eq!(dec256.as_ref(), plaintext.as_slice());
    info!("Both key sizes decrypt correctly: OK");

    let hmac_msg: Vec<u8> = b"same message".to_vec();
    let hmac1 = hmac_sha256(key.as_ref(), &hmac_msg)?;
    let hmac2 = hmac_sha256(key.as_ref(), &hmac_msg)?;
    assert_eq!(hmac1, hmac2);
    info!("HMAC is deterministic: OK");

    let hmac_msg2: Vec<u8> = b"different message".to_vec();
    let hmac3 = hmac_sha256(key.as_ref(), &hmac_msg2)?;
    assert_ne!(hmac1, hmac3);
    info!("HMAC differs for different messages: OK");

    let salt = generate_salt()?;
    let pw_bytes: Vec<u8> = b"test_password_determinism_12345".to_vec();
    let password = Password::Ref(&pw_bytes);
    let derived1 = password.derive_key_pbkdf2(&salt, 32)?;
    let derived2 = password.derive_key_pbkdf2(&salt, 32)?;
    assert_eq!(derived1.as_ref(), derived2.as_ref());
    info!("PBKDF2 derivation is deterministic: OK");

    let salt2 = generate_salt()?;
    let derived3 = password.derive_key_pbkdf2(&salt2, 32)?;
    assert_ne!(derived1.as_ref(), derived3.as_ref());
    info!("Different salts produce different derived keys: OK");

    let random1 = generate_random_data(32)?;
    let random2 = generate_random_data(32)?;
    assert_ne!(random1, random2);
    info!("Random data is unique: OK");

    Ok(())
}

fn test_crypto_error_handling() -> anyhow::Result<()> {
    info!("Testing crypto error handling...");

    let key = generate_aes256_key()?;
    let plaintext: Vec<u8> = b"test plaintext".to_vec();
    let (ciphertext, iv, tag) = aes_gcm_encrypt(&plaintext, key.as_ref())?;

    let wrong_key = generate_aes256_key()?;
    let result = aes_gcm_decrypt(&ciphertext, &iv, &tag, wrong_key.as_ref());
    assert!(result.is_err());
    info!("Wrong key decryption fails: OK");

    let mut tampered_ct = ciphertext.clone();
    if !tampered_ct.is_empty() {
        tampered_ct[0] ^= 0xFF;
    }
    let result = aes_gcm_decrypt(&tampered_ct, &iv, &tag, key.as_ref());
    assert!(result.is_err());
    info!("Tampered ciphertext decryption fails: OK");

    let mut tampered_iv = iv.clone();
    tampered_iv[0] ^= 0xFF;
    let result = aes_gcm_decrypt(&ciphertext, &tampered_iv, &tag, key.as_ref());
    assert!(result.is_err());
    info!("Tampered IV decryption fails: OK");

    let mut tampered_tag = tag.clone();
    tampered_tag[0] ^= 0xFF;
    let result = aes_gcm_decrypt(&ciphertext, &iv, &tampered_tag, key.as_ref());
    assert!(result.is_err());
    info!("Tampered tag decryption fails: OK");

    let short_iv = vec![0u8; 8];
    let result = aes_gcm_decrypt(&ciphertext, &short_iv, &tag, key.as_ref());
    assert!(result.is_err());
    info!("Invalid IV length rejected: OK");

    let short_tag = vec![0u8; 8];
    let result = aes_gcm_decrypt(&ciphertext, &iv, &short_tag, key.as_ref());
    assert!(result.is_err());
    info!("Invalid tag length rejected: OK");

    let invalid_key = vec![0u8; 24]; // neither 16 nor 32 bytes
    let result = aes_gcm_encrypt(&plaintext, &invalid_key);
    assert!(result.is_err());
    info!("Invalid key length rejected: OK");

    let pw_bytes: Vec<u8> = b"test_password_invalid_salt_1234".to_vec();
    let password = Password::Ref(&pw_bytes);
    let invalid_salt = vec![0u8; 8];
    let result = password.derive_key_pbkdf2(&invalid_salt, 32);
    assert!(result.is_err());
    info!("Invalid salt length for PBKDF2 rejected: OK");

    // Test invalid output length for PBKDF2
    let valid_salt = generate_salt()?;
    let result = password.derive_key_pbkdf2(&valid_salt, 24);
    assert!(result.is_err());
    info!("Invalid output length for PBKDF2 rejected: OK");

    Ok(())
}

fn test_keystore_multiple_keys() -> anyhow::Result<()> {
    info!("Testing keystore with multiple keys...");

    let db_path = std::env::temp_dir().join("keystore_multi_test");
    std::fs::create_dir_all(&db_path)?;
    let db_file = db_path.join("persistent.sqlite");
    if db_file.exists() {
        std::fs::remove_file(&db_file)?;
    }

    let keystore = Keystore::new(&db_path)?;

    let keys_data = vec![
        (
            "aes_key_1",
            vec![KeyParameter {
                tag: Tag::Algorithm,
                value: KeyParameterValue::Algorithm(32), // AES
            }],
            vec![1u8; 16],
        ),
        (
            "aes_key_2",
            vec![KeyParameter { tag: Tag::Algorithm, value: KeyParameterValue::Algorithm(32) }],
            vec![2u8; 32],
        ),
        (
            "rsa_key_1",
            vec![KeyParameter {
                tag: Tag::Algorithm,
                value: KeyParameterValue::Algorithm(1), // RSA
            }],
            vec![3u8; 64],
        ),
        (
            "ec_key_1",
            vec![KeyParameter {
                tag: Tag::Algorithm,
                value: KeyParameterValue::Algorithm(3), // EC
            }],
            vec![4u8; 48],
        ),
    ];

    let mut created_ids = Vec::new();
    for (alias, params, blob) in &keys_data {
        let metadata = keystore.generate_key(alias, 1000, params.clone(), blob.clone())?;
        created_ids.push(metadata.key_id);
        info!("Created key '{}' with ID: {}", alias, metadata.key_id);
    }

    for (alias, _, original_blob) in &keys_data {
        let retrieved = keystore.get_key(alias, 1000)?;
        assert_eq!(&retrieved, original_blob);
        info!("Retrieved key '{}': {} bytes, matches original", alias, retrieved.len());
    }

    for (alias, _, _) in keys_data.iter().rev() {
        keystore.delete_key(alias, 1000)?;
        info!("Deleted key '{}'", alias);

        // Verify key is actually deleted
        let result = keystore.get_key(alias, 1000);
        assert!(result.is_err());
    }

    info!("Multiple keys test: OK");
    Ok(())
}

fn test_keystore_namespaces() -> anyhow::Result<()> {
    info!("Testing keystore namespace isolation...");

    let db_path = std::env::temp_dir().join("keystore_ns_test");
    std::fs::create_dir_all(&db_path)?;
    let db_file = db_path.join("persistent.sqlite");
    if db_file.exists() {
        std::fs::remove_file(&db_file)?;
    }

    let keystore = Keystore::new(&db_path)?;
    let params =
        vec![KeyParameter { tag: Tag::Algorithm, value: KeyParameterValue::Algorithm(32) }];

    let blob_ns1 = vec![0x11u8; 16];
    let blob_ns2 = vec![0x22u8; 16];
    let blob_ns3 = vec![0x33u8; 16];

    keystore.generate_key("shared_alias", 1000, params.clone(), blob_ns1.clone())?;
    keystore.generate_key("shared_alias", 2000, params.clone(), blob_ns2.clone())?;
    keystore.generate_key("shared_alias", 3000, params.clone(), blob_ns3.clone())?;

    info!("Created 3 keys with same alias in different namespaces");

    let retrieved_ns1 = keystore.get_key("shared_alias", 1000)?;
    let retrieved_ns2 = keystore.get_key("shared_alias", 2000)?;
    let retrieved_ns3 = keystore.get_key("shared_alias", 3000)?;

    assert_eq!(retrieved_ns1, blob_ns1);
    assert_eq!(retrieved_ns2, blob_ns2);
    assert_eq!(retrieved_ns3, blob_ns3);
    info!("Namespace isolation verified: each returns correct key");
    keystore.delete_key("shared_alias", 1000)?;
    assert!(keystore.get_key("shared_alias", 1000).is_err());
    assert_eq!(keystore.get_key("shared_alias", 2000)?, blob_ns2);
    assert_eq!(keystore.get_key("shared_alias", 3000)?, blob_ns3);
    info!("Delete in one namespace doesn't affect others: OK");
    keystore.delete_key("shared_alias", 2000)?;
    keystore.delete_key("shared_alias", 3000)?;

    info!("Namespace isolation test: OK");
    Ok(())
}

fn test_operation_concurrency() -> anyhow::Result<()> {
    info!("Testing operation concurrency...");

    use std::sync::{Arc, Mutex};
    use std::thread;

    let op_db = Arc::new(OperationDb::new());
    let num_threads = 10;
    let ops_per_thread = 100;
    let all_operations: Arc<Mutex<Vec<Arc<Operation>>>> = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let op_db = Arc::clone(&op_db);
            let all_ops = Arc::clone(&all_operations);
            thread::spawn(move || {
                let mut local_ops = Vec::new();
                for i in 0..ops_per_thread {
                    let key_id = (thread_id * ops_per_thread + i) as i64;
                    let op = Arc::new(Operation::new(key_id));
                    op_db.add_operation(&op);
                    local_ops.push(op);
                }
                all_ops.lock().unwrap().extend(local_ops);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let total_expected = num_threads * ops_per_thread;
    let actual_count = op_db.count();
    info!("Concurrent operation adds: expected {}, got {}", total_expected, actual_count);
    assert_eq!(actual_count, total_expected);
    assert_eq!(all_operations.lock().unwrap().len(), total_expected);

    // Test concurrent pruning with a limit (prune_oldest doesn't remove from Vec,
    // so we can't loop until None - that would be infinite)
    let prune_limit = 100;
    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let op_db = Arc::clone(&op_db);
            thread::spawn(move || {
                let mut local_pruned = 0;
                for _ in 0..prune_limit {
                    if op_db.prune_oldest().is_some() {
                        local_pruned += 1;
                    }
                }
                local_pruned
            })
        })
        .collect();

    let mut total_pruned = 0;
    for handle in handles {
        total_pruned += handle.join().expect("Thread panicked");
    }

    info!("Concurrent pruning: {} prune calls completed without panics", total_pruned);

    // Drop all operations to test cleanup
    drop(all_operations);

    // After dropping all Arc<Operation>, Weak refs become invalid
    // count() should return 0
    let final_count = op_db.count();
    info!("After dropping all operations, count = {}", final_count);
    assert_eq!(final_count, 0);

    info!("Operation concurrency test: OK (no race conditions detected)");
    Ok(())
}
