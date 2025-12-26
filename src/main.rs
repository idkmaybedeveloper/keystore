use keystore::{
    Keystore,
    key_parameter::{KeyParameter, Tag},
};
use log::{error, info};
use std::io::Write;

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

    let db_path = std::env::temp_dir().join("keystore_test");
    std::fs::create_dir_all(&db_path)?;

    let db_file = db_path.join("persistent.sqlite");
    if db_file.exists() {
        info!("Removing existing database file");
        std::fs::remove_file(&db_file)?;
    }

    let keystore = Keystore::new(db_path)?;

    let params = vec![
        KeyParameter {
            tag: Tag::Algorithm,
            value: keystore::key_parameter::KeyParameterValue::Algorithm(1),
        },
        KeyParameter {
            tag: Tag::KeySize,
            value: keystore::key_parameter::KeyParameterValue::KeySize(256),
        },
    ];

    let key_blob = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let metadata = keystore.generate_key("test_key", 1000, params.clone(), key_blob.clone())?;
    info!("Generated key with ID: {}", metadata.key_id);

    let retrieved = keystore.get_key("test_key", 1000)?;
    info!("Retrieved key: {:?}", retrieved);

    keystore.delete_key("test_key", 1000)?;
    info!("Key deleted successfully");

    Ok(())
}
