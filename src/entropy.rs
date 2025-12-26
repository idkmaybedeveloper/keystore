use crate::crypto::generate_random_data;
use anyhow::{Context, Result};
use log::error;
use std::time::{Duration, Instant};

const ENTROPY_SIZE: usize = 64;
const MIN_FEED_INTERVAL_SECS: u64 = 30;

#[derive(Default)]
struct FeederInfo {
    last_feed: Option<Instant>,
}

pub struct EntropyFeeder {
    info: FeederInfo,
}

impl EntropyFeeder {
    pub fn new() -> Self {
        Self { info: FeederInfo::default() }
    }

    pub fn should_feed(&self) -> bool {
        let now = Instant::now();
        match self.info.last_feed {
            None => true,
            Some(last) => now.duration_since(last) > Duration::from_secs(MIN_FEED_INTERVAL_SECS),
        }
    }

    pub fn feed(&mut self) {
        self.info.last_feed = Some(Instant::now());
    }
}

impl Default for EntropyFeeder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_entropy(size: usize) -> Result<Vec<u8>> {
    generate_random_data(size).context("Retrieving entropy")
}

pub fn feed_entropy_to_devices(_devices: usize) {
    if _devices == 0 {
        return;
    }
    let data = match get_entropy(_devices * ENTROPY_SIZE) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to retrieve {}*{} bytes of entropy: {:?}", _devices, ENTROPY_SIZE, e);
            return;
        }
    };
    log::debug!("Generated {} bytes of entropy", data.len());
}
