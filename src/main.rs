use std::error::Error;
use serde::{Serialize, Deserialize};

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::Arc;
use log::{warn};

use prew::{RewriteReverseProxy, PostgresqlProcessor, PacketRules};

#[derive(Debug, Serialize, Deserialize)]
struct AppendInfo {
    append: String
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag="mode")]
enum ProxyMode {
    Passthru,
    DbAppend(AppendInfo),
}

#[derive(Debug, Serialize, Deserialize)]
struct PrewConfig {
    bind_addr: String,
    server_addr: String,
    mode: ProxyMode,
}

impl Default for PrewConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:6432".to_string(),
            server_addr: "0.0.0.0:5432".to_string(),
            mode: ProxyMode::DbAppend(AppendInfo{append: "_abcd".to_string()}),
        }
    }
}



fn write_default_config() -> Result<PrewConfig, Box<dyn Error>> {
    let config = PrewConfig::default();
    let s = toml::to_string_pretty(&config)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("prew.toml")?;
    f.write_all(s.as_bytes())?;
    Ok(config)
}


fn read_config() -> Result<PrewConfig, Box<dyn Error>> {
    let path = "prew.toml";
    let cfg_data: PrewConfig;
    match File::open(path) {
        Ok(mut cfg_file) => {
            let mut cfg_string = String::new();
            cfg_file.read_to_string(&mut cfg_string)?;
            cfg_data = toml::from_str(&cfg_string)?;
        }
        Err(e)=> {
            warn!("Couldn't find config file; writing out default: {}", e);
            cfg_data = write_default_config()?;
        }
    }
    Ok(cfg_data)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    env_logger::init();
    let config = read_config()?;
    // let (_tx, rx) = oneshot::channel();
    // let processor = PostgresqlProcessor::passthru();
    if let ProxyMode::DbAppend(appendinfo) = config.mode {
        let mut proxy = RewriteReverseProxy::new();
        let processor = PostgresqlProcessor::appenddbname(appendinfo.append);
        let rules = PacketRules {
            bind_addr: config.bind_addr,
            server_addr: config.server_addr,
            processor: Arc::new(processor),
        };
        proxy.add_proxy(Box::new(rules)).await;
        proxy.run().await;
    } else if let ProxyMode::Passthru = config.mode {
        let mut proxy = RewriteReverseProxy::new();
        let processor = PostgresqlProcessor::passthru();
        let rules = PacketRules {
            bind_addr: config.bind_addr,
            server_addr: config.server_addr,
            processor: Arc::new(processor),
        };
        proxy.add_proxy(Box::new(rules)).await;
        proxy.run().await;
    }
    Ok(())
}
