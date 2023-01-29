use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::Arc;

use serde::{Serialize, Deserialize};
use anyhow::{anyhow, Result};
use futures::lock::Mutex;
use log::{warn, info};

use prew::{RewriteReverseProxy, PacketRules, RuleSetProcessor, NoFilter, MessageEncoder};
use prew::{PostgresParser, AppendDbNameTransformer, NoReport, NoTransform, PacketProcessor};
use prew::rule::{DefaultContext};
// use prew::{Parser, Filter, Transformer, Encoder, Reporter};

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



fn write_default_config() -> Result<PrewConfig> {
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


fn read_config() -> Result<PrewConfig> {
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
async fn main() -> Result<()>{
    env_logger::init();
    let mut config = read_config()?;
    if let Ok(bind_addr) = env::var("PREW_BIND_ADDR") {
        info!("Overriding bind address: {}", &bind_addr);
        config.bind_addr = bind_addr;
    }
    if let Ok(server_addr) = env::var("PREW_SERVER_ADDR") {
        info!("Overriding server address: {}", &server_addr);
        config.server_addr = server_addr;
    }
    // let (_tx, rx) = oneshot::channel();
    // let processor = PostgresqlProcessor::passthru();
    let mut proxy = RewriteReverseProxy::new();

    let processor: Arc<Mutex<dyn PacketProcessor + Send>>;
    if let ProxyMode::DbAppend(appendinfo) = config.mode {
        let rules = RuleSetProcessor::new(
            &PostgresParser::new(),
            &NoFilter::new(),
            &AppendDbNameTransformer::new(appendinfo.append),
            &MessageEncoder::new(),
            &NoReport::new(),
            &DefaultContext::new
        );
        processor = Arc::new(Mutex::new(rules));
    } else if let ProxyMode::Passthru = config.mode {
        let rules = RuleSetProcessor::new(
            &PostgresParser::new(),
            &NoFilter::new(),
            &NoTransform::new(),
            &MessageEncoder::new(),
            &NoReport::new(),
            &DefaultContext::new
        );
        processor = Arc::new(Mutex::new(rules));
    } else {
        return Err(anyhow!("Unknown config mode: {:?}", config.mode));
    }

    let rules = PacketRules {
        bind_addr: config.bind_addr,
        server_addr: config.server_addr,
        processor,
    };
    proxy.add_proxy(Box::new(rules)).await;
    info!("Starting proxy");
    proxy.run().await;
    Ok(())
}
