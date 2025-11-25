use anyhow::{Context as _, Result, anyhow, bail};
use clap::{ArgAction, Parser};
use env_logger::Env;
use log::{debug, info, trace, warn};
use reqwest::{Certificate, Client};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::borrow::Cow;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use url::Url;
use uuid::Uuid;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

// usernames::constants::USERNAME_LINK_ENTROPY_SIZE is not public
pub const USERNAME_LINK_ENTROPY_SIZE: usize = 32;
pub const UUID_BYTE_SIZE: usize = 16;

pub const SIGNAL_CA: &str = "-----BEGIN CERTIFICATE-----\nMIIF2zCCA8OgAwIBAgIUAMHz4g60cIDBpPr1gyZ/JDaaPpcwDQYJKoZIhvcNAQEL\nBQAwdTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT\nDU1vdW50YWluIFZpZXcxHjAcBgNVBAoTFVNpZ25hbCBNZXNzZW5nZXIsIExMQzEZ\nMBcGA1UEAxMQU2lnbmFsIE1lc3NlbmdlcjAeFw0yMjAxMjYwMDQ1NTFaFw0zMjAx\nMjQwMDQ1NTBaMHUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw\nFAYDVQQHEw1Nb3VudGFpbiBWaWV3MR4wHAYDVQQKExVTaWduYWwgTWVzc2VuZ2Vy\nLCBMTEMxGTAXBgNVBAMTEFNpZ25hbCBNZXNzZW5nZXIwggIiMA0GCSqGSIb3DQEB\nAQUAA4ICDwAwggIKAoICAQDEecifxMHHlDhxbERVdErOhGsLO08PUdNkATjZ1kT5\n1uPf5JPiRbus9F4J/GgBQ4ANSAjIDZuFY0WOvG/i0qvxthpW70ocp8IjkiWTNiA8\n1zQNQdCiWbGDU4B1sLi2o4JgJMweSkQFiyDynqWgHpw+KmvytCzRWnvrrptIfE4G\nPxNOsAtXFbVH++8JO42IaKRVlbfpe/lUHbjiYmIpQroZPGPY4Oql8KM3o39ObPnT\no1WoM4moyOOZpU3lV1awftvWBx1sbTBL02sQWfHRxgNVF+Pj0fdDMMFdFJobArrL\nVfK2Ua+dYN4pV5XIxzVarSRW73CXqQ+2qloPW/ynpa3gRtYeGWV4jl7eD0PmeHpK\nOY78idP4H1jfAv0TAVeKpuB5ZFZ2szcySxrQa8d7FIf0kNJe9gIRjbQ+XrvnN+ZZ\nvj6d+8uBJq8LfQaFhlVfI0/aIdggScapR7w8oLpvdflUWqcTLeXVNLVrg15cEDwd\nlV8PVscT/KT0bfNzKI80qBq8LyRmauAqP0CDjayYGb2UAabnhefgmRY6aBE5mXxd\nbyAEzzCS3vDxjeTD8v8nbDq+SD6lJi0i7jgwEfNDhe9XK50baK15Udc8Cr/ZlhGM\njNmWqBd0jIpaZm1rzWA0k4VwXtDwpBXSz8oBFshiXs3FD6jHY2IhOR3ppbyd4qRU\npwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV\nHQ4EFgQUtfNLxuXWS9DlgGuMUMNnW7yx83EwHwYDVR0jBBgwFoAUtfNLxuXWS9Dl\ngGuMUMNnW7yx83EwDQYJKoZIhvcNAQELBQADggIBABUeiryS0qjykBN75aoHO9bV\nPrrX+DSJIB9V2YzkFVyh/io65QJMG8naWVGOSpVRwUwhZVKh3JVp/miPgzTGAo7z\nhrDIoXc+ih7orAMb19qol/2Ha8OZLa75LojJNRbZoCR5C+gM8C+spMLjFf9k3JVx\ndajhtRUcR0zYhwsBS7qZ5Me0d6gRXD0ZiSbadMMxSw6KfKk3ePmPb9gX+MRTS63c\n8mLzVYB/3fe/bkpq4RUwzUHvoZf+SUD7NzSQRQQMfvAHlxk11TVNxScYPtxXDyiy\n3Cssl9gWrrWqQ/omuHipoH62J7h8KAYbr6oEIq+Czuenc3eCIBGBBfvCpuFOgckA\nXXE4MlBasEU0MO66GrTCgMt9bAmSw3TrRP12+ZUFxYNtqWluRU8JWQ4FCCPcz9pg\nMRBOgn4lTxDZG+I47OKNuSRjFEP94cdgxd3H/5BK7WHUz1tAGQ4BgepSXgmjzifF\nT5FVTDTl3ZnWUVBXiHYtbOBgLiSIkbqGMCLtrBtFIeQ7RRTb3L+IE9R0UB0cJB3A\nXbf1lVkOcmrdu2h8A32aCwtr5S1fBF1unlG7imPmqJfpOMWa8yIF/KWVm29JAPq8\nLrsybb0z5gg8w7ZblEuB9zOW9M3l60DXuJO6l7g+deV6P96rv2unHS8UlvWiVWDy\n9qfgAJizyy3kqM4lOwBH\n-----END CERTIFICATE-----\n";

#[derive(clap::Parser)]
#[command(version)]
struct Args {
    /// Increase logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    verbose: u8,
    /// Path to a pem file to use as trusted CA
    #[arg(long)]
    ca_file: Option<PathBuf>,
    /// Value for http user agent header
    #[arg(long)]
    user_agent: Option<String>,
    /// Reduce logging output
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    subcommand: SubCommand,
}

#[derive(Debug, clap::Subcommand)]
enum SubCommand {
    /// Lookup signal.me link to username and uuid
    Url {
        /// Stop after resolving the username, do not resolve uuid
        #[arg(long)]
        only_username: bool,
        /// Do not print the username (quiet mode only)
        #[arg(long)]
        only_uuid: bool,
        url: String,
    },
    /// Lookup a username to uuid
    Username { username: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameLinkResponse {
    pub username_link_encrypted_value: String,
}

#[derive(Debug, Deserialize)]
pub struct UsernameHashResponse {
    pub uuid: String,
}

// supports both base64 and base64-url
fn from_web_safe_base64(base64: &str) -> Result<Vec<u8>> {
    let base64 = base64.replace('_', "/").replace('-', "+");
    let bytes = data_encoding::BASE64_NOPAD.decode(base64.as_bytes())?;
    Ok(bytes)
}

fn parse_signal_me_url(url: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let url = url
        .parse::<Url>()
        .with_context(|| anyhow!("Failed to parse url: {url:?}"))?;

    let host = url.host();
    if host != Some(url::Host::Domain("signal.me")) {
        warn!("Unexpected domain in url: {host:?}");
    }

    let fragment = url
        .fragment()
        .with_context(|| anyhow!("Missing url fragment: {url:?}"))?;
    debug!("Found url fragment: {fragment:?}");

    let fragment = fragment
        .strip_prefix("eu/")
        .context("Fragment is supposed to start with #eu/")?;
    let fragment = from_web_safe_base64(fragment)?;

    trace!("Decoded fragment: {fragment:?}");
    if fragment.len() < USERNAME_LINK_ENTROPY_SIZE {
        bail!(
            "Fragment is too short, len={} expected={}",
            fragment.len(),
            USERNAME_LINK_ENTROPY_SIZE
        );
    }

    let (entropy, server_uuid) = fragment.split_at(USERNAME_LINK_ENTROPY_SIZE);
    Ok((entropy.to_vec(), server_uuid.to_vec()))
}

async fn fetch<T: DeserializeOwned>(client: &Client, url: &str) -> Result<T> {
    info!("Sending http request to {url:?}");
    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to send http request")?
        .error_for_status()?
        .json::<T>()
        .await
        .context("Failed to receive http response")?;
    Ok(response)
}

fn username_link_url(server_uuid: &[u8; UUID_BYTE_SIZE]) -> Result<String> {
    let server_uuid = Uuid::from_bytes(*server_uuid).to_string();
    debug!("Encoded server uuid: {server_uuid:?}");

    let url = Url::parse("https://chat.signal.org/v1/accounts/username_link/")?;
    let url = url.join(&server_uuid)?;
    let url = url.to_string();

    Ok(url)
}

fn username_lookup_url(username: &str) -> Result<String> {
    let username = usernames::Username::new(username).context("Failed to parse username")?;
    let hash = username.hash();
    let hash = data_encoding::BASE64URL_NOPAD.encode(&hash);
    debug!("Calculated hash for username: {hash:?}");

    let url = Url::parse("https://chat.signal.org/v1/accounts/username_hash/")?;
    let url = url.join(&hash)?;
    let url = url.to_string();

    Ok(url)
}

async fn fetch_decrypt_username_link(
    client: &Client,
    entropy: &[u8; USERNAME_LINK_ENTROPY_SIZE],
    server_uuid: &[u8; UUID_BYTE_SIZE],
) -> Result<String> {
    let url = username_link_url(server_uuid)?;
    let response = fetch::<UsernameLinkResponse>(client, &url).await?;
    info!(
        "Received response from server: {:?}",
        response.username_link_encrypted_value
    );

    let encrypted_username = data_encoding::BASE64URL_NOPAD
        .decode(response.username_link_encrypted_value.as_bytes())
        .context("Failed to base64 decode username_link_encrypted_value")?;

    let username = usernames::decrypt_username(entropy, &encrypted_username)
        .map_err(|err| anyhow!("Failed to decrypt username: {err:#}"))?;

    Ok(username)
}

async fn setup_http_client(args: &Args) -> Result<Client> {
    let ca = if let Some(ca_file) = &args.ca_file {
        let buf = fs::read(ca_file)
            .await
            .with_context(|| anyhow!("Failed to read CA certificate from {ca_file:?}"))?;
        Cow::Owned(buf)
    } else {
        Cow::Borrowed(SIGNAL_CA.as_bytes())
    };
    let cert = Certificate::from_pem(&ca)?;

    let mut builder = Client::builder()
        .add_root_certificate(cert)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT);
    if let Some(agent) = &args.user_agent {
        builder = builder.user_agent(agent);
    }
    let client = builder.build()?;
    Ok(client)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let log_level = match (args.quiet, args.verbose) {
        (true, _) => "warn",
        (false, 0) => "info",
        (false, 1) => "info,signal_whois=debug",
        (false, 2) => "debug",
        (false, 3) => "debug,signal_whois=trace",
        (false, _) => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    // setup http client
    let client = setup_http_client(&args).await?;

    let mut subcommand = args.subcommand;
    loop {
        match &subcommand {
            SubCommand::Url {
                only_username,
                only_uuid,
                url,
            } => {
                let (entropy, server_uuid) = parse_signal_me_url(url)?;
                trace!("Found entropy for decryption: {entropy:?}");
                trace!("Found server uuid to lookup link: {server_uuid:?}");
                let entropy = entropy[..].try_into().context("entropy has wrong size")?;
                let server_uuid = server_uuid[..]
                    .try_into()
                    .context("server_uuid has wrong size")?;

                let username = fetch_decrypt_username_link(&client, entropy, server_uuid).await?;
                info!("Decrypted username: {username:?}");
                if args.quiet && !only_uuid {
                    println!("{username}");
                }

                if !only_username {
                    subcommand = SubCommand::Username { username };
                }
            }
            SubCommand::Username { username } => {
                let url = username_lookup_url(username)?;
                let response = fetch::<UsernameHashResponse>(&client, &url).await?;

                let uuid = response.uuid;
                info!("Found uuid for username: {uuid:?}");
                if args.quiet {
                    println!("{uuid}");
                }

                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_encrypted_username_link() {
        let url = "https://signal.me/#eu/Bd7NmwtYx/Q2d7xaWdoA/B6SJ5OG+avJLq6a705QqE9e21XB0IhBJYV8lmkkoMSm";
        let (entropy, server_uuid) = parse_signal_me_url(url).unwrap();
        assert_eq!(entropy, b"\x05\xde\xcd\x9b\x0b\x58\xc7\xf4\x36\x77\xbc\x5a\x59\xda\x00\xfc\x1e\x92\x27\x93\x86\xf9\xab\xc9\x2e\xae\x9a\xef\x4e\x50\xa8\x4f");
        assert_eq!(
            server_uuid,
            b"\x5e\xdb\x55\xc1\xd0\x88\x41\x25\x85\x7c\x96\x69\x24\xa0\xc4\xa6"
        );
    }

    #[test]
    fn test_username_link_api_url() {
        let server_uuid = b"\x5e\xdb\x55\xc1\xd0\x88\x41\x25\x85\x7c\x96\x69\x24\xa0\xc4\xa6";
        let url = username_link_url(server_uuid).unwrap();
        assert_eq!(
            url,
            "https://chat.signal.org/v1/accounts/username_link/5edb55c1-d088-4125-857c-966924a0c4a6"
        );
    }

    #[test]
    fn test_username_hash_api_url() {
        let username = "signal.03";
        let url = username_lookup_url(username).unwrap();
        assert_eq!(
            url,
            "https://chat.signal.org/v1/accounts/username_hash/pnHmENLMVzEaBbEiDcBGDOAI9hsuJOi65MxnS6MWYT8"
        );
    }
}
