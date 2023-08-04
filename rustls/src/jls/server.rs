use std::{io, net::SocketAddr, ops::Deref, fmt::Display};

use regex::Regex;
use url::Url;

use crate::JlsConfig;

struct JlsServerConfig {
    inner: JlsConfig,
    upstream_url: Url,
    sni_proxy: Vec<(Regex, Url)>,
}

impl JlsServerConfig {

    pub fn new(pwd: &str, iv: &str, upstream_addr: &str) -> Result<Self, url::ParseError> {
        let config = JlsServerConfig {
            inner: JlsConfig::new(pwd, iv),
            upstream_url: Url::parse(upstream_addr)?,
            sni_proxy: Vec::new(),
        };
        Ok(config)
    }

    pub fn push_sni(&mut self, domain_name: &str, url: &str) -> Result<(), JlsParseError> {
        let regx = Regex::new(domain_name).map_err(|x| JlsParseError::from(x))?;
        let url = Url::parse(url).map_err(|x| JlsParseError::from(x))?;
        self.sni_proxy.push((regx, url));
        Ok(())
    }

    pub fn get_upstream_addr(&self, server_name: &str) -> io::Result<SocketAddr> {
        match self.upstream_url.domain() {
            None => Self::to_sock_addr(&self.upstream_url),
            Some(domain) => {
                if domain == server_name {
                    Self::to_sock_addr(&self.upstream_url)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "client server name {} doesn't match upstream url {}",
                            server_name, self.upstream_url
                        ),
                    ))
                }
            }
        }
    }

    pub(crate) fn check_server_name(&self, server_name: &str) -> bool {
        match self.upstream_url.domain() {
            None => true,
            Some(domain) => domain == server_name,
        }
    }

    pub(crate) fn find_upstream(&self, domain_name: &str) -> io::Result<SocketAddr> {
        for (regx, upstream) in self.sni_proxy {
            if regx.is_match(domain_name) {
                return Self::to_sock_addr(&upstream);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to find reverse proxy entry"),
        ))
    }

    fn to_sock_addr(url: &Url) -> io::Result<SocketAddr> {
        url.socket_addrs(|| Some(443))?
            .pop()
            .ok_or(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("failed to resolve domain: {}", url),
            ))
    }
}

impl Deref for JlsServerConfig {
    type Target = JlsConfig;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug)]
pub enum JlsParseError {
    RegexError(String),
    UrlError(String),
}

impl std::error::Error for JlsParseError {}
impl Display for JlsParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::RegexError(ref err) => write!(f, "Regex Parse Error: {}", err),
            Self::UrlError(ref err) => write!(f, "Url Parse Error: {}", err),
        }
    }
}

impl From<url::ParseError> for JlsParseError {
    fn from(url_err: url::ParseError) -> Self {
        JlsParseError::UrlError(url_err.to_string())
    }
}

impl From<regex::Error> for JlsParseError {
    fn from(regx_err: regex::Error) -> Self {
        JlsParseError::RegexError(regx_err.to_string())
    }
}
