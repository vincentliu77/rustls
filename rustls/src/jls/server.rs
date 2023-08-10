use std::{fmt::Display, io, net::SocketAddr, ops::Deref};

use regex::Regex;
use url::Url;

use crate::{JlsConfig, vecbuf::ChunkVecBuffer};

#[derive(Clone, Debug, Default)]
/// Jls Server Configuration
pub struct JlsServerConfig {
    inner: JlsConfig,
    upstream_url: Option<Url>,
    sni_proxy: Vec<(Regex, Url)>,
}

impl JlsServerConfig {
    /// Create a new jls server configuration
    pub fn new(pwd: &str, iv: &str, upstream_addr: &str) -> Result<Self, url::ParseError> {
        let config = JlsServerConfig {
            inner: JlsConfig::new(pwd, iv),
            upstream_url: Some(Url::parse(upstream_addr)?),
            sni_proxy: Vec::new(),
        };
        Ok(config)
    }

    /// push sni reverse proxy entry given domain name regex
    pub fn push_sni(&mut self, domain_regex: &str, url: &str) -> Result<(), JlsParseError> {
        let regx = Regex::new(domain_regex).map_err(|x| JlsParseError::from(x))?;
        let url = Url::parse(url).map_err(|x| JlsParseError::from(x))?;
        self.sni_proxy.push((regx, url));
        Ok(())
    }

    /// Verify server name and return destination addr
    pub fn find_jls_upstream(&self, server_name: &str) -> io::Result<SocketAddr> {
        if let Some(url) = &self.upstream_url {
            match url.domain() {
                None => Self::to_sock_addr(url),
                Some(domain) => {
                    if domain == server_name {
                        Self::to_sock_addr(url)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "client server name {} doesn't match upstream url {}",
                                server_name, url
                            ),
                        ))
                    }
                }
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("empty jls upstream"),
            ))
        }
    }

    /// Skip client servername verification, return upstream_url directly
    pub fn get_jls_upstream(&self) -> io::Result<SocketAddr> {
        if let Some(url) = &self.upstream_url {
            Self::to_sock_addr(url)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("empty jls upstream"),
            ))
        }
    }

    /// Verify whether client server name match upstream url
    pub(crate) fn check_server_name(&self, server_name: &str) -> bool {
        if let Some(url) = &self.upstream_url {
            match url.domain() {
                None => {
                    log::trace!("No domain in upstream url");
                    true
                },
                Some(domain) => {
                    log::trace!("compare server name {} with {}",server_name,domain);
                    domain == server_name
                },
            }
        } else {
            log::trace!("upstream url not found");
            return false;
        }
    }

    /// Find reverse proxy destination given domain name
    pub(crate) fn find_proxy_upstream(&self, domain_name: &str) -> io::Result<SocketAddr> {
        for (regx, upstream) in self.sni_proxy.iter() {
            if regx.is_match(domain_name) {
                return Self::to_sock_addr(upstream);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to find reverse proxy entry"),
        ))
    }

    /// Search domain name in the reverse proxy list, return upstream if not found
    pub fn find_upstream(&self, domain_name: &str) -> io::Result<SocketAddr> {
        self.find_proxy_upstream(domain_name)
            .or(self.get_jls_upstream())
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

pub(crate) struct JlsForwardConn {
    pub(crate) from_upstream: [u8;1024],
    pub(crate) to_upstream: ChunkVecBuffer,
    pub(crate) upstream_addr: SocketAddr,
}
