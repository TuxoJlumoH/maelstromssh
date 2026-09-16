//! Parses OpenSSH-style `-L`/`-R`/`-D` forward specs into `ForwardRule`s.

use anyhow::{bail, Context, Result};
use vortexssh_core::config::{ForwardKind, ForwardRule};

/// Parses a forward specification.
///
/// - Local/Remote: `[bind_address:]port:host:hostport`
/// - Dynamic:      `[bind_address:]port`
///
/// IPv6 addresses in the bind address are not supported (the `:` separator is
/// ambiguous); an empty destination host means `127.0.0.1`.
pub fn parse(spec: &str, kind: ForwardKind) -> Result<ForwardRule> {
    let parts: Vec<&str> = spec.split(':').collect();
    match kind {
        ForwardKind::Dynamic => {
            let (bind_host, bind_port) = match parts.len() {
                1 => ("", parts[0]),
                2 => (parts[0], parts[1]),
                _ => bail!("invalid -D spec '{spec}' (expected [bind:]port)"),
            };
            Ok(ForwardRule {
                kind,
                bind_host: bind_host.to_string(),
                bind_port: parse_port(bind_port)?,
                dest_host: None,
                dest_port: None,
            })
        }
        ForwardKind::Local | ForwardKind::Remote => {
            let (bind_host, bind_port, dest_host, dest_port) = match parts.len() {
                3 => ("", parts[0], parts[1], parts[2]),
                4 => (parts[0], parts[1], parts[2], parts[3]),
                _ => bail!("invalid forward spec '{spec}' (expected [bind:]port:host:hostport)"),
            };
            let dest_host = if dest_host.is_empty() {
                "127.0.0.1".to_string()
            } else {
                dest_host.to_string()
            };
            Ok(ForwardRule {
                kind,
                bind_host: bind_host.to_string(),
                bind_port: parse_port(bind_port)?,
                dest_host: Some(dest_host),
                dest_port: Some(parse_port(dest_port)?),
            })
        }
    }
}

fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>()
        .with_context(|| format!("invalid port '{s}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_three_parts_defaults_bind() {
        let r = parse("8080:localhost:80", ForwardKind::Local).unwrap();
        assert_eq!(r.kind, ForwardKind::Local);
        assert_eq!(r.bind_host, "");
        assert_eq!(r.bind_port, 8080);
        assert_eq!(r.dest_host.as_deref(), Some("localhost"));
        assert_eq!(r.dest_port, Some(80));
    }

    #[test]
    fn local_four_parts_with_bind() {
        let r = parse("127.0.0.1:9000:10.0.0.1:3306", ForwardKind::Local).unwrap();
        assert_eq!(r.bind_host, "127.0.0.1");
        assert_eq!(r.bind_port, 9000);
        assert_eq!(r.dest_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.dest_port, Some(3306));
    }

    #[test]
    fn empty_dest_host_defaults_to_localhost() {
        let r = parse("8080::80", ForwardKind::Remote).unwrap();
        assert_eq!(r.dest_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(r.dest_port, Some(80));
    }

    #[test]
    fn dynamic_one_and_two_parts() {
        let r = parse("1080", ForwardKind::Dynamic).unwrap();
        assert_eq!(r.bind_host, "");
        assert_eq!(r.bind_port, 1080);
        let r = parse("127.0.0.1:1080", ForwardKind::Dynamic).unwrap();
        assert_eq!(r.bind_host, "127.0.0.1");
        assert_eq!(r.bind_port, 1080);
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(parse("8080", ForwardKind::Local).is_err());
        assert!(parse("a:b:c:d:e", ForwardKind::Local).is_err());
        assert!(parse("8080:host:notaport", ForwardKind::Local).is_err());
        assert!(parse("", ForwardKind::Dynamic).is_err());
    }
}
