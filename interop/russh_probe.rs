use std::borrow::Cow;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::LineEnding;
use russh::keys::{
    Algorithm, EcdsaCurve, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
    decode_secret_key, generate_secret_key_for, load_public_key, load_secret_key,
};
use russh::server::{Auth, ChannelOpenHandle, Msg, Server as _, Session};
use russh::{Channel, ChannelId, ChannelMsg, Preferred, cipher, client, kex, mac, server};
use tokio::net::TcpListener;

fn parse_sig_alg(name: &str) -> Result<Algorithm, String> {
    match name {
        "ssh-mldsa87-p384" => Ok(Algorithm::Mldsa87P384),
        "ssh-ed25519" => Ok(Algorithm::Ed25519),
        "ecdsa-sha2-nistp384" => Ok(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        }),
        "ecdsa-sha2-nistp256" => Ok(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }),
        "rsa-sha2-512" => Ok(Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        }),
        "rsa-sha2-256" => Ok(Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        }),
        other => Err(format!("unsupported signature algorithm: {other}")),
    }
}

fn build_preferred(
    kex_name: &str,
    sig_alg_name: &str,
    cipher_name: &str,
    mac_name: &str,
) -> Result<Preferred, String> {
    let kex_alg =
        kex::Name::try_from(kex_name).map_err(|_| format!("unknown kex: {kex_name}"))?;
    let sig_alg = parse_sig_alg(sig_alg_name)?;
    let cipher_alg =
        cipher::Name::try_from(cipher_name).map_err(|_| format!("unknown cipher: {cipher_name}"))?;
    let mac_alg =
        mac::Name::try_from(mac_name).map_err(|_| format!("unknown mac: {mac_name}"))?;

    Ok(Preferred {
        kex: Cow::Owned(vec![
            kex_alg,
            kex::EXTENSION_SUPPORT_AS_CLIENT,
            kex::EXTENSION_SUPPORT_AS_SERVER,
            kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
        ]),
        key: Cow::Owned(vec![sig_alg]),
        host_key_certificates: Cow::Borrowed(&[]),
        cipher: Cow::Owned(vec![cipher_alg]),
        mac: Cow::Owned(vec![mac_alg]),
        compression: Cow::Owned(vec![russh::compression::NONE]),
    })
}

fn cmd_keygen(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(out_dir)?;
    let specs: &[(&str, Algorithm)] = &[
        ("id_mldsa87_p384", Algorithm::Mldsa87P384),
        ("id_ed25519", Algorithm::Ed25519),
        (
            "id_ecdsa_p384",
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
        ),
        (
            "id_ecdsa_p256",
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        ),
        (
            "id_rsa",
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        ),
    ];

    let mut authorized_keys = String::new();
    for (file_stem, alg) in specs {
        let priv_key = generate_secret_key_for(alg)?;
        let priv_pem = priv_key.to_openssh(LineEnding::LF)?;
        let pub_line = priv_key.public_key().to_openssh()?;

        // Verify russh round-trip on the generated key
        let decoded = decode_secret_key(&priv_pem, None)?;
        assert_eq!(decoded.public_key().key_data(), priv_key.public_key().key_data());

        let priv_path = out_dir.join(file_stem);
        let pub_path = out_dir.join(format!("{file_stem}.pub"));
        fs::write(&priv_path, priv_pem.as_bytes())?;
        fs::write(&pub_path, format!("{pub_line}\n").as_bytes())?;
        authorized_keys.push_str(&pub_line);
        authorized_keys.push('\n');
    }

    fs::write(out_dir.join("authorized_keys"), authorized_keys.as_bytes())?;
    Ok(())
}

struct ClientHandler {
    expected_server_key: PublicKey,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        match server_public_key {
            PublicKeyOrCertificate::PublicKey { key: pk, .. } => {
                Ok(pk.key_data() == self.expected_server_key.key_data())
            }
            PublicKeyOrCertificate::Certificate(_) => Ok(false),
        }
    }
}

async fn cmd_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 10 {
        return Err(
            "usage: russh_probe client <host> <port> <user> <privkey> <host_pubkey> <kex> <sig_alg> <cipher> <mac> <payload>"
                .into(),
        );
    }
    let host = &args[0];
    let port: u16 = args[1].parse()?;
    let user = &args[2];
    let privkey_path = Path::new(&args[3]);
    let host_pubkey_path = Path::new(&args[4]);
    let kex_name = &args[5];
    let sig_alg_name = &args[6];
    let cipher_name = &args[7];
    let mac_name = &args[8];
    let payload = &args[9];

    let key_pair = load_secret_key(privkey_path, None)?;
    let expected_server_key = load_public_key(host_pubkey_path)?;
    let preferred = build_preferred(kex_name, sig_alg_name, cipher_name, mac_name)?;
    let rsa_hash = match parse_sig_alg(sig_alg_name)? {
        Algorithm::Rsa { hash } => hash,
        _ => None,
    };

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(10)),
        preferred,
        ..Default::default()
    });

    let mut session = client::connect(
        config,
        (host.as_str(), port),
        ClientHandler {
            expected_server_key,
        },
    )
    .await?;

    let auth_res = session
        .authenticate_publickey(
            user,
            PrivateKeyWithHashAlg::new(Arc::new(key_pair), rsa_hash),
        )
        .await?;
    if !auth_res.success() {
        return Err("russh publickey authentication failed".into());
    }

    let mut channel = session.channel_open_session().await?;
    channel.request_shell(true).await?;
    let mut to_send = payload.as_bytes().to_vec();
    to_send.push(b'\n');
    channel.data(&to_send[..]).await?;
    channel.eof().await?;

    let mut received = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                received.extend_from_slice(&data);
            }
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }

    let text = String::from_utf8_lossy(&received);
    print!("{text}");
    println!(
        "negotiated kex={kex_name} sig={sig_alg_name} cipher={cipher_name} mac={mac_name}"
    );
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await;
    Ok(())
}

#[derive(Clone)]
struct InteropServer {
    authorized_keys: Arc<Vec<PublicKey>>,
    buf: Vec<u8>,
}

impl server::Server for InteropServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        Self {
            authorized_keys: self.authorized_keys.clone(),
            buf: Vec::new(),
        }
    }
}

impl server::Handler for InteropServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let allowed = self
            .authorized_keys
            .iter()
            .any(|k| k.key_data() == public_key.key_data());
        if allowed {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.buf.extend_from_slice(data);
        if let Some(pos) = self.buf.iter().position(|&b| b == b'\n' || b == b'\r') {
            let line = String::from_utf8_lossy(&self.buf[..pos]).to_string();
            let reply = format!("russh-server-echo:{line}\r\n");
            session.data(channel, reply.into_bytes())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

async fn cmd_server(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 7 {
        return Err(
            "usage: russh_probe server <port> <hostkey> <authorized_keys> <kex> <sig_alg> <cipher> <mac>"
                .into(),
        );
    }
    let port: u16 = args[0].parse()?;
    let hostkey_path = Path::new(&args[1]);
    let auth_keys_path = Path::new(&args[2]);
    let kex_name = &args[3];
    let sig_alg_name = &args[4];
    let cipher_name = &args[5];
    let mac_name = &args[6];

    let host_key = load_secret_key(hostkey_path, None)?;
    let auth_contents = fs::read_to_string(auth_keys_path)?;
    let mut authorized_keys = Vec::new();
    for line in auth_contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        authorized_keys.push(PublicKey::from_openssh(trimmed)?);
    }

    let preferred = build_preferred(kex_name, sig_alg_name, cipher_name, mac_name)?;
    let config = Arc::new(server::Config {
        inactivity_timeout: Some(Duration::from_secs(15)),
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        preferred,
        ..Default::default()
    });

    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("russh server listening on port {port}");

    let mut srv = InteropServer {
        authorized_keys: Arc::new(authorized_keys),
        buf: Vec::new(),
    };
    srv.run_on_socket(config, &listener).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err("usage: russh_probe <keygen|client|server> ...".into());
    }
    match args[1].as_str() {
        "keygen" => {
            if args.len() != 3 {
                return Err("usage: russh_probe keygen <out_dir>".into());
            }
            cmd_keygen(Path::new(&args[2]))
        }
        "client" => cmd_client(&args[2..]).await,
        "server" => cmd_server(&args[2..]).await,
        other => Err(format!("unknown subcommand: {other}").into()),
    }
}
