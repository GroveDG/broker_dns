use std::{
    error::Error,
    fmt::Display,
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
    sync::LazyLock,
};

use arti_client::{TorClient, TorClientConfig};
use domain::{
    base::{Name, Rtype},
    rdata::Txt,
    resolv::StubResolver,
};
use hyper_util::rt::tokio::WithHyperIo;
use tokio::net::TcpListener;
use tor_rtcompat::PreferredRuntime;

use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper::{StatusCode, body::Bytes};
use hyper::{
    client::conn::http1 as http1_client, header::HeaderValue, server::conn::http1 as http1_server,
};

static LOOKUP: LazyLock<StubResolver> = LazyLock::new(|| StubResolver::new());

#[tokio::main]
async fn main() {
    println!("Start");

    let config = TorClientConfig::default();
    let tor = TorClient::create_bootstrapped(config).await.unwrap();
    
    println!("Tor bootstrapped");

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80))
        .await
        .unwrap();

    println!("Listening...");

    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };

        println!("Socket accepted");

        let io = hyper_util::rt::TokioIo::new(socket);

        if let Err(err) = http1_server::Builder::new()
            .serve_connection(
                io,
                service_fn(|request| handle_connection(tor.clone(), request)),
            )
            .await
        {
            eprintln!("Error serving connection: {:?}", err);
        }
    }
}

type DynErr = Box<dyn Error + Send + Sync>;

async fn handle_connection(
    tor: TorClient<PreferredRuntime>,
    mut request: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, DynErr> {
    println!("Begin connection");

    let Some(host) = request.headers_mut().get_mut("host") else {
        return Ok(http_err(StatusCode::BAD_REQUEST));
    };
    let destination = {
        let Ok(host) = str::from_utf8(host.as_bytes()) else {
            return Ok(http_err(StatusCode::BAD_REQUEST));
        };

        let Ok(host) = resolve_host(host).await else {
            return Ok(http_err(StatusCode::NOT_FOUND));
        };
        host
    };

    println!("Resolved host");

    let stream = tor.connect((destination.as_str(), 80)).await?;

    println!("Connected through TOR");

    *host = HeaderValue::from_str(&destination)?;

    let stream = WithHyperIo::new(stream);

    let (mut send, con) = http1_client::handshake(stream).await?;

    println!("Hand shook");

    tokio::task::spawn(async move {
        if let Err(err) = con.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let response = send.send_request(request).await?;

    println!("Recieved response");

    return Ok(Response::new(response.into_body().boxed()));
}

#[derive(Debug)]
enum ResolveError {
    NoOnion,
    MissingSection,
}
impl Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoOnion => {
                f.write_str("No valid onion address in TXT records on 'onion.' subdomain")
            }
            Self::MissingSection => f.write_str("Host name missing dot-separated section"),
        }
    }
}
impl Error for ResolveError {}

async fn resolve_host(host: &str) -> Result<String, DynErr> {
    if let Some(host) = host.strip_suffix(".broker") {
        return Ok(host.to_string());
    }

    // Change to 'onion.' subdomain for TXT query.
    let mut sections = host.split('.').rev();
    let Some(mut tld) = sections.next() else {
        return Err(Box::new(ResolveError::MissingSection));
    };
    if tld.is_empty() {
        tld = match sections.next() {
            Some(tld) => tld,
            None => return Err(Box::new(ResolveError::MissingSection)),
        };
    }
    let Some(domain) = sections.next() else {
        return Err(Box::new(ResolveError::MissingSection));
    };
    let host = ["onion", domain, tld].join(".");
    
    let name = Name::<Vec<_>>::from_str(&host)?;
    let answer = LOOKUP.query((name, Rtype::TXT)).await?;
    for record in answer.answer()?.limit_to::<Txt<_>>() {
        let Ok(record) = record else {
            continue;
        };
        let Some(data) = record.data().as_flat_slice() else {
            continue;
        };
        if data.len() == 56 && data.iter().all(u8::is_ascii_alphanumeric) {
            let mut site = String::from_utf8(data.to_vec())?;
            site.push_str(".onion");
            return Ok(site);
        }
    }
    Err(Box::new(ResolveError::NoOnion))
}

fn http_err(error: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut response = Response::new(empty());
    *response.status_mut() = error;
    response
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
