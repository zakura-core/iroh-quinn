//! Capacity ownership follows transport state, including surviving stream handles.

use super::*;
use tokio::sync::oneshot;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(5);

struct Owner(Option<oneshot::Sender<()>>);

impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().send(());
    }
}

fn owner() -> (Box<dyn std::any::Any + Send + Sync>, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    (Box::new(Owner(Some(tx))), rx)
}

fn client_config(factory: &EndpointFactory) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(factory.cert.cert.der().clone()).unwrap();
    let mut config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_millis(200).try_into().unwrap()));
    config.transport_config(Arc::new(transport));
    config
}

#[tokio::test]
async fn unread_stream_retains_owner_after_connection_close() {
    let factory = EndpointFactory::new();
    let server = factory.endpoint("server");
    let client = factory.endpoint("client");
    let (reservation, mut released) = owner();
    let (local, remote) = timeout(DEADLINE, async {
        tokio::join!(
            client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async {
                server
                    .accept()
                    .await
                    .unwrap()
                    .accept_owned(None, reservation)
                    .unwrap()
                    .await
            },
        )
    })
    .await
    .unwrap();
    let (local, remote) = (local.unwrap(), remote.unwrap());
    let mut send = local.open_uni().await.unwrap();
    send.write_all(&[42; 1024]).await.unwrap();
    send.finish().unwrap();
    timeout(DEADLINE, send.stopped()).await.unwrap().unwrap();
    let unread = timeout(DEADLINE, remote.accept_uni())
        .await
        .unwrap()
        .unwrap();
    remote.close(0u32.into(), b"done");
    remote.closed().await;
    drop(remote);
    assert!(matches!(
        released.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    drop(unread);
    timeout(DEADLINE, released).await.unwrap().unwrap();
    local.close(0u32.into(), b"done");
    drop((send, local));
    timeout(DEADLINE, client.wait_idle()).await.unwrap();
    timeout(DEADLINE, server.wait_idle()).await.unwrap();
}

#[tokio::test]
async fn rejected_construction_releases_owner() {
    let factory = EndpointFactory::new();
    let endpoint = factory.endpoint("closed");
    endpoint.close(0u32.into(), b"closed");
    let (reservation, released) = owner();
    assert!(
        endpoint
            .connect_with_owner(
                client_config(&factory),
                endpoint.local_addr().unwrap(),
                "localhost",
                reservation
            )
            .is_err()
    );
    timeout(DEADLINE, released).await.unwrap().unwrap();
}

#[tokio::test]
async fn cancelled_handshake_releases_owner_after_transport_cleanup() {
    let factory = EndpointFactory::new();
    let server = factory.endpoint("unaccepted");
    let client = factory.endpoint("client");
    let (reservation, released) = owner();
    let connecting = client
        .connect_with_owner(
            client_config(&factory),
            server.local_addr().unwrap(),
            "localhost",
            reservation,
        )
        .unwrap();
    // Cancellation must not depend on a successful handshake or a returned Connection.
    drop(connecting);
    timeout(DEADLINE, released).await.unwrap().unwrap();
    timeout(DEADLINE, client.wait_idle()).await.unwrap();
    server.close(0u32.into(), b"done");
}
