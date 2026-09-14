//! Routing the phone's sockets through the Tailscale VPN network (work order 09 decision 11).
//!
//! Kotlin passes the VPN `Network`'s handle; every socket is bound to it with
//! `android_setsocknetwork` before `bind` or `connect`, so traffic never leaves by another network.
//! The handle is held only in memory and never persisted.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::args::{NetworkHandle, is_tailscale_cgnat};

/// Associates a socket with the network the phone selected, before it is bound.
pub trait SocketBinder: Send + Sync {
    fn bind_to_network(&self, socket: &TcpSocket) -> io::Result<()>;
}

#[cfg(target_os = "android")]
#[link(name = "android")]
unsafe extern "C" {
    /// `<android/multinetwork.h>`, API 23 and later (minSdk is 26). `net_handle_t` is `uint64_t`.
    fn android_setsocknetwork(network: u64, fd: core::ffi::c_int) -> core::ffi::c_int;
}

/// Binds sockets to the VPN network through the NDK.
#[cfg(target_os = "android")]
#[derive(Debug)]
pub struct AndroidNetworkBinder {
    network: NetworkHandle,
}

#[cfg(target_os = "android")]
impl SocketBinder for AndroidNetworkBinder {
    fn bind_to_network(&self, socket: &TcpSocket) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor is owned by `socket`, which outlives the call; the function only
        // associates that descriptor with a network and retains nothing.
        let fd = socket.as_raw_fd();
        let status = unsafe { android_setsocknetwork(self.network.get(), fd) };
        if status == 0 {
            crate::host::log_android(&format!(
                "android_setsocknetwork net={} fd={} SUCCESS",
                self.network.get(),
                fd
            ));
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            crate::host::log_android(&format!(
                "android_setsocknetwork net={} fd={} FAILED: {err}",
                self.network.get(),
                fd
            ));
            Err(err)
        }
    }
}

/// Host builds have no Android network to select; sockets follow the host routing table, so the
/// same resident code runs in host tests.
#[derive(Debug, Default)]
pub struct HostSocketBinder;

impl SocketBinder for HostSocketBinder {
    fn bind_to_network(&self, _socket: &TcpSocket) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn platform_binder(network: NetworkHandle) -> Arc<dyn SocketBinder> {
    #[cfg(target_os = "android")]
    {
        Arc::new(AndroidNetworkBinder { network })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = network;
        Arc::new(HostSocketBinder)
    }
}

/// A listener on `(local, port)`, routed through the binder first. Must run inside the bridge
/// runtime; only a Tailscale address is ever bound, never a wildcard.
pub fn bind_listener(
    binder: &dyn SocketBinder,
    local: Ipv4Addr,
    port: u16,
    backlog: u32,
) -> io::Result<TcpListener> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(io::Error::other(
            "the listener must be created inside the bridge runtime",
        ));
    }
    let socket = routed_socket(binder, local)?;
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    let _ = socket.set_reuseport(true);
    socket.bind(SocketAddr::V4(SocketAddrV4::new(local, port)))?;
    socket.listen(backlog)
}

/// An outbound connection from `(local, 0)`, routed through the binder first.
pub async fn connect_bound(
    binder: &dyn SocketBinder,
    local: Ipv4Addr,
    remote: SocketAddrV4,
) -> io::Result<TcpStream> {
    let socket = routed_socket(binder, local)?;
    socket.bind(SocketAddr::V4(SocketAddrV4::new(local, 0)))?;
    socket.connect(SocketAddr::V4(remote)).await
}

fn routed_socket(binder: &dyn SocketBinder, local: Ipv4Addr) -> io::Result<TcpSocket> {
    if !is_tailscale_cgnat(local) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to bind {local}: only a Tailscale 100.64.0.0/10 address may be bound"
            ),
        ));
    }
    let socket = TcpSocket::new_v4()?;
    binder.bind_to_network(&socket)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Records the socket's local address at routing time, proving routing precedes `bind`.
    #[derive(Default)]
    struct RecordingBinder {
        seen: Mutex<Vec<Option<SocketAddr>>>,
        fail: bool,
    }

    impl SocketBinder for RecordingBinder {
        fn bind_to_network(&self, socket: &TcpSocket) -> io::Result<()> {
            self.seen
                .lock()
                .expect("seen")
                .push(socket.local_addr().ok());
            if self.fail {
                Err(io::Error::other("vpn network is gone"))
            } else {
                Ok(())
            }
        }
    }

    fn remote() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 9), 45_832)
    }

    #[tokio::test]
    async fn wildcard_and_non_tailscale_addresses_are_refused_before_routing() {
        let binder = RecordingBinder::default();
        for local in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(100, 128, 0, 1),
        ] {
            let listener = bind_listener(&binder, local, 0, 8).expect_err("refused");
            assert_eq!(listener.kind(), io::ErrorKind::InvalidInput);
            let stream = connect_bound(&binder, local, remote())
                .await
                .expect_err("refused");
            assert_eq!(stream.kind(), io::ErrorKind::InvalidInput);
        }
        assert!(binder.seen.lock().expect("seen").is_empty());
    }

    #[tokio::test]
    async fn every_socket_is_routed_while_still_unbound() {
        let binder = RecordingBinder::default();
        let local = Ipv4Addr::new(100, 64, 0, 1);
        // The host may or may not own this address; only the routing order is asserted.
        let _ = bind_listener(&binder, local, 0, 8);
        let _ = connect_bound(&binder, local, remote()).await;
        // Unix reports an unbound socket as 0.0.0.0:0; Windows refuses to name an unbound socket.
        let unbound = if cfg!(windows) {
            None
        } else {
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
        };
        assert_eq!(*binder.seen.lock().expect("seen"), vec![unbound, unbound]);
    }

    #[tokio::test]
    async fn a_routing_failure_stops_before_bind_and_is_reported() {
        let binder = RecordingBinder {
            fail: true,
            ..RecordingBinder::default()
        };
        let local = Ipv4Addr::new(100, 64, 0, 1);
        let error = bind_listener(&binder, local, 0, 8).expect_err("routing failed");
        assert_eq!(error.to_string(), "vpn network is gone");
        let error = connect_bound(&binder, local, remote())
            .await
            .expect_err("routing failed");
        assert_eq!(error.to_string(), "vpn network is gone");
    }

    #[test]
    fn a_listener_outside_the_runtime_is_an_error_not_a_panic() {
        let error = bind_listener(&HostSocketBinder, Ipv4Addr::new(100, 64, 0, 1), 0, 8)
            .expect_err("no runtime");
        assert!(error.to_string().contains("bridge runtime"));
    }
}
