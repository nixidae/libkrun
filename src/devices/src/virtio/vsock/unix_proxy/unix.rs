use std::num::Wrapping;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, Backlog, MsgFlags, Shutdown, SockFlag, SockType, UnixAddr, accept, bind,
    connect, listen, recv, send, shutdown, socket,
};

#[cfg(target_os = "macos")]
use super::super::super::linux_errno::linux_errno_raw;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiConnectReq, VsockPacket};
use super::super::proxy::{
    NewProxyType, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt,
};
use utils::epoll::EventSet;

pub type PlatformHandle = OwnedFd;

pub(crate) fn create_socket(id: u64) -> Result<PlatformHandle, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;

    // macOS forces us to do this here instead of just using SockFlag::SOCK_NONBLOCK above.
    match fcntl(&fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!("error switching to non-blocking: id={id}, err={e}");
                }
            }
            None => error!("invalid fd flags id={id}"),
        },
        Err(e) => error!("couldn't obtain fd flags id={id}, err={e}"),
    };

    set_nosigpipe(&fd);
    Ok(fd)
}

/// `sendmsg` sends with no flags on macOS, so every stream socket needs
/// this, the accepted ones too: else a send after the peer closed raises
/// SIGPIPE and the VMM dies.
fn set_nosigpipe(_fd: &OwnedFd) {
    #[cfg(target_os = "macos")]
    {
        // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
        let option_value: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                _fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &option_value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&option_value) as libc::socklen_t,
            )
        };
    }
}

/// Non-blocking, accepted sockets too: `send_now` must never block, and
/// macOS ignores MSG_DONTWAIT on a send to a blocking AF_UNIX stream.
pub(crate) fn switch_to_connected(proxy: &mut super::UnixProxy) {
    proxy.status = ProxyStatus::Connected;
    match fcntl(&proxy.fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&proxy.fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!("error switching to non-blocking: id={}, err={}", proxy.id, e);
                }
            }
            None => error!("invalid fd flags id={}", proxy.id),
        },
        Err(e) => error!("couldn't obtain fd flags id={}, err={}", proxy.id, e),
    };
}

fn push_connect_rsp(proxy: &super::UnixProxy, result: i32) {
    debug!(
        "push_connect_rsp: id: {}, control_port: {}, result: {}",
        proxy.id, proxy.control_port, result
    );

    // This response goes to the control port (DGRAM).
    let rx = MuxerRx::ConnResponse {
        local_port: 1025,
        peer_port: proxy.control_port,
        result,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn recv_to_pkt(proxy: &super::UnixProxy, pkt: &mut VsockPacket) -> RecvPkt {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);

        debug!(
            "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
            proxy.peer_avail_credit(),
            buf.len(),
            max_len
        );

        if max_len == 0 {
            return RecvPkt::WaitForCredit;
        }

        match recv(
            proxy.fd.as_raw_fd(),
            &mut buf[..max_len],
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(cnt) => {
                debug!("recv cnt={cnt}");
                if cnt > 0 {
                    debug!("recv rx_cnt={}", proxy.rx_cnt);
                    RecvPkt::Read(cnt)
                } else {
                    RecvPkt::Close
                }
            }
            Err(e) => {
                debug!("recv_pkt: recv error: {e:?}");
                match e {
                    Errno::EAGAIN | Errno::EINTR => RecvPkt::Error,
                    _ => RecvPkt::Close,
                }
            }
        }
    } else {
        debug!("recv_pkt: pkt without buf");
        RecvPkt::Error
    }
}

pub(crate) fn do_connect(
    proxy: &mut super::UnixProxy,
    _pkt: &VsockPacket,
    _req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let addr = UnixAddr::new(&proxy.path).unwrap();

    let result = match connect(proxy.fd.as_raw_fd(), &addr) {
        Ok(()) => {
            debug!("connect: Connected");
            switch_to_connected(proxy);
            0
        }
        Err(nix::errno::Errno::EINPROGRESS) => {
            debug!("connect: Connecting");
            proxy.status = ProxyStatus::Connecting;
            0
        }
        Err(e) => {
            debug!("Error connecting: {e}");
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(Errno::last_raw());
            #[cfg(target_os = "linux")]
            let errno = -Errno::last_raw();
            errno
        }
    };

    if proxy.status == ProxyStatus::Connecting {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN | EventSet::OUT));
    } else {
        if proxy.status == ProxyStatus::Connected {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        }
        push_connect_rsp(proxy, result);
    }
    update
}

pub(crate) fn confirm_connect(
    proxy: &mut super::UnixProxy,
    pkt: &VsockPacket,
) -> Option<ProxyUpdate> {
    debug!(
        "confirm_connect: local_port={} peer_port={}, src_port={}, dst_port={}",
        pkt.dst_port(),
        pkt.src_port(),
        proxy.local_port,
        proxy.peer_port,
    );

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    proxy.local_port = pkt.dst_port();
    proxy.peer_port = pkt.src_port();

    // This response goes to the connection.
    let rx = MuxerRx::OpResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    None
}

/// What the host socket is polled for: IN while the proxy reads it, OUT
/// while guest data waits for it.
fn wanted_events(proxy: &super::UnixProxy) -> EventSet {
    let mut events = EventSet::empty();
    if proxy.status == ProxyStatus::Connected && !proxy.host_read_closed {
        events |= EventSet::IN;
    }
    if !proxy.pending.is_empty() {
        events |= EventSet::OUT;
    }
    events
}

/// Never blocks: the muxer thread serves every connection. The socket is
/// O_NONBLOCK as well (`switch_to_connected`).
fn send_now(proxy: &super::UnixProxy, buf: &[u8]) -> nix::Result<usize> {
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::MSG_DONTWAIT;

    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;

    send(proxy.fd.as_raw_fd(), buf, flags)
}

/// The host end is gone. EOF on its read side is only a half-close, so a
/// failed send is where the guest learns it.
fn reset_host_gone(proxy: &mut super::UnixProxy, err: Errno) -> ProxyUpdate {
    debug!(
        "host end closed, sending reset: id={}, err={err}",
        proxy.id
    );
    proxy.pending.clear();
    proxy.push_reset();
    proxy.status = ProxyStatus::Closed;
    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty())),
        remove_proxy: ProxyRemoval::Deferred,
        signal_queue: true,
        ..Default::default()
    }
}

fn push_credit_update(proxy: &mut super::UnixProxy, update: &mut ProxyUpdate) {
    if (proxy.tx_cnt - proxy.last_tx_cnt_sent).0 < proxy.peer_buf_alloc / 2 {
        return;
    }
    debug!(
        "sending credit update: id={}, tx_cnt={}, last_tx_cnt={}",
        proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
    );
    proxy.last_tx_cnt_sent = proxy.tx_cnt;

    let rx = MuxerRx::CreditUpdate {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
        fwd_cnt: proxy.tx_cnt.0,
    };

    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
    update.signal_queue = true;
}

pub(crate) fn sendmsg(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();
    let Some(buf) = pkt.buf() else {
        return update;
    };

    let was_pending = !proxy.pending.is_empty();
    if was_pending {
        proxy.pending.extend(buf);
    } else {
        match send_now(proxy, buf) {
            Ok(sent) => {
                proxy.tx_cnt += Wrapping(sent as u32);
                proxy.pending.extend(&buf[sent..]);
            }
            Err(Errno::EAGAIN | Errno::EINTR) => proxy.pending.extend(buf),
            Err(err) => return reset_host_gone(proxy, err),
        }
    }

    if !was_pending && !proxy.pending.is_empty() {
        debug!(
            "sendmsg: host socket full, holding {} bytes: id={}",
            proxy.pending.len(),
            proxy.id
        );
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), wanted_events(proxy)));
    }

    push_credit_update(proxy, &mut update);
    update
}

/// Send what the host socket takes of `pending`; once it is empty, apply
/// a shutdown the guest asked for meanwhile.
fn flush_pending(proxy: &mut super::UnixProxy) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();
    while !proxy.pending.is_empty() {
        let (front, _) = proxy.pending.as_slices();
        match send_now(proxy, front) {
            Ok(0) => break,
            Ok(sent) => {
                proxy.tx_cnt += Wrapping(sent as u32);
                proxy.pending.drain(..sent);
            }
            Err(Errno::EAGAIN) => break,
            Err(Errno::EINTR) => continue,
            Err(err) => return reset_host_gone(proxy, err),
        }
    }
    push_credit_update(proxy, &mut update);

    if proxy.pending.is_empty() && proxy.deferred_shutdown != 0 {
        let flags = std::mem::take(&mut proxy.deferred_shutdown);
        shutdown_host(proxy, flags);
        const BOTH: u32 =
            super::uapi::VSOCK_FLAGS_SHUTDOWN_RCV | super::uapi::VSOCK_FLAGS_SHUTDOWN_SEND;
        if proxy.peer_shutdown == BOTH {
            proxy.push_reset();
            proxy.status = ProxyStatus::Closed;
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
            update.remove_proxy = ProxyRemoval::Deferred;
            update.signal_queue = true;
            return update;
        }
    }

    update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), wanted_events(proxy)));
    update
}

pub(crate) fn update_peer_credit(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    debug!(
        "update_credit: buf_alloc={} rx_cnt={} fwd_cnt={}",
        pkt.buf_alloc(),
        proxy.rx_cnt,
        pkt.fwd_cnt()
    );
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    if proxy.host_read_closed
        || proxy.status != ProxyStatus::WaitingCreditUpdate
        || proxy.peer_avail_credit() == 0
    {
        return ProxyUpdate::default();
    }

    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), wanted_events(proxy))),
        ..Default::default()
    }
}

pub(crate) fn push_op_request(proxy: &super::UnixProxy) {
    debug!(
        "push_op_request: id={}, local_port={} peer_port={}",
        proxy.id, proxy.local_port, proxy.peer_port
    );

    // This packet goes to the connection.
    let rx = MuxerRx::OpRequest {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn process_op_response(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    debug!(
        "process_op_response: id={} src_port={} dst_port={}",
        proxy.id,
        pkt.src_port(),
        pkt.dst_port()
    );

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    switch_to_connected(proxy);

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), wanted_events(proxy))),
        ..Default::default()
    }
}

pub(crate) fn do_shutdown(proxy: &mut super::UnixProxy, pkt: &VsockPacket) {
    shutdown_host(proxy, pkt.flags());
}

fn shutdown_host(proxy: &mut super::UnixProxy, flags: u32) {
    let recv_off = flags & super::uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
    let send_off = flags & super::uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;

    let how = if recv_off && send_off {
        Shutdown::Both
    } else if recv_off {
        Shutdown::Read
    } else {
        Shutdown::Write
    };

    if let Err(e) = shutdown(proxy.fd.as_raw_fd(), how) {
        warn!("error sending shutdown to socket: {e}");
    }
}

pub(crate) fn release(proxy: &mut super::UnixProxy) -> ProxyUpdate {
    debug!(
        "release: id={}, tx_cnt={}, last_tx_cnt={}",
        proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
    );

    // A connection that never reached Connected carries no data and is not
    // registered for polling yet, so there is nothing to reserve its id for.
    // Keeping it would leave the accepted host socket open, and its peer
    // blocked, until the reaper reclaims the proxy.
    let remove_proxy = match proxy.status {
        ProxyStatus::ReverseInit | ProxyStatus::Connecting => ProxyRemoval::Immediate,
        _ => ProxyRemoval::Deferred,
    };

    ProxyUpdate {
        remove_proxy,
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::UnixProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    // A hung-up stream can still contain data, including more than the guest
    // currently has buffers or credit for. Only recv() can establish EOF.
    if evset.contains(EventSet::HANG_UP)
        && !matches!(
            proxy.status,
            ProxyStatus::Connected | ProxyStatus::WaitingCreditUpdate
        )
    {
        debug!("process_event: HANG_UP");

        if proxy.status == ProxyStatus::Connecting {
            push_connect_rsp(proxy, -libc::ECONNREFUSED);
        } else {
            proxy.push_reset();
        }

        proxy.status = ProxyStatus::Closed;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;

        return update;
    }

    if evset.intersects(EventSet::IN | EventSet::HANG_UP) {
        debug!("process_event: IN");
        if proxy.status == ProxyStatus::Connected {
            let (signal_queue, wait_credit) = proxy.recv_pkt();
            update.signal_queue = signal_queue;

            if wait_credit && proxy.status != ProxyStatus::WaitingCreditUpdate {
                proxy.status = ProxyStatus::WaitingCreditUpdate;
                let rx = MuxerRx::CreditRequest {
                    local_port: proxy.local_port,
                    peer_port: proxy.peer_port,
                    fwd_cnt: proxy.tx_cnt.0,
                };
                update.push_credit_req = Some(rx);
            }

            if proxy.status == ProxyStatus::Closed {
                debug!(
                    "process_event: endpoint closed, sending reset: id={}",
                    proxy.id
                );

                proxy.push_reset();
                update.signal_queue = true;
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
                update.remove_proxy = ProxyRemoval::Deferred;
                return update;
            } else if proxy.host_read_closed || proxy.status == ProxyStatus::WaitingCreditUpdate {
                debug!("process_event: disabling read polling");
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), wanted_events(proxy)));
            }
        } else {
            debug!("EventSet::IN while not connected: {:?}", proxy.status);
        }
    }

    if evset.contains(EventSet::OUT) {
        debug!("process_event: OUT");
        if proxy.status == ProxyStatus::Connecting {
            switch_to_connected(proxy);
            push_connect_rsp(proxy, 0);
            update.signal_queue = true;
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        } else if !proxy.pending.is_empty() {
            let flushed = flush_pending(proxy);
            update.signal_queue |= flushed.signal_queue;
            update.polling = flushed.polling;
            update.remove_proxy = flushed.remove_proxy;
        } else {
            debug!("EventSet::OUT with nothing pending: id={}", proxy.id);
        }
    }

    update
}

pub(crate) fn as_raw_fd(proxy: &super::UnixProxy) -> RawFd {
    proxy.fd.as_raw_fd()
}

pub(crate) fn new_acceptor_proxy(
    id: u64,
    path: &Path,
    peer_port: u32,
) -> Result<super::UnixAcceptorProxy, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    bind(
        fd.as_raw_fd(),
        &UnixAddr::new(path)
            .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    listen(
        &fd,
        Backlog::new(5)
            .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    Ok(super::UnixAcceptorProxy { id, fd, peer_port })
}

pub(crate) fn process_acceptor_event(
    proxy: &mut super::UnixAcceptorProxy,
    evset: EventSet,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        debug!("process_event: HANG_UP");
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
        return update;
    }
    if evset.contains(EventSet::IN) {
        match accept(proxy.fd.as_raw_fd()) {
            Ok(accept_fd) => {
                // Safe because we've just obtained the FD from the `accept` call above.
                let new_fd = unsafe { OwnedFd::from_raw_fd(accept_fd) };
                set_nosigpipe(&new_fd);
                update.new_proxy = Some((
                    proxy.peer_port,
                    new_fd,
                    AddressFamily::Unix,
                    NewProxyType::Unix,
                ));
            }
            Err(e) => warn!("error accepting connection: id={}, err={}", proxy.id, e),
        };
        update.signal_queue = true;
    }
    update
}

pub(crate) fn as_raw_acceptor_fd(proxy: &super::UnixAcceptorProxy) -> RawFd {
    proxy.fd.as_raw_fd()
}
