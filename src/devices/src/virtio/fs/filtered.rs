// A writable PassthroughFs that shows the guest only what an allowlist names.
//
// The read-only share filters names only: nothing it shows can change. A
// writable share must also keep the guest from changing what it does not see.
// The directories above an allowed path ("partial") are the fixed way to it:
// their listings are filtered as on a read-only share, and every operation
// that would add, remove or rename a name in one, or change one's own
// attributes, fails with EACCES. Below an allowed path everything passes
// through, writes included, and the host's permissions decide.
//
// An inode reaches the guest only through a lookup or a listing, both
// filtered, so an operation by inode alone touches only what the guest may
// see; the partial directories themselves are the one exception, and are
// checked by inode.
//
// IMPORTANT: When adding new methods to the FileSystem trait, review this
// wrapper: an operation that takes a parent directory and a name must check
// `partial`. Unoverridden methods fall back to the trait defaults (ENOSYS).
#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::ffi::CStr;
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::time::Duration;

#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use super::allowlist::{self, Allowlist, Visibility};
use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::fuse;
use super::inode_alloc::InodeAllocator;
use super::passthrough::{self, PassthroughFs};
#[cfg(target_os = "windows")]
use super::windows::fs_utils;
use crate::virtio::bindings;
use crate::virtio::linux_errno;

type Inode = u64;
type Handle = u64;

pub struct PassthroughFsFiltered {
    inner: PassthroughFs,
    allowlist: Option<Arc<Allowlist>>,
    negative_timeout: Duration,
}

impl PassthroughFsFiltered {
    pub fn new(
        cfg: passthrough::Config,
        inode_alloc: Arc<InodeAllocator>,
        allowlist: Option<Arc<Allowlist>>,
        negative_timeout: Duration,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: PassthroughFs::new(cfg, inode_alloc)?,
            allowlist,
            negative_timeout,
        })
    }

    /// Whether `inode` is a directory above an allowed path, which the guest
    /// may walk through and not change.
    fn partial(&self, inode: Inode) -> bool {
        self.allowlist.as_ref().is_some_and(|a| a.is_partial(inode))
    }

    /// EACCES for a change to directory `inode` when it is partial.
    fn fixed(&self, inode: Inode) -> io::Result<()> {
        if self.partial(inode) {
            return Err(linux_errno::eacces());
        }
        Ok(())
    }

    fn listed(&self, inode: Inode, name: &[u8], entry_inode: Option<Inode>) -> bool {
        let Some(allowlist) = &self.allowlist else {
            return true;
        };
        match allowlist.visibility(inode, name) {
            Visibility::Unfiltered | Visibility::Shown { partial: false } => true,
            Visibility::Shown { partial: true } => {
                if let Some(child) = entry_inode {
                    allowlist.record(inode, name, child);
                }
                true
            }
            Visibility::Hidden => false,
        }
    }
}

impl FileSystem for PassthroughFsFiltered {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.inner.init(capable)
    }

    fn destroy(&self) {
        self.inner.destroy()
    }

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        allowlist::lookup(
            self.allowlist.as_deref(),
            self.negative_timeout,
            parent,
            name.to_bytes(),
            || self.inner.lookup(ctx, parent, name),
        )
    }

    fn forget(&self, ctx: Context, inode: Inode, count: u64) {
        self.inner.forget(ctx, inode, count)
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(Inode, u64)>) {
        self.inner.batch_forget(ctx, requests)
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.inner.getattr(ctx, inode, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.fixed(inode)?;
        self.inner.setattr(ctx, inode, attr, handle, valid)
    }

    fn readlink(&self, ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        self.inner.readlink(ctx, inode)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.fixed(parent)?;
        self.inner.symlink(ctx, linkname, parent, name, extensions)
    }

    fn mknod(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.fixed(inode)?;
        self.inner
            .mknod(ctx, inode, name, mode, rdev, umask, extensions)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.fixed(parent)?;
        self.inner.mkdir(ctx, parent, name, mode, umask, extensions)
    }

    fn unlink(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.fixed(parent)?;
        self.inner.unlink(ctx, parent, name)
    }

    fn rmdir(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.fixed(parent)?;
        self.inner.rmdir(ctx, parent, name)
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.fixed(olddir)?;
        self.fixed(newdir)?;
        self.inner
            .rename(ctx, olddir, oldname, newdir, newname, flags)
    }

    fn link(
        &self,
        ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        self.fixed(newparent)?;
        self.inner.link(ctx, inode, newparent, newname)
    }

    fn open(
        &self,
        ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.inner.open(ctx, inode, kill_priv, flags)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        // O_CREAT on a hidden name would make, or truncate, a file the guest
        // may not see; on an allowed one the guest opens it, which a lookup
        // and an open serve.
        self.fixed(parent)?;
        self.inner
            .create(ctx, parent, name, mode, kill_priv, flags, umask, extensions)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        self.inner
            .read(ctx, inode, handle, w, size, offset, lock_owner, flags)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        self.inner.write(
            ctx,
            inode,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn flush(&self, ctx: Context, inode: Inode, handle: Handle, lock_owner: u64) -> io::Result<()> {
        self.inner.flush(ctx, inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        self.inner.fsync(ctx, inode, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        self.inner
            .fallocate(ctx, inode, handle, mode, offset, length)
    }

    fn release(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
        handle: Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.inner
            .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
    }

    fn statfs(&self, ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        self.inner.statfs(ctx, inode)
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.fixed(inode)?;
        self.inner.setxattr(ctx, inode, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.inner.getxattr(ctx, inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        self.inner.listxattr(ctx, inode, size)
    }

    fn removexattr(&self, ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        self.fixed(inode)?;
        self.inner.removexattr(ctx, inode, name)
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.inner.opendir(ctx, inode, flags)
    }

    fn readdir<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if !self.partial(inode) {
            return self
                .inner
                .readdir(ctx, inode, handle, size, offset, add_entry);
        }
        let mut add_entry = add_entry;
        // A hidden entry returns 1, not 0: the passthrough reads 0 as a
        // full buffer and stops, as it does for "." and "..".
        self.inner
            .readdir(ctx, inode, handle, size, offset, |entry| {
                if self.listed(inode, entry.name, None) {
                    add_entry(entry)
                } else {
                    Ok(1)
                }
            })
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        if !self.partial(inode) {
            return self
                .inner
                .readdirplus(ctx, inode, handle, size, offset, add_entry);
        }
        let mut add_entry = add_entry;
        self.inner
            .readdirplus(ctx, inode, handle, size, offset, |dir_entry, entry| {
                if self.listed(inode, dir_entry.name, Some(entry.inode)) {
                    add_entry(dir_entry, entry)
                } else {
                    // The guest never learns this inode to forget it.
                    if entry.inode != 0 {
                        self.inner.forget(ctx, entry.inode, 1);
                    }
                    Ok(1)
                }
            })
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.inner.fsyncdir(ctx, inode, datasync, handle)
    }

    fn releasedir(&self, ctx: Context, inode: Inode, flags: u32, handle: Handle) -> io::Result<()> {
        self.inner.releasedir(ctx, inode, flags, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        #[cfg(not(target_os = "windows"))]
        let w_ok = libc::W_OK;
        #[cfg(target_os = "windows")]
        let w_ok = fs_utils::W_OK;
        if mask & (w_ok as u32) != 0 {
            self.fixed(inode)?;
        }
        self.inner.access(ctx, inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.inner.lseek(ctx, inode, handle, offset, whence)
    }

    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: Inode,
        handle_in: Handle,
        offset_in: u64,
        inode_out: Inode,
        handle_out: Handle,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        self.inner.copyfilerange(
            ctx, inode_in, handle_in, offset_in, inode_out, handle_out, offset_out, len, flags,
        )
    }

    fn setupmapping(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        self.inner.setupmapping(
            ctx,
            inode,
            handle,
            foffset,
            len,
            flags,
            moffset,
            host_shm_base,
            shm_size,
            #[cfg(target_os = "macos")]
            map_sender,
        )
    }

    fn removemapping(
        &self,
        ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        self.inner.removemapping(
            ctx,
            requests,
            host_shm_base,
            shm_size,
            #[cfg(target_os = "macos")]
            map_sender,
        )
    }

    fn ioctl(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        self.inner.ioctl(
            ctx, inode, handle, flags, cmd, arg, in_size, out_size, exit_code,
        )
    }
}
