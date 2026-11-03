// Which paths of a read-only share the guest may see.
//
// An allowlist names paths relative to the share's root. A directory above
// an allowed path ("partial") shows only the names that lead to one; an
// allowed path and everything below it pass through unchanged. A host
// shares its whole Nix store this way and a guest sees only its own
// closure, with no bind mounts on the host.
//
// Partial directories are tracked by the inode their lookup returned, with
// their path from the root. Inodes come from an `InodeAllocator`, which
// never reuses a number, so an entry stays valid after the guest forgets
// the inode.
//
// An allowlist read from a file reads it again when a lookup in a partial
// directory misses and the file has changed, so a host adds paths while
// the guest runs by appending them. The guest's kernel may hold a negative
// dentry for a name it looked up before: the guest drops its caches.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use super::fuse::ROOT_ID;

type Inode = u64;
type Name = Vec<u8>;

#[derive(Debug, Default)]
struct Node {
    children: HashMap<Name, Node>,
    /// An allowed path: nothing below it is filtered.
    allowed: bool,
}

impl Node {
    fn walk(&self, path: &[Name]) -> Option<&Node> {
        let mut node = self;
        for name in path {
            if node.allowed {
                return Some(node);
            }
            node = node.children.get(name)?;
        }
        Some(node)
    }
}

/// What a lookup of one name in a directory may return.
#[derive(Debug, PartialEq, Eq)]
pub enum Visibility {
    /// The directory is not partial: the name is not filtered.
    Unfiltered,
    /// The directory is partial and no allowed path goes through the name.
    Hidden,
    /// An allowed path goes through the name. `partial` says whether the
    /// name is a directory above an allowed path, whose inode the caller
    /// records with `record`.
    Shown { partial: bool },
}

/// What tells a changed file from an unchanged one.
type Signature = (u64, Option<SystemTime>);

#[derive(Debug)]
struct State {
    tree: Node,
    partial: HashMap<Inode, Vec<Name>>,
    signature: Option<Signature>,
}

#[derive(Debug)]
pub struct Allowlist {
    root: PathBuf,
    file: Option<PathBuf>,
    state: Mutex<State>,
}

fn invalid(path: &Path, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("allowlist path {}: {why}", path.display()),
    )
}

fn tree<I, P>(root: &Path, paths: I) -> io::Result<Node>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut top = Node::default();
    for path in paths {
        let path = path.as_ref();
        let relative = if path.is_absolute() {
            path.strip_prefix(root)
                .map_err(|_| invalid(path, "not below the share's root"))?
        } else {
            path
        };
        let mut node = &mut top;
        for component in relative.components() {
            match component {
                Component::Normal(name) => {
                    node = node
                        .children
                        .entry(name.as_encoded_bytes().to_vec())
                        .or_default();
                }
                Component::CurDir => {}
                _ => return Err(invalid(path, "names a parent directory")),
            }
        }
        node.allowed = true;
    }
    Ok(top)
}

fn signature(file: &Path) -> io::Result<Signature> {
    let meta = fs::metadata(file)?;
    Ok((meta.len(), meta.modified().ok()))
}

fn read(file: &Path) -> io::Result<Vec<PathBuf>> {
    Ok(fs::read_to_string(file)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect())
}

impl Allowlist {
    /// An allowlist of `paths` for a share rooted at `root`. A path is
    /// absolute and below `root`, or relative to it. An empty or `root`
    /// path allows the whole share.
    pub fn new<I, P>(root: &Path, paths: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        Self::with(root.to_path_buf(), None, tree(root, paths)?, None)
    }

    /// An allowlist read from `file`, one path per line, read again when it
    /// changes.
    pub fn from_file(root: &Path, file: &Path) -> io::Result<Self> {
        let signature = signature(file)?;
        let tree = tree(root, read(file)?)?;
        Self::with(
            root.to_path_buf(),
            Some(file.to_path_buf()),
            tree,
            Some(signature),
        )
    }

    fn with(
        root: PathBuf,
        file: Option<PathBuf>,
        tree: Node,
        signature: Option<Signature>,
    ) -> io::Result<Self> {
        let mut partial = HashMap::new();
        partial.insert(ROOT_ID, Vec::new());
        Ok(Self {
            root,
            file,
            state: Mutex::new(State {
                tree,
                partial,
                signature,
            }),
        })
    }

    /// Whether `name` in directory `parent` is visible.
    pub fn visibility(&self, parent: Inode, name: &[u8]) -> Visibility {
        let mut state = self.state.lock().unwrap();
        let verdict = Self::judge(&state, parent, name);
        if verdict == Visibility::Hidden && self.reload(&mut state) {
            return Self::judge(&state, parent, name);
        }
        verdict
    }

    fn judge(state: &State, parent: Inode, name: &[u8]) -> Visibility {
        let Some(path) = state.partial.get(&parent) else {
            return Visibility::Unfiltered;
        };
        let Some(node) = state.tree.walk(path) else {
            // A path the file listed once and lists no more.
            return Visibility::Hidden;
        };
        // The kernel looks up "." and ".." too. Each names the directory
        // itself or one above it, which is partial already or the root.
        if node.allowed || name == b"." || name == b".." {
            return Visibility::Unfiltered;
        }
        match node.children.get(name) {
            None => Visibility::Hidden,
            Some(child) => Visibility::Shown {
                partial: !child.allowed,
            },
        }
    }

    /// Reads the file again if it changed; whether it did.
    fn reload(&self, state: &mut State) -> bool {
        let Some(file) = &self.file else {
            return false;
        };
        let Ok(now) = signature(file) else {
            return false;
        };
        if state.signature == Some(now) {
            return false;
        }
        match read(file).and_then(|paths| tree(&self.root, paths)) {
            Ok(tree) => {
                state.tree = tree;
                state.signature = Some(now);
                true
            }
            Err(e) => {
                log::warn!("allowlist {}: {e}", file.display());
                false
            }
        }
    }

    /// Records the inode a lookup of `name` in `parent` returned, for a
    /// name that `visibility` called partial.
    pub fn record(&self, parent: Inode, name: &[u8], inode: Inode) {
        let mut state = self.state.lock().unwrap();
        if let Some(path) = state.partial.get(&parent) {
            let mut path = path.clone();
            path.push(name.to_vec());
            state.partial.insert(inode, path);
        }
    }

    /// Whether `inode` is a partial directory, whose listing is filtered.
    pub fn is_partial(&self, inode: Inode) -> bool {
        let state = self.state.lock().unwrap();
        state
            .partial
            .get(&inode)
            .is_some_and(|path| state.tree.walk(path).is_none_or(|node| !node.allowed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn store() -> Allowlist {
        Allowlist::new(
            Path::new("/nix"),
            [
                "/nix/store/aaa-hello",
                "store/bbb-glibc",
                "/nix/store/aaa-hello/bin",
            ],
        )
        .unwrap()
    }

    #[test]
    fn the_root_shows_only_the_way_to_an_allowed_path() {
        let list = store();
        assert!(list.is_partial(ROOT_ID));
        assert_eq!(list.visibility(ROOT_ID, b"var"), Visibility::Hidden);
        assert_eq!(
            list.visibility(ROOT_ID, b"store"),
            Visibility::Shown { partial: true }
        );
    }

    #[test]
    fn a_partial_directory_is_filtered_once_recorded() {
        let list = store();
        assert_eq!(list.visibility(7, b"ccc-other"), Visibility::Unfiltered);
        list.record(ROOT_ID, b"store", 7);
        assert!(list.is_partial(7));
        assert_eq!(list.visibility(7, b"ccc-other"), Visibility::Hidden);
        assert_eq!(
            list.visibility(7, b"aaa-hello"),
            Visibility::Shown { partial: false }
        );
        assert_eq!(list.visibility(7, b".."), Visibility::Unfiltered);
    }

    #[test]
    fn below_an_allowed_path_nothing_is_filtered() {
        let list = store();
        list.record(ROOT_ID, b"store", 7);
        // aaa-hello is allowed, so its inode is never recorded.
        assert_eq!(list.visibility(8, b"anything"), Visibility::Unfiltered);
        assert!(!list.is_partial(8));
    }

    #[test]
    fn the_root_itself_allows_everything() {
        let list = Allowlist::new(Path::new("/nix"), ["/nix"]).unwrap();
        assert!(!list.is_partial(ROOT_ID));
        assert_eq!(list.visibility(ROOT_ID, b"var"), Visibility::Unfiltered);
    }

    #[test]
    fn a_path_outside_the_root_or_with_dotdot_is_refused() {
        assert!(Allowlist::new(Path::new("/nix"), ["/etc/passwd"]).is_err());
        assert!(Allowlist::new(Path::new("/nix"), ["store/../var"]).is_err());
    }

    #[test]
    fn a_path_appended_to_the_file_shows_on_the_next_miss() {
        let dir = std::env::temp_dir().join(format!("allowlist-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("paths");
        fs::write(&file, "/nix/store/aaa-hello\n").unwrap();
        let list = Allowlist::from_file(Path::new("/nix"), &file).unwrap();
        list.record(ROOT_ID, b"store", 7);
        assert_eq!(list.visibility(7, b"ccc-new"), Visibility::Hidden);
        let mut appended = fs::OpenOptions::new().append(true).open(&file).unwrap();
        writeln!(appended, "/nix/store/ccc-new").unwrap();
        drop(appended);
        assert_eq!(
            list.visibility(7, b"ccc-new"),
            Visibility::Shown { partial: false }
        );
        assert_eq!(
            list.visibility(7, b"aaa-hello"),
            Visibility::Shown { partial: false }
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
