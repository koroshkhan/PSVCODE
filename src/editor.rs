use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct EditableEntry {
    pub rel_path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub enum EditOperation {
    Rename { from_rel: String, to_rel: String },
    Delete { rel_path: String },
    AddOrReplace { src_file: PathBuf, target_rel: String },
}

#[derive(Debug, Default)]
pub struct DumpEditorSession {
    pub root_dir: Option<PathBuf>,
    pub entries: Vec<EditableEntry>,
    pub pending_ops: Vec<EditOperation>,
}

impl DumpEditorSession {
    pub fn load_folder(&mut self, dir: &Path) -> io::Result<()> {
        if !dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Target dump folder does not exist.",
            ));
        }
        self.root_dir = Some(dir.to_path_buf());
        self.pending_ops.clear();
        self.refresh_entries()
    }

    pub fn refresh_entries(&mut self) -> io::Result<()> {
        let Some(root) = &self.root_dir else {
            return Ok(());
        };
        let mut list = Vec::new();
        let mut stack = vec![root.clone()];

        while let Some(d) = stack.pop() {
            for entry in fs::read_dir(&d)?.flatten() {
                let p = entry.path();
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                let is_dir = p.is_dir();
                let size = if is_dir {
                    0
                } else {
                    entry.metadata().map(|m| m.len()).unwrap_or(0)
                };
                list.push(EditableEntry {
                    rel_path: rel,
                    size,
                    is_dir,
                });
                if is_dir {
                    stack.push(p);
                }
            }
        }
        list.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        self.entries = list;
        Ok(())
    }

    pub fn stage_op(&mut self, op: EditOperation) {
        self.pending_ops.push(op);
    }

    pub fn undo_last(&mut self) -> bool {
        self.pending_ops.pop().is_some()
    }

    pub fn discard_all(&mut self) {
        self.pending_ops.clear();
    }

    pub fn apply_changes(&mut self) -> io::Result<usize> {
        let Some(root) = self.root_dir.clone() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "No folder loaded."));
        };

        let ops: Vec<EditOperation> = self.pending_ops.drain(..).collect();
        let applied = ops.len();

        for op in ops {
            match op {
                EditOperation::Rename { from_rel, to_rel } => {
                    let from_p = root.join(from_rel);
                    let to_p = root.join(to_rel);
                    if let Some(parent) = to_p.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    if from_p.exists() {
                        fs::rename(&from_p, &to_p)?;
                    }
                }
                EditOperation::Delete { rel_path } => {
                    let target = root.join(rel_path);
                    if target.is_dir() {
                        fs::remove_dir_all(&target)?;
                    } else if target.is_file() {
                        fs::remove_file(&target)?;
                    }
                }
                EditOperation::AddOrReplace { src_file, target_rel } => {
                    let dst = root.join(target_rel);
                    if let Some(parent) = dst.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::copy(&src_file, &dst)?;
                }
            }
        }

        self.refresh_entries()?;
        Ok(applied)
    }
}
