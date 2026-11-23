use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobPriority {
    Low = 1,
    Normal = 2,
    High = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Running { progress_pct: u8 },
    Retrying { attempt: u32, reason: String },
    Completed,
    Failed { reason: String },
}

#[derive(Debug, Clone)]
pub struct TransferJob {
    pub id: u64,
    pub priority: JobPriority,
    pub source: PathBuf,
    pub final_output: PathBuf,
    pub max_retries: u32,
    pub buffer_bytes: usize,
    pub verify_size: bool,
}

#[derive(Debug, Clone)]
struct QueuedEntry {
    seq: u64,
    job: TransferJob,
}

impl PartialEq for QueuedEntry {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}
impl Eq for QueuedEntry {}

impl PartialOrd for QueuedEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        let p_self = self.job.priority as u8;
        let p_other = other.job.priority as u8;
        p_self
            .cmp(&p_other)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

#[derive(Debug, Clone)]
pub struct JobSnapshot {
    pub id: u64,
    pub source: PathBuf,
    pub final_output: PathBuf,
    pub state: JobState,
    pub bytes_copied: u64,
    pub total_bytes: u64,
}

pub struct StreamQueueEngine {
    queue: Arc<Mutex<BinaryHeap<QueuedEntry>>>,
    snapshots: Arc<Mutex<Vec<JobSnapshot>>>,
    next_seq: Arc<Mutex<u64>>,
    concurrency: usize,
}

impl StreamQueueEngine {
    pub fn new(concurrency: usize) -> Self {
        Self {
            queue: Arc::new(Mutex::new(BinaryHeap::new())),
            snapshots: Arc::new(Mutex::new(Vec::new())),
            next_seq: Arc::new(Mutex::new(1)),
            concurrency: concurrency.max(1),
        }
    }

    pub fn enqueue(&self, job: TransferJob) {
        let total_bytes = job.source.metadata().map(|m| m.len()).unwrap_or(0);
        let snap = JobSnapshot {
            id: job.id,
            source: job.source.clone(),
            final_output: job.final_output.clone(),
            state: JobState::Queued,
            bytes_copied: 0,
            total_bytes,
        };
        {
            let mut snaps = self.snapshots.lock().unwrap();
            snaps.push(snap);
        }
        {
            let mut seq_guard = self.next_seq.lock().unwrap();
            let seq = *seq_guard;
            *seq_guard += 1;

            let mut q = self.queue.lock().unwrap();
            q.push(QueuedEntry { seq, job });
        }
    }

    pub fn snapshots(&self) -> Vec<JobSnapshot> {
        self.snapshots.lock().unwrap().clone()
    }

    pub fn run_all(&self) {
        let mut workers = Vec::new();
        for _ in 0..self.concurrency {
            let queue = Arc::clone(&self.queue);
            let snapshots = Arc::clone(&self.snapshots);

            workers.push(thread::spawn(move || loop {
                let next_job = {
                    let mut q = queue.lock().unwrap();
                    q.pop().map(|entry| entry.job)
                };

                let Some(job) = next_job else {
                    break;
                };

                execute_with_recovery(job, &snapshots);
            }));
        }

        for w in workers {
            let _ = w.join();
        }
    }
}

fn update_snapshot<F>(snapshots: &Arc<Mutex<Vec<JobSnapshot>>>, job_id: u64, updater: F)
where
    F: FnOnce(&mut JobSnapshot),
{
    let mut guard = snapshots.lock().unwrap();
    if let Some(item) = guard.iter_mut().find(|s| s.id == job_id) {
        updater(item);
    }
}

fn stream_copy_part(
    src: &Path,
    part_path: &Path,
    buf_size: usize,
    snapshots: &Arc<Mutex<Vec<JobSnapshot>>>,
    job_id: u64,
) -> io::Result<u64> {
    if let Some(parent) = part_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let src_file = File::open(src)?;
    let total = src_file.metadata()?.len().max(1);
    let mut reader = BufReader::with_capacity(buf_size, src_file);

    let out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)?;
    let mut writer = BufWriter::with_capacity(buf_size, out_file);

    let mut buf = vec![0u8; buf_size];
    let mut copied: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        copied += n as u64;

        let pct = ((copied.saturating_mul(100)) / total).min(99) as u8;
        update_snapshot(snapshots, job_id, |s| {
            s.bytes_copied = copied;
            s.state = JobState::Running { progress_pct: pct };
        });
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(copied)
}

fn execute_with_recovery(job: TransferJob, snapshots: &Arc<Mutex<Vec<JobSnapshot>>>) {
    let mut part_path = job.final_output.clone();
    let mut part_name = part_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    part_name.push_str(".part");
    part_path.set_file_name(part_name);

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        update_snapshot(snapshots, job.id, |s| {
            s.state = JobState::Running { progress_pct: 0 };
        });

        let result = (|| -> io::Result<()> {
            let src_len = job.source.metadata()?.len();
            let written = stream_copy_part(
                &job.source,
                &part_path,
                job.buffer_bytes.max(64 * 1024),
                snapshots,
                job.id,
            )?;

            if job.verify_size && written != src_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Size mismatch after copy ({written} != {src_len})"),
                ));
            }

            if job.final_output.exists() {
                fs::remove_file(&job.final_output)?;
            }
            fs::rename(&part_path, &job.final_output)?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                update_snapshot(snapshots, job.id, |s| {
                    s.bytes_copied = s.total_bytes;
                    s.state = JobState::Completed;
                });
                return;
            }
            Err(err) => {
                let _ = fs::remove_file(&part_path);

                let retryable = matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::WouldBlock
                );

                if retryable && attempt <= job.max_retries {
                    let msg = err.to_string();
                    update_snapshot(snapshots, job.id, |s| {
                        s.state = JobState::Retrying {
                            attempt,
                            reason: msg.clone(),
                        };
                    });
                    let backoff_ms = 250u64.saturating_mul(1u64 << attempt.min(5));
                    thread::sleep(Duration::from_millis(backoff_ms));
                } else {
                    update_snapshot(snapshots, job.id, |s| {
                        s.state = JobState::Failed {
                            reason: err.to_string(),
                        };
                    });
                    return;
                }
            }
        }
    }
}
