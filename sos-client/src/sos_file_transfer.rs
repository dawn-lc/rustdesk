//! SOS 文件传输模块
//!
//! 完全遵循上游 `ui_cm_interface::handle_fs` 的逻辑，不做任何额外路径变换。
//! 读取目录用 `hbb_common::fs::read_dir`，路径为客户端传来的原始路径。
//! 空路径用 `Config::get_home()`，与上游 CM 一致。

use hbb_common::fs::{self, DataSource, JobType, TransferJob};
use hbb_common::message_proto::{
    file_action, FileAction, FileResponse, FileTransferBlock,
    FileTransferReceiveRequest, FileTransferSendRequest,
};
use hbb_common::{message_proto::Message, ResultType};
use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;

pub struct FileTransferHandler {
    send_jobs: HashMap<i32, TransferJob>,
    recv_jobs: HashMap<i32, TransferJob>,
    response_tx: mpsc::Sender<Message>,
    response_rx: mpsc::Receiver<Message>,
}

/// 标准化 Windows 路径：将 /X:... 转换为 X:\...
#[cfg(windows)]
fn normalize_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('/') {
        if rest.len() >= 2
            && rest.as_bytes()[0].is_ascii_alphabetic()
            && rest.as_bytes()[1] == b':'
        {
            let drive_letter = rest.as_bytes()[0] as char;
            let sub = &rest[2..];
            if sub.is_empty() || sub == "/" {
                return format!("{}:\\", drive_letter);
            } else {
                let sub = sub.trim_start_matches('/');
                return format!("{}:\\{}", drive_letter, sub);
            }
        }
    }
    path.to_string()
}

#[cfg(not(windows))]
fn normalize_path(path: &str) -> String {
    path.to_string()
}

impl FileTransferHandler {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self { send_jobs: HashMap::new(), recv_jobs: HashMap::new(), response_tx: tx, response_rx: rx }
    }

    pub fn try_recv_response(&mut self) -> Option<Message> {
        self.response_rx.try_recv().ok()
    }

    pub fn has_send_jobs(&self) -> bool {
        !self.send_jobs.is_empty()
    }

    pub fn handle_action(&mut self, action: &FileAction) {
        use file_action::Union::*;
        if let Some(ref union) = action.union {
            match union {
                ReadDir(rd)       => Self::read_dir(&rd.path, rd.include_hidden, &self.response_tx),
                ReadEmptyDirs(rd) => Self::read_dir(&rd.path, rd.include_hidden, &self.response_tx),
                Send(s)           => { let mut s2 = s.clone(); s2.path = normalize_path(&s2.path); if let Err(e) = self.start_send_job(&s2) { let _ = self.response_tx.send(fs::new_error(s2.id, e, s2.file_num)); } }
                Receive(r)        => { let mut r2 = r.clone(); r2.path = normalize_path(&r2.path); if let Err(e) = self.start_receive_job(&r2) { let _ = self.response_tx.send(fs::new_error(r2.id, e, r2.file_num)); } }
                Cancel(c)         => { self.send_jobs.remove(&c.id); self.recv_jobs.remove(&c.id); }
                RemoveDir(d)      => Self::remove_dir(&normalize_path(&d.path), d.id, d.recursive, &self.response_tx),
                RemoveFile(f)     => Self::remove_file(&normalize_path(&f.path), f.id, f.file_num, &self.response_tx),
                Create(c)         => Self::create_dir(&normalize_path(&c.path), c.id, &self.response_tx),
                Rename(r)         => Self::rename(r.id, &normalize_path(&r.path), &r.new_name, &self.response_tx),
                AllFiles(f)       => Self::all_files(&normalize_path(&f.path), f.id, f.include_hidden, &self.response_tx),
                SendConfirm(_)    => {}
                _                 => {}
            }
        }
    }

    pub async fn handle_data(&mut self, block: &FileTransferBlock) {
        let id = block.id;
        if let Some(job) = self.recv_jobs.get_mut(&id) {
            if let Err(e) = job.write(block.clone()).await {
                let _ = self.response_tx.send(fs::new_error(id, e, block.file_num));
                self.recv_jobs.remove(&id);
            }
        }
    }

    /// 客户端通知传输完成：调用 modify_time() 将 .download 重命名为最终文件名
    pub fn handle_done(&mut self, id: i32, file_num: i32) {
        if let Some(job) = self.recv_jobs.remove(&id) {
            job.modify_time();
            log::info!("[FT] Receive job {} finalized (.download renamed)", id);
            let _ = self.response_tx.send(fs::new_done(id, file_num));
        }
    }

    /// 客户端通知传输错误：清理临时文件
    pub fn handle_error(&mut self, id: i32) {
        if let Some(job) = self.recv_jobs.remove(&id) {
            job.remove_download_file();
            log::info!("[FT] Receive job {} error, cleaned up temp files", id);
        }
    }

    /// 处理客户端发送的文件摘要（用于覆盖检测）
    pub fn handle_digest(&mut self, _digest: &hbb_common::message_proto::FileTransferDigest) {
        // To-do: implement digest check for overwrite detection
        log::debug!("[FT] Digest received (not implemented)");
    }

    pub async fn poll_send_jobs(&mut self) {
        for id in self.send_jobs.keys().copied().collect::<Vec<_>>() {
            self.process_send_job(id).await;
        }
    }

    async fn process_send_job(&mut self, id: i32) {
        let job = match self.send_jobs.get_mut(&id) { Some(j) => j, None => return };
        match job.read().await {
            Err(e)           => { let _ = self.response_tx.send(fs::new_error(id, e, -1)); self.send_jobs.remove(&id); }
            Ok(Some(blk))    => { let _ = self.response_tx.send(fs::new_block(blk)); }
            Ok(None) if job.job_completed() => { let _ = self.response_tx.send(fs::new_done(id, -1)); self.send_jobs.remove(&id); }
            Ok(None)         => {}
        }
    }

    // ── 严格遵循上游 CM handle_fs 各分支，不做路径变换 ──

    fn read_dir(original_dir: &str, include_hidden: bool, tx: &mpsc::Sender<Message>) {
        // 标准化路径用于文件系统读取
        let normalized = normalize_path(original_dir);
        let path = if normalized.is_empty() { hbb_common::config::Config::get_home() } else { Path::new(&normalized).to_path_buf() };
        log::info!("[FT] read_dir: original='{}' normalized='{}' path='{:?}'", original_dir, normalized, path);
        match fs::read_dir(&path, include_hidden) {
            Ok(mut fd) => {
                // 响应路径使用客户端原始路径（客户端按字符串精确匹配 task key）
                // 子目录导航时客户端会基于此路径构造下一级路径（如 /C:/Desktop），
                // 下一次 read_dir 的 normalize 会正确处理 /X:/path → X:\path
                fd.path = original_dir.to_string();
                log::info!("[FT] read_dir OK: {} entries, response_path='{}'", fd.entries.len(), fd.path);
                // 调试：记录前5个条目的名称和类型
                for (i, e) in fd.entries.iter().take(5).enumerate() {
                    log::info!("[FT] entry[{}]: name='{}' type={:?} is_hidden={} size={}",
                        i, e.name, e.entry_type.enum_value_or_default(),
                        e.is_hidden, e.size);
                }
                let mut msg = Message::new();
                let mut fr = FileResponse::new();
                fr.set_dir(fd);
                msg.set_file_response(fr);
                let _ = tx.send(msg);
            }
            Err(e) => {
                log::info!("[FT] read_dir FAIL: error={}", e);
                // 发送错误响应，否则客户端会一直重试
                let _ = tx.send(fs::new_error(-1, e, -1));
            }
        }
    }

    fn remove_dir(path: &str, id: i32, recursive: bool, tx: &mpsc::Sender<Message>) {
        let r = if recursive { std::fs::remove_dir_all(Path::new(path)) } else { std::fs::remove_dir(Path::new(path)) };
        match r {
            Ok(_) => { let mut msg = Message::new(); let mut fr = FileResponse::new();
                       let mut d = hbb_common::message_proto::FileDirectory::new(); d.path = path.to_owned();
                       fr.set_dir(d); msg.set_file_response(fr); let _ = tx.send(msg); }
            Err(e) => { let _ = tx.send(fs::new_error(id, e, -1)); }
        }
    }

    fn remove_file(path: &str, id: i32, file_num: i32, tx: &mpsc::Sender<Message>) {
        match std::fs::remove_file(Path::new(path)) {
            Ok(_) => { let mut msg = Message::new(); let mut fr = FileResponse::new();
                       let mut d = hbb_common::message_proto::FileDirectory::new(); d.path = path.to_owned();
                       fr.set_dir(d); msg.set_file_response(fr); let _ = tx.send(msg); }
            Err(e) => { let _ = tx.send(fs::new_error(id, e, file_num)); }
        }
    }

    fn create_dir(path: &str, id: i32, tx: &mpsc::Sender<Message>) {
        match std::fs::create_dir_all(Path::new(path)) {
            Ok(_) => { let mut msg = Message::new(); let mut fr = FileResponse::new();
                       let mut d = hbb_common::message_proto::FileDirectory::new(); d.path = path.to_owned();
                       fr.set_dir(d); msg.set_file_response(fr); let _ = tx.send(msg); }
            Err(e) => { let _ = tx.send(fs::new_error(id, e, -1)); }
        }
    }

    fn rename(id: i32, path: &str, new_name: &str, tx: &mpsc::Sender<Message>) {
        let old = Path::new(path);
        let new = old.parent().map(|p| p.join(new_name)).unwrap_or_else(|| Path::new(new_name).to_path_buf());
        match std::fs::rename(old, &new) {
            Ok(_) => { let mut msg = Message::new(); let mut fr = FileResponse::new();
                       let mut d = hbb_common::message_proto::FileDirectory::new(); d.path = new.to_string_lossy().to_string();
                       fr.set_dir(d); msg.set_file_response(fr); let _ = tx.send(msg); }
            Err(e) => { let _ = tx.send(fs::new_error(id, e, -1)); }
        }
    }

    fn all_files(path: &str, id: i32, include_hidden: bool, tx: &mpsc::Sender<Message>) {
        match fs::get_recursive_files(path, include_hidden) {
            Ok(files) => { let _ = tx.send(fs::new_dir(id, path.to_owned(), files)); }
            Err(e)    => { let _ = tx.send(fs::new_error(id, e, -1)); }
        }
    }

    fn start_send_job(&mut self, send: &FileTransferSendRequest) -> ResultType<()> {
        let job = TransferJob::new_read(
            send.id, JobType::Generic, String::new(),
            DataSource::FilePath(Path::new(&send.path).to_path_buf()),
            send.file_num, send.include_hidden, true, false,
        )?;
        self.send_jobs.insert(send.id, job);
        Ok(())
    }

    fn start_receive_job(&mut self, recv: &FileTransferReceiveRequest) -> ResultType<()> {
        let mut job = TransferJob::new_write(
            recv.id, JobType::Generic, String::new(),
            DataSource::FilePath(Path::new(&recv.path).to_path_buf()),
            recv.file_num, false, false, false,
        );
        job.set_files(recv.files.clone())?;
        self.recv_jobs.insert(recv.id, job);
        Ok(())
    }
}
