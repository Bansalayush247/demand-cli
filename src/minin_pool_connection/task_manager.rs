use std::sync::Arc;

use crate::shared::utils::AbortOnDrop;
use roles_logic_sv2::utils::Mutex;
use tokio::sync::mpsc;
use tracing::debug;

#[derive(Debug)]
#[allow(dead_code)]
enum Task {
    Sv2UpRelayUp(AbortOnDrop),
    Sv2UpRelayDown(AbortOnDrop),
}

pub struct TaskManager {
    send_task: mpsc::Sender<Task>,
    abort: Option<AbortOnDrop>,
}

impl TaskManager {
    pub fn initialize() -> Arc<Mutex<Self>> {
        let (sender, mut receiver) = mpsc::channel(10);
        let handle = tokio::task::spawn(async move {
            let mut tasks = vec![];
            while let Some(task) = receiver.recv().await {
                tasks.push(task);
            }
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1000)).await;
            }
        });
        debug!("Mining Pool Task Manager initialized");
        Arc::new(Mutex::new(Self {
            send_task: sender,
            abort: Some(handle.into()),
        }))
    }

    pub fn get_aborter(&mut self) -> Option<AbortOnDrop> {
        self.abort.take()
    }
    pub async fn add_sv2_relay_up(
        self_: Arc<Mutex<Self>>,
        abortable: AbortOnDrop,
    ) -> Result<(), ()> {
        let send_task = self_.safe_lock(|s| s.send_task.clone()).unwrap();
        send_task
            .send(Task::Sv2UpRelayUp(abortable))
            .await
            .map_err(|_| ())
    }
    pub async fn add_sv2_relay_down(
        self_: Arc<Mutex<Self>>,
        abortable: AbortOnDrop,
    ) -> Result<(), ()> {
        let send_task = self_.safe_lock(|s| s.send_task.clone()).unwrap();
        send_task
            .send(Task::Sv2UpRelayDown(abortable))
            .await
            .map_err(|_| ())
    }
}
