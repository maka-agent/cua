// SPDX-License-Identifier: MIT

//! Same-user supervisor connections. A live connection holds one browser user;
//! EOF releases it, including when a runtime crashes.

use super::{HandoffError, storage};
use crate::browser::local_ipc::{self, EndpointAddress, LocalListener, LocalStream};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Descriptor {
    generation: String,
    pid: u32,
    address: EndpointAddress,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    Acquire {
        owner: uuid::Uuid,
        extension_id: String,
    },
    Native {
        pid: u32,
    },
    NativeReady,
    StopNative,
    ReleaseOwner {
        owner: uuid::Uuid,
    },
    Ready,
    Release,
    Released {
        users: usize,
    },
    Failed {
        message: String,
    },
}

pub struct Connection(LocalStream);

impl Connection {
    pub async fn connect(directory: &Path) -> Result<Self, HandoffError> {
        let path = directory.join("supervisor.json");
        let descriptor: Descriptor = tokio::task::spawn_blocking(move || {
            let bytes = local_ipc::load_private_installation_config(&path)?;
            Ok::<Descriptor, HandoffError>(serde_json::from_slice(&bytes)?)
        })
        .await
        .map_err(|error| {
            HandoffError::Configuration(format!("supervisor descriptor task: {error}"))
        })??;
        Ok(Self(
            local_ipc::connect_service(
                directory,
                &descriptor.generation,
                &descriptor.address,
                descriptor.pid,
            )
            .await?,
        ))
    }

    pub async fn send(&mut self, message: &Message) -> Result<(), HandoffError> {
        local_ipc::write_json(&mut self.0, &serde_json::to_value(message)?).await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Option<Message>, HandoffError> {
        local_ipc::read_json(&mut self.0)
            .await?
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }
}

pub struct Listener {
    listener: LocalListener,
    descriptor: Descriptor,
}

impl Listener {
    /// Caller owns the registration transaction lock before publishing a leader.
    pub async fn bind(directory: &Path) -> Result<Self, HandoffError> {
        local_ipc::ensure_private_state_directory(directory)?;
        let generation = uuid::Uuid::new_v4().to_string();
        let (listener, address) = LocalListener::bind(directory, &generation).await?;
        let descriptor = Descriptor {
            generation,
            pid: std::process::id(),
            address,
        };
        if let Err(error) = storage::atomic_file(
            &directory.join("supervisor.json"),
            &serde_json::to_vec(&descriptor)?,
            None,
        ) {
            listener.cleanup()?;
            return Err(error.into());
        }
        Ok(Self {
            listener,
            descriptor,
        })
    }

    pub async fn accept(&mut self) -> Result<Connection, HandoffError> {
        let (stream, _) = self.listener.accept().await?;
        Ok(Connection(stream))
    }

    pub fn close(self, directory: &Path) -> Result<(), HandoffError> {
        let path = directory.join("supervisor.json");
        let bytes = local_ipc::load_private_installation_config(&path)?;
        let current: Descriptor = serde_json::from_slice(&bytes)?;
        let result = if current.generation == self.descriptor.generation
            && current.pid == self.descriptor.pid
        {
            std::fs::remove_file(&path)
                .and_then(|()| storage::sync_directory(directory))
                .map_err(Into::into)
        } else {
            Err(HandoffError::Configuration(
                "supervisor descriptor was replaced".into(),
            ))
        };
        self.listener.cleanup()?;
        result
    }
}
