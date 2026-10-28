// SPDX-License-Identifier: MIT

//! Shared accounting for JSON payload bytes retained by broker queues.
//!
//! This bounds queued logical payload bytes, not caller-owned values, temporary
//! JSON decoding allocations, or values still owned by an in-flight caller.
//! Move the same charge with one logical payload through input, pending,
//! outbound, early-event and delivery queues. Do not deep-clone a payload and
//! reuse its charge for both copies; separately queued copies need separate
//! charges. Keep the final wrapper alive until its socket write completes.

use super::extension_framing::{self, Direction, FrameError};
use serde::{Serialize, Serializer};
use std::{fmt, sync::Arc, time::Duration};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// One extension host's queued JSON budget; a single valid 64MiB message fits.
pub(crate) const QUEUED_JSON_BYTES: usize = 128 * 1024 * 1024;

/// Final local IPC egress budget, matching the existing client write budget.
/// This limits shutdown drainage only; it never extends a command timeout or
/// proves that a peer consumed any already queued fact.
pub(crate) const IPC_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub(crate) enum DeliveryError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("queued JSON byte budget is closed")]
    Closed(#[from] AcquireError),
    #[error("queued JSON byte count does not fit the semaphore permit range")]
    PermitRange,
    #[error("queued JSON byte budget is unavailable: {0}")]
    Unavailable(#[from] TryAcquireError),
}

/// Cloneable handle to one shared queued-byte budget.
#[derive(Clone)]
pub(crate) struct ByteBudget {
    permits: Arc<Semaphore>,
}

impl ByteBudget {
    pub(crate) fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(QUEUED_JSON_BYTES)),
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn test_with_capacity(bytes: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(bytes)),
        }
    }

    /// Charge one JSON payload before admitting it into a broker queue.
    ///
    /// The counting serialization uses the existing 64MiB logical/extension-input
    /// bound. Its temporary buffer is dropped before waiting for permits.
    /// Backpressure does not create cleanup authority or replay a command.
    ///
    /// # Errors
    /// Rejects invalid or oversized serialization, a closed budget, or a byte
    /// count outside the semaphore's range. Closing the budget wakes waiters.
    pub(crate) async fn charge<T: Serialize + Sync>(
        &self,
        value: &T,
    ) -> Result<Arc<ByteCharge>, DeliveryError> {
        let bytes = {
            let encoded = extension_framing::encode_json(value, Direction::ChromeToHost)?;
            encoded.len()
        };
        let permits = u32::try_from(bytes).map_err(|_| DeliveryError::PermitRange)?;
        let permit = self.permits.clone().acquire_many_owned(permits).await?;
        Ok(Arc::new(ByteCharge {
            bytes,
            _permit: permit,
        }))
    }

    /// Charge a bounded actor-generated payload without awaiting its maka queue.
    ///
    /// # Errors
    /// Rejects oversized serialization, a closed or saturated budget, and a
    /// byte count outside the permit range. No permits are retained on failure.
    pub(crate) fn try_charge<T: Serialize + Sync>(
        &self,
        value: &T,
    ) -> Result<Arc<ByteCharge>, DeliveryError> {
        let bytes = extension_framing::encode_json(value, Direction::ChromeToHost)?.len();
        let permits = u32::try_from(bytes).map_err(|_| DeliveryError::PermitRange)?;
        let permit = self.permits.clone().try_acquire_many_owned(permits)?;
        Ok(Arc::new(ByteCharge {
            bytes,
            _permit: permit,
        }))
    }

    pub(crate) fn available_bytes(&self) -> usize {
        self.permits.available_permits()
    }

    /// Stop queue admission without revoking or rewriting any browser authority.
    pub(crate) fn close(&self) {
        self.permits.close();
    }
}

impl Default for ByteBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ByteBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByteBudget")
            .field("capacity", &QUEUED_JSON_BYTES)
            .field("available", &self.available_bytes())
            .finish()
    }
}

/// The last shared reference releases this logical payload's byte reservation.
pub(crate) struct ByteCharge {
    bytes: usize,
    _permit: OwnedSemaphorePermit,
}

impl ByteCharge {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl fmt::Debug for ByteCharge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByteCharge")
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// A payload and its queue reservation; serialization exposes only the payload.
///
/// `None` is reserved for fixed-size host lifecycle signals which carry no
/// arbitrary admitted payload. The constructor performs no allocation or I/O.
/// No Clone implementation is provided, so copying a large event requires an
/// explicit decision about byte accounting at its call site.
pub(crate) struct Queued<T> {
    event: T,
    charge: Option<Arc<ByteCharge>>,
}

impl<T> Queued<T> {
    pub(crate) fn new(event: T, charge: Option<Arc<ByteCharge>>) -> Self {
        Self { event, charge }
    }

    pub(crate) fn event(&self) -> &T {
        &self.event
    }

    /// Move both pieces together when changing queue type or transport stage.
    pub(crate) fn into_parts(self) -> (T, Option<Arc<ByteCharge>>) {
        (self.event, self.charge)
    }
}

impl<T: Serialize> Serialize for Queued<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.event.serialize(serializer)
    }
}

impl<T> fmt::Debug for Queued<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Extension messages can contain endpoint capabilities and page content.
        formatter
            .debug_struct("Queued")
            .field("event_type", &std::any::type_name::<T>())
            .field(
                "charged_bytes",
                &self.charge.as_ref().map(|charge| charge.bytes()),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serialization_remains_identical_and_counts_utf8_bytes() {
        let budget = ByteBudget::new();
        let value = json!({"text":"你好"});
        let charge = budget.try_charge(&value).unwrap();
        assert_eq!(charge.bytes(), "{\"text\":\"你好\"}".len());
        let queued = Queued::new(value, Some(charge));
        assert_eq!(
            serde_json::to_vec(&queued).unwrap(),
            "{\"text\":\"你好\"}".as_bytes()
        );
        assert_eq!(queued.event()["text"], "你好");
        drop(queued);
        assert_eq!(budget.available_bytes(), QUEUED_JSON_BYTES);
    }

    #[tokio::test]
    async fn moving_through_queues_does_not_double_charge_or_release_early() {
        let budget = ByteBudget::new();
        let value = json!({"id":1});
        let charge = budget.charge(&value).await.unwrap();
        let bytes = charge.bytes();
        let second_reference = charge.clone();
        let queued = Queued::new(value, Some(charge));
        let (event, charge) = queued.into_parts();
        let writer_owned = Queued::new(event, charge);
        assert_eq!(budget.available_bytes(), QUEUED_JSON_BYTES - bytes);
        drop(second_reference);
        assert_eq!(budget.available_bytes(), QUEUED_JSON_BYTES - bytes);
        drop(writer_owned);
        assert_eq!(budget.available_bytes(), QUEUED_JSON_BYTES);
    }

    #[tokio::test]
    async fn saturation_waits_for_last_reference_and_close_wakes_a_waiter() {
        // Exercise the fixed public budget. The same caller-owned string is
        // counted as two independently queued logical messages.
        let budget = ByteBudget::new();
        let value = "x".repeat(64 * 1024 * 1024 - 2);
        let first = budget.charge(&value).await.unwrap();
        let second = budget.charge(&value).await.unwrap();
        assert_eq!(budget.available_bytes(), 0);
        let small = json!(null);
        assert!(matches!(
            budget.try_charge(&small),
            Err(DeliveryError::Unavailable(TryAcquireError::NoPermits))
        ));
        let pending = budget.charge(&small);
        tokio::pin!(pending);
        tokio::select! {
            biased;
            result = &mut pending => panic!("full budget admitted a third message: {result:?}"),
            () = std::future::ready(()) => {}
        }
        let held = first.clone();
        drop(first);
        assert_eq!(
            budget.available_bytes(),
            0,
            "a shared writer reference still owns the reservation"
        );
        drop(held);
        let admitted = pending.await.unwrap();
        assert_eq!(admitted.bytes(), 4);
        drop(admitted);
        drop(second);
        assert_eq!(budget.available_bytes(), QUEUED_JSON_BYTES);

        let closing = ByteBudget::new();
        let held_first = closing.charge(&value).await.unwrap();
        let held_second = closing.charge(&value).await.unwrap();
        let waiting = closing.charge(&small);
        tokio::pin!(waiting);
        tokio::select! {
            biased;
            result = &mut waiting => panic!("full closing budget admitted work: {result:?}"),
            () = std::future::ready(()) => {}
        }
        closing.close();
        assert!(matches!(waiting.await, Err(DeliveryError::Closed(_))));
        drop((held_first, held_second));
    }

    #[test]
    fn fixed_lifecycle_signals_are_transparent_and_debug_omits_payloads() {
        let queued = Queued::new(json!({"capability":"private-fixture-value"}), None);
        assert_eq!(
            serde_json::to_value(&queued).unwrap()["capability"],
            "private-fixture-value"
        );
        let debug = format!("{queued:?}");
        assert!(!debug.contains("private-fixture-value"));
        assert!(debug.contains("Queued"));
    }
}
