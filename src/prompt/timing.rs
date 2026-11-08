//! Public deadlines are absolute Linux CLOCK_MONOTONIC microseconds. Rust
//! Instant remains the enforcing clock; never serialize its opaque layout.
use serde::{Deserialize, Serialize};
use std::{io, time::Instant};

// A newtype, not a bare Option field: private protocol fields are mandatory
// even when their value is null. This prevents silent pre-v4 message acceptance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Deadline(pub Option<u64>);
impl<'de> Deserialize<'de> for Deadline {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Nullable;
        impl serde::de::Visitor<'_> for Nullable {
            type Value = Deadline;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an explicit nullable monotonic microsecond deadline")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Deadline, E> {
                Ok(Deadline(None))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Deadline, E> {
                Ok(Deadline(Some(value)))
            }
        }
        deserializer.deserialize_any(Nullable)
    }
}
impl Deadline {
    pub fn from_instant(target: Instant) -> io::Result<Self> {
        // Sample CLOCK_MONOTONIC first: the exported deadline rounds earlier,
        // never later, than the broker's enforcing Linux Instant deadline.
        let before = keychain_sep_driver::clock::monotonic_nanoseconds()?;
        Self::from_samples(before, target, Instant::now())
    }
    fn from_samples(before: u128, target: Instant, after: Instant) -> io::Result<Self> {
        let Some(remaining) = target.checked_duration_since(after) else {
            return Ok(Self(Some(0)));
        };
        let micros = before
            .checked_add(remaining.as_nanos())
            .ok_or_else(|| io::Error::other("monotonic deadline overflow"))?
            / 1000;
        Ok(Self(Some(u64::try_from(micros).map_err(|_| {
            io::Error::other("monotonic deadline overflow")
        })?)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn projection_is_absolute_rounded_down_and_checked() -> io::Result<()> {
        let now = Instant::now();
        assert_eq!(
            Deadline::from_samples(1000999, now + Duration::from_nanos(1999), now)?,
            Deadline(Some(1002))
        );
        assert_eq!(
            Deadline::from_samples(1000999, now, now + Duration::from_nanos(1))?,
            Deadline(Some(0))
        );
        assert!(Deadline::from_samples(u128::MAX, now + Duration::from_secs(1), now).is_err());
        assert!(Deadline::from_samples(u64::MAX as u128 * 1000 + 1000, now, now).is_err());
        assert_eq!(
            serde_json::to_string(&Deadline(None)).map_err(io::Error::other)?,
            "null"
        );
        Ok(())
    }
    #[test]
    fn live_projection_does_not_outlive_the_enforcing_bound() -> io::Result<()> {
        let target = Instant::now() + Duration::from_secs(1);
        let projected = Deadline::from_instant(target)?
            .0
            .ok_or_else(|| io::Error::other("missing deadline"))?;
        let before = Instant::now();
        let ticks = keychain_sep_driver::clock::monotonic_nanoseconds()?;
        assert!(
            projected as u128 * 1000 <= ticks + target.saturating_duration_since(before).as_nanos()
        );
        Ok(())
    }
}
