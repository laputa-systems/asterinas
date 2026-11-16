// SPDX-License-Identifier: MPL-2.0

//! The system time of Asterinas.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use component::{ComponentInitError, init_component};
use ostd::sync::{LocalIrqDisabled, SpinLock};
use rtc::Driver;
use spin::Once;

// Set this crate's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "time: "
    };
}

pub mod adjust;
mod clocksource;
mod rtc;
mod system_time;
mod tsc;

pub use clocksource::{ClockSource, Instant};
pub use system_time::SystemTime;

pub static VDSO_DATA_HIGH_RES_UPDATE_FN: Once<fn(Instant, u64)> = Once::new();

static RTC_DRIVER: Once<Arc<dyn Driver + Send + Sync>> = Once::new();

#[init_component]
fn time_init() -> Result<(), ComponentInitError> {
    let rtc = rtc::init_rtc_driver();
    RTC_DRIVER.call_once(|| rtc);
    tsc::init();
    Ok(())
}

static START_TIME: Once<SystemTime> = Once::new();

/// Returns the start time, which is the system time when calibrating.
pub fn read_start_time() -> SystemTime {
    *START_TIME.get().unwrap()
}

/// Returns the raw time from the TSC clocksource, which no frequency correction slews.
pub fn read_raw_monotonic_time() -> Duration {
    let instant = tsc::read_instant();
    Duration::new(instant.secs(), instant.nanos())
}

/// Returns the current system time.
pub fn read_system_time() -> SystemTime {
    SystemTime::new(read_wall_time())
}

/// Returns the monotonic time: the raw time slewed by the wall clock's frequency correction.
pub fn read_monotonic_time() -> Duration {
    let monotonic_ns = WALL_CLOCK.get().unwrap().lock().monotonic_ns(raw_ns());
    Duration::from_nanos(monotonic_ns as u64)
}

/// Returns the default (TSC) clocksource.
pub fn default_clocksource() -> Arc<ClockSource> {
    tsc::CLOCK.get().unwrap().clone()
}

static WALL_CLOCK: Once<SpinLock<adjust::WallClock, LocalIrqDisabled>> = Once::new();

/// Starts the wall clock at `wall_at_raw_zero`, the wall time when the raw clock is zero.
pub fn init_wall_clock(wall_at_raw_zero: Duration) {
    WALL_CLOCK.call_once(|| {
        SpinLock::new(adjust::WallClock::new(wall_at_raw_zero.as_nanos() as i128))
    });
}

fn raw_ns() -> i128 {
    read_raw_monotonic_time().as_nanos() as i128
}

/// Returns the wall time since the Unix epoch.
pub fn read_wall_time() -> Duration {
    let wall_ns = WALL_CLOCK.get().unwrap().lock().wall_ns(raw_ns());
    Duration::from_nanos(wall_ns.max(0) as u64)
}

/// The disciplined clocks read at one raw clocksource time.
#[derive(Clone, Copy, Debug)]
pub struct DisciplinedTime {
    pub monotonic: Duration,
    pub wall: Duration,
    pub tai: Duration,
    /// The frequency correction in units of 2^-16 ppm.
    pub frequency: i64,
}

/// Reads the monotonic and wall clocks at raw clocksource time `raw`.
pub fn disciplined_time_at(raw: Duration) -> DisciplinedTime {
    let clock = WALL_CLOCK.get().unwrap().lock();
    let raw_ns = raw.as_nanos() as i128;
    DisciplinedTime {
        monotonic: Duration::from_nanos(clock.monotonic_ns(raw_ns) as u64),
        wall: Duration::from_nanos(clock.wall_ns(raw_ns).max(0) as u64),
        tai: Duration::from_nanos((clock.wall_ns(raw_ns) + i128::from(clock.tai_offset()) * 1_000_000_000).max(0) as u64),
        frequency: clock.frequency(),
    }
}

/// Sets the wall time. Fails with [`adjust::Error::Permission`] unless `privileged`.
pub fn set_wall_time(wall: Duration, privileged: bool) -> Result<(), adjust::Error> {
    WALL_CLOCK
        .get()
        .unwrap()
        .lock()
        .set(raw_ns(), wall.as_nanos() as i128, privileged)
}

/// Applies a leap second scheduled through `adjtimex`. Returns whether one was pending.
pub fn apply_pending_leap() -> bool {
    WALL_CLOCK.get().unwrap().lock().apply_pending_leap()
}

/// Reads or changes the wall clock as `adjtimex` does.
pub fn adjust_wall_clock(
    request: &adjust::Request,
    privileged: bool,
) -> Result<adjust::Reply, adjust::Error> {
    WALL_CLOCK
        .get()
        .unwrap()
        .lock()
        .adjust(raw_ns(), request, privileged)
}
