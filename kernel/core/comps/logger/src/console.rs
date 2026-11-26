// SPDX-License-Identifier: MPL-2.0

//! `print` and `println` macros
//!
//! FIXME: It will print to all `virtio-console` devices, which is not a good choice.
//!

use alloc::{collections::btree_map::BTreeMap, fmt, string::String};
use core::fmt::Write;

use ostd::sync::{LocalIrqDisabled, SpinLockGuard};

/// Prints the formatted arguments to the standard output.
pub fn _print(args: fmt::Arguments) {
    // We must call `all_devices_lock` instead of `all_devices` here, as `all_devices` invokes the
    // `clone` method of `String` and `Arc`, which may lead to a deadlock when there is low memory
    // in the heap. (The heap allocator will log a message when memory is low.)
    //
    // Also, holding the lock will prevent the logs from interleaving.
    let devices = aster_console::all_device_entries_lock();

    struct Printer<'a>(SpinLockGuard<'a, BTreeMap<String, aster_console::ConsoleDevice>, LocalIrqDisabled>);
    impl Write for Printer<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let mut wrote = false;
            for console in self.0.values() {
                if console.log_output() {
                    console.device().send(s.as_bytes());
                    wrote = true;
                }
            }
            if !wrote {
                ostd::early_print!("{}", s);
            }
            Ok(())
        }
    }

    Printer(devices).write_fmt(args).unwrap();
}

/// Copied from Rust std: <https://github.com/rust-lang/rust/blob/master/library/std/src/macros.rs>
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::_print(format_args!($($arg)*));
    }};
}

/// Copied from Rust std: <https://github.com/rust-lang/rust/blob/master/library/std/src/macros.rs>
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::_print(::core::format_args_nl!($($arg)*));
    }};
}
