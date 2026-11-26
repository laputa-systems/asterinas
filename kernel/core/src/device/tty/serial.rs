// SPDX-License-Identifier: MPL-2.0

use alloc::format;

use aster_console::AnyConsoleDevice;
use ostd::mm::Infallible;
use spin::Once;

use super::{Tty, TtyDriver};
use crate::{
    device::{
        registry::char,
        tty::{file::TtyFile, termio::CTermios},
    },
    fs::{devtmpfs::DevtmpfsNodeMeta, file::PerOpenFileOps},
    prelude::*,
};

/// The driver for serial devices.
#[derive(Clone)]
pub(super) struct SerialDriver {
    console: Arc<dyn AnyConsoleDevice>,
}

impl SerialDriver {
    const MINOR_ID_BASE: u32 = 64;
}

impl TtyDriver for SerialDriver {
    // Reference: <https://elixir.bootlin.com/linux/v6.17/source/include/uapi/linux/major.h#L18>.
    const DEVICE_MAJOR_ID: u32 = 4;

    fn devtmpfs_meta(&self, index: u32) -> Option<DevtmpfsNodeMeta> {
        Some(DevtmpfsNodeMeta::new(format!("ttyS{}", index - Self::MINOR_ID_BASE)).unwrap())
    }

    fn open(tty: Arc<Tty<Self>>) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(TtyFile::new(tty)))
    }

    fn push_output(&self, chs: &[u8]) -> Result<usize> {
        self.console.send(chs);
        Ok(chs.len())
    }

    fn echo_callback(&self) -> impl FnMut(&[u8]) + '_ {
        |chs| self.console.send(chs)
    }

    fn can_push(&self) -> bool {
        true
    }

    fn notify_input(&self) {}

    fn on_termios_change(&self, _old_termios: &CTermios, _new_termios: &CTermios) {}
}

static SERIAL0: Once<Arc<Tty<SerialDriver>>> = Once::new();

/// Returns the `ttyS0` device.
///
/// Returns `None` if the device is not found nor initialized.
pub(super) fn serial0_device() -> Option<&'static Arc<Tty<SerialDriver>>> {
    SERIAL0.get()
}

fn register_serial_tty(minor: u32, console: Arc<dyn AnyConsoleDevice>) -> Result<Arc<Tty<SerialDriver>>> {
    let driver = SerialDriver {
        console: console.clone(),
    };
    let tty = Tty::new(minor, driver);
    char::register(tty.clone())?;

    let input_tty = tty.clone();
    console.register_callback(Box::leak(Box::new(
        move |mut reader: VmReader<Infallible>| {
            let mut chs = vec![0u8; reader.remain()];
            reader.read(&mut VmWriter::from(chs.as_mut_slice()));
            let _ = input_tty.push_input(chs.as_slice());
        },
    )));
    Ok(tty)
}

pub(super) fn init_in_first_process() -> Result<()> {
    let devices = aster_console::all_devices();

    for (console_name, minor) in [
        (aster_console::UART_CONSOLE_NAME, SerialDriver::MINOR_ID_BASE),
        (aster_console::UART2_CONSOLE_NAME, SerialDriver::MINOR_ID_BASE + 1),
    ] {
        let Some((_, console)) = devices
            .iter()
            .find(|(name, _)| name.as_str() == console_name)
            .map(|(_, device)| (console_name, device.clone()))
        else {
            continue;
        };
        let tty = register_serial_tty(minor, console)?;
        if minor == SerialDriver::MINOR_ID_BASE {
            SERIAL0.call_once(|| tty);
        }
    }

    Ok(())
}
