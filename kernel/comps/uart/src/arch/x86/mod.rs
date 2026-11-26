// SPDX-License-Identifier: MPL-2.0

use ostd::{
    arch::{
        irq::{IRQ_CHIP, MappedIrqLine},
        serial::{COM2_SERIAL_PORT, SERIAL_PORT},
    },
    irq::IrqLine,
};
use spin::Once;

use crate::console::{Uart, UartConsole};

const COM1_ISA_INTR_NUM: u8 = 4;
const COM2_ISA_INTR_NUM: u8 = 3;

static COM1_IRQ_LINE: Once<MappedIrqLine> = Once::new();
static COM2_IRQ_LINE: Once<MappedIrqLine> = Once::new();

fn init_console<U: Uart + Send + Sync + 'static>(
    uart: U,
    isa_intr_num: u8,
    name: &str,
    log_output: bool,
) -> Option<MappedIrqLine> {
    let mut irq_line = IrqLine::alloc()
        .and_then(|irq_line| IRQ_CHIP.get().unwrap().map_isa_pin_to(irq_line, isa_intr_num))
        .ok()?;

    let uart_console = UartConsole::new(uart);
    aster_console::register_device_with_log_output(name.into(), uart_console.clone(), log_output);

    let callback_console = uart_console.clone();
    irq_line.on_active(move |_| callback_console.trigger_input_callbacks());
    uart_console.uart().flush();
    Some(irq_line)
}

pub(super) fn init() {
    if let Some(uart) = SERIAL_PORT.get()
        && let Some(irq_line) = init_console(uart, COM1_ISA_INTR_NUM, aster_console::UART_CONSOLE_NAME, true)
    {
        COM1_IRQ_LINE.call_once(move || irq_line);
        ostd::info!("Registered NS16550A COM1 as a console");
    }

    if let Some(uart) = COM2_SERIAL_PORT.get()
        && let Some(irq_line) = init_console(uart, COM2_ISA_INTR_NUM, aster_console::UART2_CONSOLE_NAME, false)
    {
        COM2_IRQ_LINE.call_once(move || irq_line);
        ostd::info!("Registered NS16550A COM2 as a non-logging console");
    }
}
