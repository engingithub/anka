//! Timer — programmable interval timer with interrupt generation.
//!
//! The timer counts CPU cycles and fires an auto-vectored interrupt
//! when the counter reaches the programmed period.  The guest must
//! acknowledge the interrupt by writing to the ACK register.
//!
//! Memory map (8 bytes at base address):
//!
//! ```text
//! Offset  Name      R/W  Description
//! ──────  ────────  ───  ────────────────────────────────────────
//! +0x00   CTRL      R/W  bit 0 = enable
//! +0x01   IRQ_LVL   R/W  interrupt level 1–7 (0 = disabled)
//! +0x02   PERIOD_H  R/W  period high byte  ┐ 16-bit reload value
//! +0x03   PERIOD_L  R/W  period low byte   ┘ (in CPU cycles)
//! +0x04   TICKS     R    total interrupts fired (32-bit, big-endian)
//! +0x05   ...       R    (TICKS byte 1)
//! +0x06   ...       R    (TICKS byte 2)
//! +0x07   STATUS    R    bit 0 = interrupt pending
//!                   W    any write = acknowledge (clear pending)
//! ```
//!
//! The timer fires when the internal cycle counter reaches the period.
//! The counter reloads automatically (free-running mode).  The pending
//! flag stays asserted until the guest acknowledges.

use super::device::Device;

const CTRL: u32 = 0;
const IRQ_LVL: u32 = 1;
const PERIOD_H: u32 = 2;
const PERIOD_L: u32 = 3;
const TICKS_0: u32 = 4;
const STATUS: u32 = 7;

/// Programmable interval timer.
pub struct Timer {
    enabled: bool,
    irq_level_val: u8,
    period: u16,
    counter: u32,
    ticks: u32,
    pending: bool,
}

impl Timer {
    /// Create a new timer with the given default period and IRQ level.
    /// The timer starts disabled.
    pub fn new(period: u16, irq_level: u8) -> Self {
        Self {
            enabled: false,
            irq_level_val: irq_level,
            period,
            counter: 0,
            ticks: 0,
            pending: false,
        }
    }
}

impl Device for Timer {
    fn name(&self) -> &str { "timer" }
    fn size(&self) -> u32 { 8 }

    fn read(&mut self, offset: u32) -> u8 {
        match offset {
            CTRL => self.enabled as u8,
            IRQ_LVL => self.irq_level_val,
            PERIOD_H => (self.period >> 8) as u8,
            PERIOD_L => self.period as u8,
            TICKS_0 => (self.ticks >> 24) as u8,
            5 => (self.ticks >> 16) as u8,
            6 => (self.ticks >> 8) as u8,
            STATUS => self.pending as u8,
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, val: u8) {
        match offset {
            CTRL => {
                let was = self.enabled;
                self.enabled = val & 1 != 0;
                if !was && self.enabled {
                    self.counter = 0;
                }
            }
            IRQ_LVL => {
                self.irq_level_val = val & 7;
            }
            PERIOD_H => {
                self.period = (self.period & 0x00FF) | ((val as u16) << 8);
            }
            PERIOD_L => {
                self.period = (self.period & 0xFF00) | val as u16;
            }
            STATUS => {
                // Any write to STATUS = acknowledge
                self.pending = false;
            }
            _ => {}
        }
    }

    fn irq_level(&self) -> u8 {
        if self.pending && self.irq_level_val > 0 {
            self.irq_level_val
        } else {
            0
        }
    }

    fn tick(&mut self, cycles: u32) {
        if !self.enabled || self.period == 0 {
            return;
        }
        self.counter += cycles;
        while self.counter >= self.period as u32 {
            self.counter -= self.period as u32;
            self.ticks = self.ticks.wrapping_add(1);
            self.pending = true;
        }
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_after_period() {
        let mut t = Timer::new(100, 6);
        assert_eq!(t.irq_level(), 0); // not enabled

        t.write(CTRL, 1); // enable
        assert_eq!(t.irq_level(), 0); // not yet fired

        t.tick(99);
        assert_eq!(t.irq_level(), 0); // still counting

        t.tick(1);
        assert_eq!(t.irq_level(), 6); // fired!
        assert_eq!(t.read(STATUS), 1);

        // Acknowledge
        t.write(STATUS, 0);
        assert_eq!(t.irq_level(), 0);
        assert_eq!(t.read(STATUS), 0);
    }

    #[test]
    fn counts_ticks() {
        let mut t = Timer::new(50, 6);
        t.write(CTRL, 1);
        t.tick(200); // should fire 4 times
        assert!(t.pending);
        assert_eq!(t.ticks, 4);
        // Read TICKS high bytes via register interface
        assert_eq!(t.read(TICKS_0), 0);     // bits 31-24
        assert_eq!(t.read(5), 0);           // bits 23-16
        assert_eq!(t.read(6), 0);           // bits 15-8
        // Low byte of ticks is not directly accessible (STATUS at +7)
        // but the internal count is verified above.
    }

    /// Full integration test: timer interrupt fires during CPU execution,
    /// the ISR increments a RAM counter, acknowledges the timer, and
    /// returns via RTE.
    #[test]
    fn timer_interrupt_integration() {
        use crate::asm::Asm;
        use crate::bus::MappedBus;
        use crate::bus::Bus;
        use crate::cpu::Cpu;

        const TIMER_BASE: u32 = 0x00F0_0010;
        const COUNTER_ADDR: u32 = 0x0000_0800;

        // ── Timer ISR (at 0x2000) ─────────────────────────────────
        //
        // The handler increments a 32-bit counter in RAM and ACKs
        // the timer by writing to STATUS.
        let mut isr = Asm::new(0x2000);
        isr.label("timer_isr");

        // Load counter from RAM: MOVE.L (COUNTER_ADDR).L, D0
        // EA = absolute long → mode 111, reg 001
        isr.emit(0x2039);                     // MOVE.L xxx.L, D0
        isr.emit((COUNTER_ADDR >> 16) as u16);
        isr.emit(COUNTER_ADDR as u16);

        isr.addq_l(1, 0);                     // ADDQ.L #1, D0

        // Store counter: MOVE.L D0, (COUNTER_ADDR).L
        isr.emit(0x23C0);                     // MOVE.L D0, xxx.L
        isr.emit((COUNTER_ADDR >> 16) as u16);
        isr.emit(COUNTER_ADDR as u16);

        // ACK timer: write to STATUS register
        // MOVE.B #1, (TIMER_BASE+7).L
        isr.emit(0x13FC);                     // MOVE.B #imm, xxx.L
        isr.emit(0x0001);                     // immediate = 1
        let ack_addr = TIMER_BASE + 7;        // STATUS register
        isr.emit((ack_addr >> 16) as u16);
        isr.emit(ack_addr as u16);

        isr.emit(0x4E73);                     // RTE
        let isr_bin = isr.assemble();

        // ── Main program (at 0x1000) ─────────────────────────────
        //
        // Enable the timer, then spin in a loop.  The timer ISR will
        // preempt us.  After enough iterations, STOP.
        let mut main_prog = Asm::new(0x1000);
        main_prog.label("_start");

        // Enable timer: write 1 to CTRL
        main_prog.emit(0x13FC);               // MOVE.B #imm, xxx.L
        main_prog.emit(0x0001);
        main_prog.emit((TIMER_BASE >> 16) as u16);
        main_prog.emit(TIMER_BASE as u16);

        // Lower IPL to 0 so level-6 interrupt can fire:
        // MOVE #$2000, SR  (supervisor mode, IPL=0)
        main_prog.emit(0x46FC);               // MOVE #imm, SR
        main_prog.emit(0x2000);

        // Busy loop: decrement D7 from a large value
        main_prog.move_l_imm(2000, 7);        // MOVE.L #2000, D7
        main_prog.label("spin");
        main_prog.emit(0x5387);               // SUBQ.L #1, D7
        main_prog.bne("spin");

        // Done — halt
        main_prog.stop(0x2700);
        let main_bin = main_prog.assemble();

        // ── Assemble the machine ─────────────────────────────────
        let mut bus = MappedBus::new_16mb();
        bus.add_device(TIMER_BASE, Box::new(Timer::new(100, 6)));

        // Vector table
        bus.write32(0x000000, 0x0010_0000);   // SSP
        bus.write32(0x000004, 0x0000_1000);   // Reset PC → _start

        // Auto-vector for level 6 → vector 30 → address 0x78
        bus.write32(0x078, 0x0000_2000);      // points to timer_isr

        // Load code
        bus.load(0x1000, &main_bin);
        bus.load(0x2000, &isr_bin);

        // Counter starts at 0
        bus.write32(COUNTER_ADDR, 0);

        let mut cpu = Cpu::new(bus);

        // Run
        let mut steps = 0u64;
        while !cpu.halted && steps < 50_000 {
            cpu.step();
            steps += 1;
        }

        assert!(cpu.halted, "CPU did not halt");

        // The timer should have fired multiple times.
        // At period=100 cycles, across ~2000 loop iterations of
        // ~10-14 cycles each, we expect roughly 200-300 interrupts.
        let counter = cpu.bus.read32(COUNTER_ADDR);
        assert!(counter > 0,
            "timer ISR never ran (counter={})", counter);
        assert!(counter > 10,
            "timer fired too few times (counter={})", counter);
    }
}
