//! Long mode support additions: 64-bit registers, REX prefix decoding, and tests

use core::fmt;

/// 16 general purpose registers RAX..R15 stored as u64
#[derive(Clone)]
pub struct Registers {
    /// rax..r15
    regs: [u64; 16],
    /// RFLAGS (64-bit to allow extended flags in long mode)
    pub rflags: u64,
}

impl Registers {
    pub fn new() -> Self {
        Registers {
            regs: [0u64; 16],
            rflags: 0,
        }
    }

    pub fn get_r64(&self, idx: usize) -> u64 {
        self.regs[idx & 0xf]
    }

    pub fn set_r64(&mut self, idx: usize, val: u64) {
        self.regs[idx & 0xf] = val;
    }

    pub fn get_r32(&self, idx: usize) -> u32 {
        (self.regs[idx & 0xf] & 0xffff_ffff) as u32
    }

    pub fn set_r32(&mut self, idx: usize, val: u32) {
        let new = (val as u64) & 0xffff_ffffu64;
        self.regs[idx & 0xf] = new;
    }

    pub fn get_r16(&self, idx: usize) -> u16 {
        (self.regs[idx & 0xf] & 0xffff) as u16
    }

    pub fn set_r16(&mut self, idx: usize, val: u16) {
        let i = idx & 0xf;
        let high = self.regs[i] & !0xffffu64;
        self.regs[i] = high | ((val as u64) & 0xffffu64);
    }

    pub fn get_r8l(&self, idx: usize) -> u8 {
        (self.regs[idx & 0xf] & 0xff) as u8
    }

    pub fn set_r8l(&mut self, idx: usize, val: u8) {
        let i = idx & 0xf;
        let high = self.regs[i] & !0xffu64;
        self.regs[i] = high | ((val as u64) & 0xffu64);
    }

    pub fn get_r8h(&self, idx: usize) -> u8 {
        let i = idx & 0xf;
        ((self.regs[i] >> 8) & 0xff) as u8
    }

    pub fn set_r8h(&mut self, idx: usize, val: u8) {
        let i = idx & 0xf;
        let low = self.regs[i] & !(0xffu64 << 8);
        let new = low | (((val as u64) & 0xffu64) << 8);
        self.regs[i] = new;
    }
}

impl fmt::Debug for Registers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, r) in self.regs.iter().enumerate() {
            writeln!(f, "r{} = 0x{:016x}", i, r)?;
        }
        writeln!(f, "rflags = 0x{:016x}", self.rflags)
    }
}

/// REX prefix representation
#[derive(Debug, Clone, Copy)]
pub struct Rex {
    pub w: bool,
    pub r: bool,
    pub x: bool,
    pub b: bool,
}

impl Rex {
    pub fn from_byte(b: u8) -> Option<Self> {
        if (0x40..=0x4f).contains(&b) {
            Some(Rex {
                w: (b & 0x08) != 0,
                r: (b & 0x04) != 0,
                x: (b & 0x02) != 0,
                b: (b & 0x01) != 0,
            })
        } else {
            None
        }
    }
}

/// Parse a prefix stream and return detected REX (if any) and consumed length.
pub fn parse_prefixes(stream: &[u8]) -> (Option<Rex>, usize) {
    let mut pos = 0usize;
    let mut rex: Option<Rex> = None;

    if pos < stream.len() {
        if let Some(r) = Rex::from_byte(stream[pos]) {
            rex = Some(r);
            pos += 1;
        }
    }
    (rex, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyCpu {
        pub registers: Registers,
    }

    impl DummyCpu {
        fn new() -> Self {
            Self { registers: Registers::new() }
        }

        /// Extremely minimal executor for demonstration purposes
        fn exec_mov_demo(&mut self) {
            // mov rax, 0x1122334455667788
            self.registers.set_r64(0, 0x1122334455667788);
            // mov rbx, rax
            let val = self.registers.get_r64(0);
            self.registers.set_r64(1, val);
        }
    }

    #[test]
    fn mov_rax_rbx_64bit_transfer() {
        let mut cpu = DummyCpu::new();
        cpu.exec_mov_demo();
        assert_eq!(cpu.registers.get_r64(0), 0x1122334455667788u64);
        assert_eq!(cpu.registers.get_r64(1), 0x1122334455667788u64);
    }
}
