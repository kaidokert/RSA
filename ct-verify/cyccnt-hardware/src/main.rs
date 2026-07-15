#![no_main]
#![no_std]

use const_num_traits::Ct;
use core::{convert::Infallible, hint::black_box};
use cortex_m::peripheral::DWT;
use cortex_m_rt::entry;
use fixed_bigint::FixedUInt;
use rand_core::{TryCryptoRng, TryRng};
use rsa::GenericRsaPrivateKey;
use rsa::modmath_support::{ModMathParams, public_key_ct_from_be_bytes};
use rsa::pkcs1v15::GenericSigningKey;
use rsa::traits::FixedWidthUnsignedInt;
use rtt_target::{rprintln, rtt_init_print};
use sha2::Sha256;

include!("../../test_keys.rs");

const TRIALS: usize = 4;
const MAX_POSITIVE_SPREAD: u32 = 32;
const MAX_SAFE_DWT_REGION: u32 = 0xf000_0000;
const RNG_SEED: u64 = 0x4354_5f52_5341_3531;
const ORDER: [bool; TRIALS * 2] = [false, true, true, false, true, false, false, true];
const MESSAGE: &[u8] = b"RSA CYCCNT fixture message";
const STACK_PAINT: u8 = 0xaa;
const STACK_SAFE_ZONE: usize = 512;

unsafe extern "C" {
    static _stack_start: u32;
    static _stack_end: u32;
}

const _: () = assert!(
    cfg!(feature = "rsa512") as usize
        + cfg!(feature = "rsa1024") as usize
        + cfg!(feature = "rsa2048") as usize
        == 1,
    "enable exactly one RSA width feature",
);
const _: () = assert!(
    cfg!(feature = "carrier-u32x16") as usize
        + cfg!(feature = "carrier-u32x32") as usize
        + cfg!(feature = "carrier-u32x64") as usize
        + cfg!(feature = "carrier-u8x64") as usize
        == 1,
    "enable exactly one carrier feature",
);
const _: () = assert!(
    (cfg!(feature = "rsa512")
        && (cfg!(feature = "carrier-u32x16") || cfg!(feature = "carrier-u8x64")))
        || (cfg!(feature = "rsa1024") && cfg!(feature = "carrier-u32x32"))
        || (cfg!(feature = "rsa2048") && cfg!(feature = "carrier-u32x64")),
    "selected carrier does not match the RSA width",
);

#[cfg(feature = "rsa512")]
const SUITE: &str = "rsa512-cyccnt";
#[cfg(feature = "rsa512")]
const KEY_BYTES: usize = 64;

#[cfg(feature = "rsa1024")]
const SUITE: &str = "rsa1024-cyccnt";
#[cfg(feature = "rsa1024")]
const KEY_BYTES: usize = 128;

#[cfg(feature = "rsa2048")]
const SUITE: &str = "rsa2048-cyccnt";
#[cfg(feature = "rsa2048")]
const KEY_BYTES: usize = 256;

#[cfg(feature = "carrier-u32x16")]
type Carrier = FixedUInt<u32, 16, Ct>;
#[cfg(feature = "carrier-u32x16")]
const CARRIER: &str = "u32x16";

#[cfg(feature = "carrier-u32x32")]
type Carrier = FixedUInt<u32, 32, Ct>;
#[cfg(feature = "carrier-u32x32")]
const CARRIER: &str = "u32x32";

#[cfg(feature = "carrier-u32x64")]
type Carrier = FixedUInt<u32, 64, Ct>;
#[cfg(feature = "carrier-u32x64")]
const CARRIER: &str = "u32x64";

#[cfg(feature = "carrier-u8x64")]
type Carrier = FixedUInt<u8, 64, Ct>;
#[cfg(feature = "carrier-u8x64")]
const CARRIER: &str = "u8x64";

type SigningKey = GenericSigningKey<Sha256, Carrier, ModMathParams<Carrier, Ct>>;

#[cfg(feature = "clock-168mhz")]
const CLOCK_PROFILE: &str = "hsi-pll-168mhz";
#[cfg(not(feature = "clock-168mhz"))]
const CLOCK_PROFILE: &str = "reset-hsi-16mhz";

#[cfg(feature = "clock-168mhz")]
fn configure_clock() -> u32 {
    use stm32f4xx_hal::{pac, prelude::*, rcc::Config};

    let device = pac::Peripherals::take().unwrap();
    let rcc = device.RCC.freeze(
        Config::hsi()
            .sysclk(168.MHz())
            .hclk(168.MHz())
            .pclk1(42.MHz())
            .pclk2(84.MHz()),
    );
    let hclk_hz = rcc.clocks.hclk().raw();
    assert_eq!(hclk_hz, 168_000_000);
    hclk_hz
}

#[cfg(not(feature = "clock-168mhz"))]
fn configure_clock() -> u32 {
    16_000_000
}

fn paint_stack() {
    unsafe {
        let stack_end = &_stack_end as *const u32 as usize;
        let sp: usize;
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
        let paint_end = sp.saturating_sub(STACK_SAFE_ZONE).max(stack_end);
        core::ptr::write_bytes(stack_end as *mut u8, STACK_PAINT, paint_end - stack_end);
    }
}

fn stack_high_water_mark() -> usize {
    unsafe {
        let stack_start = &_stack_start as *const u32 as usize;
        let stack_end = &_stack_end as *const u32 as usize;
        let mut current = stack_end;
        while current < stack_start && core::ptr::read_volatile(current as *const u8) == STACK_PAINT
        {
            current += 1;
        }
        stack_start - current
    }
}

#[derive(Clone, Copy)]
struct KeyInput {
    modulus: &'static [u8; KEY_BYTES],
    private_exponent: &'static [u8; KEY_BYTES],
}

#[cfg(feature = "rsa512")]
const KEY_A: KeyInput = KeyInput {
    modulus: &N_512,
    private_exponent: &D_512,
};
#[cfg(feature = "rsa512")]
const KEY_B: KeyInput = KeyInput {
    modulus: &N_512_B,
    private_exponent: &D_512_B,
};

#[cfg(feature = "rsa2048")]
const KEY_A: KeyInput = KeyInput {
    modulus: &N_2048,
    private_exponent: &D_2048,
};
#[cfg(feature = "rsa2048")]
const KEY_B: KeyInput = KeyInput {
    modulus: &N_2048_B,
    private_exponent: &D_2048_B,
};

#[cfg(feature = "rsa1024")]
const KEY_A: KeyInput = KeyInput {
    modulus: &N_1024,
    private_exponent: &D_1024,
};
#[cfg(feature = "rsa1024")]
const KEY_B: KeyInput = KeyInput {
    modulus: &N_1024_B,
    private_exponent: &D_1024_B,
};

struct CountingRng {
    state: u64,
    words: u32,
}

impl CountingRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed,
            words: 0,
        }
    }

    fn next_word(&mut self) -> u64 {
        self.words += 1;
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next_word() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next_word())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next_word().to_le_bytes();
            for (destination, source) in chunk.iter_mut().zip(bytes.iter()) {
                *destination = *source;
            }
        }
        Ok(())
    }
}

impl TryCryptoRng for CountingRng {}

#[derive(Clone, Copy)]
struct SignOutcome {
    ok: bool,
    rng_words: u32,
}

fn prepare_key(input: &KeyInput) -> Option<SigningKey> {
    let Ok(public_key) = public_key_ct_from_be_bytes::<Carrier>(black_box(input.modulus), 65537)
    else {
        return None;
    };
    let Ok(d) = Carrier::try_from_be_bytes_vartime(black_box(input.private_exponent)) else {
        return None;
    };
    Some(GenericSigningKey::<Sha256, _, _>::new(
        GenericRsaPrivateKey::from_public_and_d(public_key, d),
    ))
}

#[inline(never)]
fn sign_once(signing_key: &SigningKey) -> SignOutcome {
    let mut rng = CountingRng::new(RNG_SEED);
    let mut encoded_message = [0u8; KEY_BYTES];
    let mut signature = [0u8; KEY_BYTES];
    let ok = signing_key
        .try_sign_with_rng_into(
            &mut rng,
            black_box(MESSAGE),
            &mut encoded_message,
            &mut signature,
        )
        .is_ok();
    let _ = black_box((encoded_message, signature));
    SignOutcome {
        ok,
        rng_words: rng.words,
    }
}

#[derive(Clone, Copy)]
struct Samples {
    a: [u32; TRIALS],
    b: [u32; TRIALS],
    outputs_ok: bool,
}

#[inline(always)]
fn measure_once(signing_key: &SigningKey, expected_rng_words: u32) -> (u32, bool) {
    cortex_m::interrupt::free(|_| {
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        let start = DWT::cycle_count();
        let outcome = sign_once(black_box(signing_key));
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        let elapsed = DWT::cycle_count().wrapping_sub(start);
        (
            elapsed,
            outcome.ok && outcome.rng_words == expected_rng_words && elapsed < MAX_SAFE_DWT_REGION,
        )
    })
}

fn measure_signing(key_a: &SigningKey, key_b: &SigningKey, expected_rng_words: u32) -> Samples {
    let _ = black_box(sign_once(key_a));
    let _ = black_box(sign_once(key_b));
    let _ = black_box(sign_once(key_b));
    let _ = black_box(sign_once(key_a));

    let mut samples = Samples {
        a: [0; TRIALS],
        b: [0; TRIALS],
        outputs_ok: true,
    };
    let mut ai = 0;
    let mut bi = 0;
    for use_b in ORDER {
        let signing_key = if use_b { key_b } else { key_a };
        let (cycles, ok) = measure_once(signing_key, expected_rng_words);
        samples.outputs_ok &= ok;
        if use_b {
            samples.b[bi] = cycles;
            bi += 1;
        } else {
            samples.a[ai] = cycles;
            ai += 1;
        }
    }
    samples
}

fn measure_setup() -> Samples {
    let _ = black_box(prepare_key(&KEY_A).is_some());
    let _ = black_box(prepare_key(&KEY_B).is_some());
    let _ = black_box(prepare_key(&KEY_B).is_some());
    let _ = black_box(prepare_key(&KEY_A).is_some());

    let mut samples = Samples {
        a: [0; TRIALS],
        b: [0; TRIALS],
        outputs_ok: true,
    };
    let mut ai = 0;
    let mut bi = 0;
    for use_b in ORDER {
        let input = if use_b { &KEY_B } else { &KEY_A };
        let (cycles, ok) = cortex_m::interrupt::free(|_| {
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            let start = DWT::cycle_count();
            let ok = black_box(prepare_key(input).is_some());
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            (DWT::cycle_count().wrapping_sub(start), ok)
        });
        samples.outputs_ok &= ok;
        if use_b {
            samples.b[bi] = cycles;
            bi += 1;
        } else {
            samples.a[ai] = cycles;
            ai += 1;
        }
    }
    samples
}

#[inline(never)]
fn negative_early_exit(secret: &[u8; KEY_BYTES]) -> bool {
    let mut leading_zeroes = 0;
    for &byte in black_box(secret) {
        if byte != 0 {
            break;
        }
        leading_zeroes += 1;
    }
    let _ = black_box(leading_zeroes);
    true
}

fn measure_negative() -> Samples {
    const ZERO: [u8; KEY_BYTES] = [0; KEY_BYTES];
    let _ = black_box(negative_early_exit(&ZERO));
    let _ = black_box(negative_early_exit(KEY_B.private_exponent));
    let _ = black_box(negative_early_exit(KEY_B.private_exponent));
    let _ = black_box(negative_early_exit(&ZERO));

    let mut samples = Samples {
        a: [0; TRIALS],
        b: [0; TRIALS],
        outputs_ok: true,
    };
    let mut ai = 0;
    let mut bi = 0;
    for use_b in ORDER {
        let secret = if use_b { KEY_B.private_exponent } else { &ZERO };
        let (cycles, ok) = cortex_m::interrupt::free(|_| {
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            let start = DWT::cycle_count();
            let ok = negative_early_exit(secret);
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            (DWT::cycle_count().wrapping_sub(start), ok)
        });
        samples.outputs_ok &= ok;
        if use_b {
            samples.b[bi] = cycles;
            bi += 1;
        } else {
            samples.a[ai] = cycles;
            ai += 1;
        }
    }
    samples
}

fn bounds(values: &[u32; TRIALS]) -> (u32, u32) {
    let mut min = u32::MAX;
    let mut max = 0;
    for &value in values {
        min = min.min(value);
        max = max.max(value);
    }
    (min, max)
}

fn report(name: &str, class: &str, samples: Samples, expect_equal: bool) -> bool {
    let (a_min, a_max) = bounds(&samples.a);
    let (b_min, b_max) = bounds(&samples.b);
    let spread = a_min.min(b_min).abs_diff(a_max.max(b_max));
    let timing_ok = if expect_equal {
        spread <= MAX_POSITIVE_SPREAD
    } else {
        a_max < b_min || b_max < a_min
    };
    let passed = samples.outputs_ok && timing_ok;
    rprintln!(
        "CT_RESULT fixture:{} carrier:{} class:{} a_min:{} a_max:{} b_min:{} b_max:{} spread:{} output_ok:{} status:{}",
        name,
        CARRIER,
        class,
        a_min,
        a_max,
        b_min,
        b_max,
        spread,
        samples.outputs_ok as u8,
        if passed { "PASS" } else { "FAIL" }
    );
    passed
}

fn report_diagnostic(name: &str, samples: Samples) {
    let (a_min, a_max) = bounds(&samples.a);
    let (b_min, b_max) = bounds(&samples.b);
    rprintln!(
        "CT_DIAGNOSTIC fixture:{} carrier:{} class:public-setup a_min:{} a_max:{} b_min:{} b_max:{} spread:{} output_ok:{}",
        name,
        CARRIER,
        a_min,
        a_max,
        b_min,
        b_max,
        a_min.min(b_min).abs_diff(a_max.max(b_max)),
        samples.outputs_ok as u8
    );
}

fn stop() -> ! {
    loop {
        cortex_m::asm::nop();
    }
}

#[entry]
fn main() -> ! {
    rtt_init_print!();
    let hclk_hz = configure_clock();
    let mut peripherals = cortex_m::Peripherals::take().unwrap();
    assert!(DWT::has_cycle_counter());
    peripherals.DCB.enable_trace();
    peripherals.DWT.set_cycle_count(0);
    peripherals.DWT.enable_cycle_counter();
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    paint_stack();

    let Some(key_a) = prepare_key(&KEY_A) else {
        rprintln!("SETUP_FAIL key:A");
        stop();
    };
    let Some(key_b) = prepare_key(&KEY_B) else {
        rprintln!("SETUP_FAIL key:B");
        stop();
    };
    let preflight_a = sign_once(&key_a);
    let preflight_b = sign_once(&key_b);
    let streams_matched =
        preflight_a.ok && preflight_b.ok && preflight_a.rng_words == preflight_b.rng_words;
    rprintln!(
        "CT_BEGIN suite:{} carrier:{} clock_profile:{} hclk_hz:{} trials:{} max_positive_spread:{} rng_words_a:{} rng_words_b:{} streams_matched:{}",
        SUITE,
        CARRIER,
        CLOCK_PROFILE,
        hclk_hz,
        TRIALS,
        MAX_POSITIVE_SPREAD,
        preflight_a.rng_words,
        preflight_b.rng_words,
        streams_matched as u8
    );
    report_diagnostic("key_construction", measure_setup());

    let signing = report(
        "pkcs1v15_blinded_sign",
        "positive",
        measure_signing(&key_a, &key_b, preflight_a.rng_words),
        true,
    ) && streams_matched;
    let negative = report("negative_early_exit", "negative", measure_negative(), false);
    let stack_bytes = stack_high_water_mark();
    rprintln!(
        "CT_STACK suite:{} carrier:{} bytes:{}",
        SUITE,
        CARRIER,
        stack_bytes
    );
    let passed = signing as u32 + negative as u32;
    rprintln!(
        "CT_SUMMARY carrier:{} passed:{} failed:{}",
        CARRIER,
        passed,
        2 - passed
    );
    stop();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    rprintln!("PANIC: {}", info);
    loop {
        cortex_m::asm::nop();
    }
}
