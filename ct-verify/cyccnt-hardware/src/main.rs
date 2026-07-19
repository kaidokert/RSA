#![no_main]
#![no_std]

use const_num_traits::Ct;
use core::{convert::Infallible, hint::black_box};
use cortex_m_rt::entry;
use krabi_caliper::cortex_m::DwtCycleCounter;
#[cfg(not(feature = "etm-single-trial"))]
use krabi_caliper::report::Field;
#[cfg(not(feature = "etm-single-trial"))]
use krabi_caliper::stack::{CortexM, LinkerStack, StackConfig, StackProbe};
#[cfg(not(feature = "etm-single-trial"))]
use krabi_caliper::suite::{PairedSuite, PairedSuiteConfig, PairedSuiteFields};
use fixed_bigint::FixedUInt;
use rand_core::{TryCryptoRng, TryRng};
use rsa::GenericRsaPrivateKey;
use rsa::modmath_support::{ModMathParams, public_key_ct_from_be_bytes};
use rsa::pkcs1v15::GenericSigningKey;
use rsa::traits::FixedWidthUnsignedInt;
use sha2::Sha256;

include!("../../test_keys.rs");

#[cfg(not(feature = "etm-single-trial"))]
const TRIALS: usize = 4;
#[cfg(not(feature = "etm-single-trial"))]
const BATCHES: usize = 1;
#[cfg(not(feature = "etm-single-trial"))]
const MAX_POSITIVE_SPREAD: u32 = 32;
#[cfg(not(feature = "etm-single-trial"))]
const MAX_SAFE_DWT_REGION: u32 = 0xf000_0000;
const RNG_SEED: u64 = 0x4354_5f52_5341_3531;
const MESSAGE: &[u8] = b"RSA CYCCNT fixture message";
#[cfg(not(feature = "etm-single-trial"))]
const STACK_SAFE_ZONE: usize = 512;

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
#[cfg(not(feature = "etm-single-trial"))]
const SUITE: &str = "rsa512-cyccnt";
#[cfg(feature = "rsa512")]
const KEY_BYTES: usize = 64;

#[cfg(feature = "rsa1024")]
#[cfg(not(feature = "etm-single-trial"))]
const SUITE: &str = "rsa1024-cyccnt";
#[cfg(feature = "rsa1024")]
const KEY_BYTES: usize = 128;

#[cfg(feature = "rsa2048")]
#[cfg(not(feature = "etm-single-trial"))]
const SUITE: &str = "rsa2048-cyccnt";
#[cfg(feature = "rsa2048")]
const KEY_BYTES: usize = 256;

#[cfg(feature = "carrier-u32x16")]
type Carrier = FixedUInt<u32, 16, Ct>;
#[cfg(feature = "carrier-u32x16")]
#[cfg(not(feature = "etm-single-trial"))]
const CARRIER: &str = "u32x16";

#[cfg(feature = "carrier-u32x32")]
type Carrier = FixedUInt<u32, 32, Ct>;
#[cfg(feature = "carrier-u32x32")]
#[cfg(not(feature = "etm-single-trial"))]
const CARRIER: &str = "u32x32";

#[cfg(feature = "carrier-u32x64")]
type Carrier = FixedUInt<u32, 64, Ct>;
#[cfg(feature = "carrier-u32x64")]
#[cfg(not(feature = "etm-single-trial"))]
const CARRIER: &str = "u32x64";

#[cfg(feature = "carrier-u8x64")]
type Carrier = FixedUInt<u8, 64, Ct>;
#[cfg(feature = "carrier-u8x64")]
#[cfg(not(feature = "etm-single-trial"))]
const CARRIER: &str = "u8x64";

type SigningKey = GenericSigningKey<Sha256, Carrier, ModMathParams<Carrier, Ct>>;

#[cfg(feature = "clock-168mhz")]
#[cfg(not(feature = "etm-single-trial"))]
const CLOCK_PROFILE: &str = "hsi-pll-168mhz";
#[cfg(not(feature = "clock-168mhz"))]
#[cfg(not(feature = "etm-single-trial"))]
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

#[cfg(not(feature = "etm-single-trial"))]
fn paint_stack() -> StackProbe {
    let stack = unsafe { LinkerStack::<CortexM>::cortex_m_runtime() };
    StackProbe::paint(&stack, StackConfig::new(STACK_SAFE_ZONE)).unwrap()
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

// Stable instruction addresses for non-halting ETM start/stop comparators.
// Keep the markers distinct so link-time optimization cannot fold them.
#[cfg(feature = "etm-single-trial")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn embedded_measure_trace_begin() {
    // SAFETY: `nop` has no architectural side effects beyond advancing PC.
    unsafe { core::arch::asm!("nop", options(nomem, nostack)) };
}

#[cfg(feature = "etm-single-trial")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn embedded_measure_trace_end() {
    // SAFETY: `nop` has no architectural side effects beyond advancing PC.
    unsafe { core::arch::asm!("nop", "nop", options(nomem, nostack)) };
}

#[cfg(feature = "etm-single-trial")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".uninit.embedded_measure")]
pub static mut embedded_measure_etm_key_index: u32 = 0;

#[cfg(feature = "etm-single-trial")]
#[unsafe(no_mangle)]
pub static mut embedded_measure_etm_dwt_ticks: u32 = 0;

#[cfg(feature = "etm-single-trial")]
#[unsafe(no_mangle)]
pub static mut embedded_measure_etm_observed_key: u32 = u32::MAX;

#[cfg(feature = "etm-single-trial")]
#[unsafe(no_mangle)]
pub static mut embedded_measure_etm_output_ok: u32 = 0;

#[cfg(feature = "etm-single-trial")]
#[unsafe(no_mangle)]
pub static mut embedded_measure_etm_rng_words: u32 = 0;

#[cfg(feature = "etm-single-trial")]
fn run_etm_single_trial(signing_key: &SigningKey, key_index: u32, hclk_hz: u32) -> ! {
    // Keep trace disabled during cache/path warm-up. The ETM start comparator
    // enables collection only when the exported begin marker executes.
    let warmup = sign_once(black_box(signing_key));
    let start = cortex_m::peripheral::DWT::cycle_count();
    let trace_begin: extern "C" fn() = black_box(embedded_measure_trace_begin);
    trace_begin();
    let outcome = sign_once(black_box(signing_key));
    let trace_end: extern "C" fn() = black_box(embedded_measure_trace_end);
    trace_end();
    let ticks = cortex_m::peripheral::DWT::cycle_count().wrapping_sub(start);
    // SAFETY: the trace fixture has exclusive access before halting and the
    // host reads this checkpoint only after the terminal BKPT.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(embedded_measure_etm_dwt_ticks),
            ticks,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(embedded_measure_etm_observed_key),
            key_index,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(embedded_measure_etm_output_ok),
            (warmup.ok && outcome.ok) as u32,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(embedded_measure_etm_rng_words),
            outcome.rng_words,
        );
    };
    krabi_caliper::rtt::print(format_args!(
        "ETM_TRIAL fixture:pkcs1v15_blinded_sign key:{} ticks:{} frequency_hz:{} warmup_ok:{} output_ok:{} rng_words:{}\n",
        key_index, ticks, hclk_hz, warmup.ok as u8, outcome.ok as u8, outcome.rng_words,
    ));
    // This feature is only used under a trace debugger. Halt after publishing
    // RTT so the host can retrieve trace statistics without polling or placing
    // a breakpoint inside the measured interval.
    cortex_m::asm::bkpt();
    stop()
}

#[inline(never)]
#[cfg(not(feature = "etm-single-trial"))]
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

fn stop() -> ! {
    loop {
        cortex_m::asm::nop();
    }
}

#[entry]
fn main() -> ! {
    let hclk_hz = configure_clock();
    let mut peripherals = cortex_m::Peripherals::take().unwrap();
    let counter = DwtCycleCounter::enable(
        &mut peripherals.DCB,
        &mut peripherals.DWT,
        Some(hclk_hz as u64),
    )
    .unwrap();
    #[cfg(feature = "etm-single-trial")]
    {
        let _reporter = krabi_caliper::rtt::init_ct_compatible();
        let _ = counter;
        // SAFETY: the host writes this selector while the core is halted at
        // reset, before main executes.
        let key_index = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(embedded_measure_etm_key_index))
        };
        let key_input = match key_index {
            0 => &KEY_A,
            1 => &KEY_B,
            _ => {
                krabi_caliper::rtt::print(format_args!("SETUP_FAIL key:{}\n", key_index));
                stop();
            }
        };
        let Some(key) = prepare_key(key_input) else {
            krabi_caliper::rtt::print(format_args!("SETUP_FAIL key:{}\n", key_index));
            stop();
        };
        run_etm_single_trial(&key, key_index, hclk_hz);
    }

    #[cfg(not(feature = "etm-single-trial"))]
    {
        let Some(key_a) = prepare_key(&KEY_A) else {
            krabi_caliper::rtt::print(format_args!("SETUP_FAIL key:A\n"));
            stop();
        };
        run_campaign(key_a, counter, hclk_hz)
    }
}

#[cfg(not(feature = "etm-single-trial"))]
fn run_campaign(key_a: SigningKey, mut counter: DwtCycleCounter, hclk_hz: u32) -> ! {
    let mut reporter = krabi_caliper::rtt::init_ct_compatible();
    let stack_probe = paint_stack();
    let Some(key_b) = prepare_key(&KEY_B) else {
        krabi_caliper::rtt::print(format_args!("SETUP_FAIL key:B\n"));
        stop();
    };
    let preflight_a = sign_once(&key_a);
    let preflight_b = sign_once(&key_b);
    let streams_matched =
        preflight_a.ok && preflight_b.ok && preflight_a.rng_words == preflight_b.rng_words;
    let run_fields = [
        Field::token("carrier", CARRIER),
        Field::token("clock_profile", CLOCK_PROFILE),
        Field::u64("hclk_hz", hclk_hz as u64),
        Field::u64("trials", TRIALS as u64),
        Field::u64("max_positive_spread", MAX_POSITIVE_SPREAD as u64),
        Field::u64("rng_words_a", preflight_a.rng_words as u64),
        Field::u64("rng_words_b", preflight_b.rng_words as u64),
        Field::bool("streams_matched", streams_matched),
    ];
    let fixture_fields = [Field::token("carrier", CARRIER)];
    let summary_fields = [Field::token("carrier", CARRIER)];
    let mut suite = PairedSuite::<_, _, TRIALS>::start(
        &mut counter,
        &mut reporter,
        PairedSuiteConfig {
            suite: SUITE,
            target: "thumbv7em-none-eabihf",
            board: Some("stm32f407vg"),
            unit: krabi_caliper::Unit::CoreCycles,
            frequency_hz: Some(hclk_hz as u64),
            warmup_blocks: 2,
            batches: BATCHES,
            positive_max_spread: MAX_POSITIVE_SPREAD as u64,
            positive_require_overlap: false,
            fields: PairedSuiteFields {
                run: &run_fields,
                fixture: &fixture_fields,
                summary: &summary_fields,
            },
        },
    )
    .unwrap()
    .max_sample_ticks(MAX_SAFE_DWT_REGION as u64);
    suite
        .diagnostic(
            "key_construction",
            "public-setup",
            &KEY_A,
            &KEY_B,
            |input| prepare_key(input).is_some(),
        )
        .unwrap();
    suite
        .positive("pkcs1v15_blinded_sign", &key_a, &key_b, |signing_key| {
            let outcome = sign_once(signing_key);
            streams_matched && outcome.ok && outcome.rng_words == preflight_a.rng_words
        })
        .unwrap();
    const ZERO: [u8; KEY_BYTES] = [0; KEY_BYTES];
    suite
        .negative(
            "negative_early_exit",
            &ZERO,
            KEY_B.private_exponent,
            negative_early_exit,
        )
        .unwrap();
    let stack = stack_probe.measure();
    suite
        .stack_measurement(stack, &[Field::token("carrier", CARRIER)])
        .unwrap();
    assert!(!stack.overflowed);
    suite.finish().unwrap();
    stop();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    krabi_caliper::rtt::print(format_args!("PANIC: {}\n", info));
    loop {
        cortex_m::asm::nop();
    }
}
