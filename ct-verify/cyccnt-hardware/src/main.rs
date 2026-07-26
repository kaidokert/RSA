#![no_main]
#![no_std]
// The `localize` variant reuses the campaign-shaped setup but runs its own
// per-stage path, so some campaign-only items are unused under that feature.
#![cfg_attr(
    feature = "localize",
    allow(dead_code, unused_imports, unused_variables)
)]

use const_num_traits::Ct;
use core::hint::black_box;
use cortex_m_rt::entry;
use fixed_bigint::FixedUInt;
use krabi_caliper::cortex_m::DwtMeasurementPlatform;
use krabi_caliper::protocol::rtt;
#[cfg(not(feature = "etm-single-trial"))]
use krabi_caliper::report::Field;
#[cfg(not(feature = "etm-single-trial"))]
use krabi_caliper::stack::{paint_cortex_m_runtime, StackProbe};
#[cfg(not(feature = "etm-single-trial"))]
use krabi_caliper::suite::{PairedSuite, PairedSuiteConfig, PairedSuiteFields};
use rand_chacha::ChaCha12Rng;
use rand_core::{SeedableRng, TryCryptoRng, TryRng};
use rsa::modmath_support::{public_key_ct_from_be_bytes, ModMathParams};
use rsa::pkcs1v15::GenericSigningKey;
#[cfg(all(feature = "rsa768", not(feature = "etm-single-trial")))]
use rsa::pss::GenericSigningKey as PssGenericSigningKey;
use rsa::traits::FixedWidthUnsignedInt;
use rsa::GenericRsaPrivateKey;
use sha2::Sha256;

include!("../../../tests/fixtures/test_keys.rs");

// `statistical-chunk` runs a short 20-sample slice so the rig can accumulate
// 100 samples across several reliable short attaches (5 x 20) instead of one
// long attach that the probe faults partway through. Host pools the per-slice
// `EM_SAMPLE` records and applies the 100-sample policy. Must stay even —
// `PairedSuite` rejects an odd capacity.
#[cfg(all(not(feature = "etm-single-trial"), feature = "statistical-chunk"))]
const TRIALS: usize = 20;
#[cfg(all(
    not(feature = "etm-single-trial"),
    feature = "statistical-campaign",
    not(feature = "statistical-chunk")
))]
const TRIALS: usize = 100;
#[cfg(all(
    not(feature = "etm-single-trial"),
    not(feature = "statistical-campaign"),
    not(feature = "statistical-chunk")
))]
const TRIALS: usize = 4;
#[cfg(not(feature = "etm-single-trial"))]
const BATCHES: usize = 1;
#[cfg(not(feature = "etm-single-trial"))]
// The u8 carrier has a reproducible 36-cycle first-sample setup effect on the F407.
const MAX_POSITIVE_SPREAD: u32 = 40;
#[cfg(not(feature = "etm-single-trial"))]
const MAX_SAFE_DWT_REGION: u32 = 0xf000_0000;
#[cfg(all(feature = "conditioning", not(feature = "etm-single-trial")))]
const SIGN_CONDITIONING: &str = "per-sample-prewarm";
#[cfg(all(not(feature = "conditioning"), not(feature = "etm-single-trial")))]
const SIGN_CONDITIONING: &str = "none";
const RNG_SEED: u64 = 0x4354_5f52_5341_3531;
const MESSAGE: &[u8] = b"RSA CYCCNT fixture message";
#[cfg(not(feature = "etm-single-trial"))]
const STACK_SAFE_ZONE: usize = 512;

const _: () = assert!(
    cfg!(feature = "rsa512") as usize
        + cfg!(feature = "rsa768") as usize
        + cfg!(feature = "rsa1024") as usize
        + cfg!(feature = "rsa2048") as usize
        == 1,
    "enable exactly one RSA width feature",
);
const _: () = assert!(
    cfg!(feature = "carrier-u32x16") as usize
        + cfg!(feature = "carrier-u32x24") as usize
        + cfg!(feature = "carrier-u32x32") as usize
        + cfg!(feature = "carrier-u32x64") as usize
        + cfg!(feature = "carrier-u8x64") as usize
        == 1,
    "enable exactly one carrier feature",
);
const _: () = assert!(
    (cfg!(feature = "rsa512")
        && (cfg!(feature = "carrier-u32x16") || cfg!(feature = "carrier-u8x64")))
        || (cfg!(feature = "rsa768") && cfg!(feature = "carrier-u32x24"))
        || (cfg!(feature = "rsa1024") && cfg!(feature = "carrier-u32x32"))
        || (cfg!(feature = "rsa2048") && cfg!(feature = "carrier-u32x64")),
    "selected carrier does not match the RSA width",
);

#[cfg(feature = "rsa512")]
#[cfg(not(feature = "etm-single-trial"))]
const SUITE: &str = "rsa512-cyccnt";
#[cfg(feature = "rsa512")]
const KEY_BYTES: usize = 64;

#[cfg(feature = "rsa768")]
#[cfg(not(feature = "etm-single-trial"))]
const SUITE: &str = "rsa768-cyccnt";
#[cfg(feature = "rsa768")]
const KEY_BYTES: usize = 96;

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

#[cfg(feature = "carrier-u32x24")]
type Carrier = FixedUInt<u32, 24, Ct>;
#[cfg(feature = "carrier-u32x24")]
#[cfg(not(feature = "etm-single-trial"))]
const CARRIER: &str = "u32x24";

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

// PSS shares the entire secret-dependent core with pkcs1v15 (same blinded
// private op); the only added path is the EMSA-PSS encoding (MGF1 + salt),
// which runs on the public hash. Gated to rsa768 because 768 is the smallest
// width where PSS's emLen (>= hLen + sLen + 2 = 66 bytes) fits — the same
// constraint that makes 768 the gate width.
#[cfg(all(feature = "rsa768", not(feature = "etm-single-trial")))]
type PssSigningKey = PssGenericSigningKey<Sha256, Carrier, ModMathParams<Carrier, Ct>>;

#[cfg(all(feature = "clock-30mhz", not(feature = "etm-single-trial")))]
const CLOCK_PROFILE: &str = "hsi-pll-30mhz-0ws";
#[cfg(all(
    feature = "clock-168mhz",
    not(feature = "clock-30mhz"),
    not(feature = "etm-single-trial")
))]
const CLOCK_PROFILE: &str = "hsi-pll-168mhz";
#[cfg(all(
    not(feature = "clock-168mhz"),
    not(feature = "clock-30mhz"),
    not(feature = "etm-single-trial")
))]
const CLOCK_PROFILE: &str = "reset-hsi-16mhz";

// 30 MHz is the F407's 0-wait-state flash ceiling. At 0 WS the ART
// prefetch/I-cache is off, so core-cycle counts stay deterministic — none of
// the secret-independent fetch jitter (which scales with operation length and
// swamped the tight positive gate at 168 MHz) — while wall time nearly halves
// vs the 16 MHz HSI reset default. This is the measurement regime the CT gate
// wants; 168 MHz trades that determinism for wall time and needs the jitter
// worked around. HSI-sourced PLL so no HSE crystal is assumed.
#[cfg(feature = "clock-30mhz")]
fn configure_clock() -> u32 {
    use stm32f4xx_hal::{pac, prelude::*, rcc::Config};

    let device = pac::Peripherals::take().unwrap();
    let rcc = device.RCC.freeze(Config::hsi().sysclk(30.MHz()));
    let hclk_hz = rcc.clocks.hclk().raw();
    assert_eq!(hclk_hz, 30_000_000);
    hclk_hz
}

#[cfg(all(feature = "clock-168mhz", not(feature = "clock-30mhz")))]
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

#[cfg(all(not(feature = "clock-168mhz"), not(feature = "clock-30mhz")))]
fn configure_clock() -> u32 {
    16_000_000
}

#[cfg(not(feature = "etm-single-trial"))]
fn paint_stack() -> StackProbe<'static> {
    // SAFETY: cortex-m-rt owns the single stack described by its linker symbols.
    unsafe { paint_cortex_m_runtime::<STACK_SAFE_ZONE>() }.unwrap()
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

#[cfg(feature = "rsa768")]
const KEY_A: KeyInput = KeyInput {
    modulus: &N_768,
    private_exponent: &D_768,
};
#[cfg(feature = "rsa768")]
const KEY_B: KeyInput = KeyInput {
    modulus: &N_768_B,
    private_exponent: &D_768_B,
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

#[derive(Clone, Copy)]
struct SignOutcome {
    ok: bool,
    rng_words: u32,
}

struct CountingCryptoRng {
    inner: ChaCha12Rng,
    words: u32,
}

impl CountingCryptoRng {
    fn new(seed: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        Self {
            inner: ChaCha12Rng::from_seed(bytes),
            words: 0,
        }
    }
}

impl TryRng for CountingCryptoRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.words = self.words.wrapping_add(1);
        self.inner.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.words = self.words.wrapping_add(2);
        self.inner.try_next_u64()
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.words = self
            .words
            .wrapping_add(destination.len().div_ceil(4) as u32);
        self.inner.try_fill_bytes(destination)
    }
}

impl TryCryptoRng for CountingCryptoRng {}

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
    let mut rng = CountingCryptoRng::new(RNG_SEED);
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

#[cfg(all(feature = "rsa768", not(feature = "etm-single-trial")))]
fn prepare_pss_key(input: &KeyInput) -> Option<PssSigningKey> {
    let Ok(public_key) = public_key_ct_from_be_bytes::<Carrier>(black_box(input.modulus), 65537)
    else {
        return None;
    };
    let Ok(d) = Carrier::try_from_be_bytes_vartime(black_box(input.private_exponent)) else {
        return None;
    };
    Some(PssGenericSigningKey::<Sha256, _, _>::new(
        GenericRsaPrivateKey::from_public_and_d(public_key, d),
    ))
}

#[cfg(all(feature = "rsa768", not(feature = "etm-single-trial")))]
#[inline(never)]
fn sign_once_pss(signing_key: &PssSigningKey) -> SignOutcome {
    let mut rng = CountingCryptoRng::new(RNG_SEED);
    let mut encoded_message = [0u8; KEY_BYTES];
    let mut signature = [0u8; KEY_BYTES];
    // salt_len defaults to D::output_size(); 32 bytes for SHA-256.
    let mut salt = [0u8; 32];
    let ok = signing_key
        .try_sign_with_rng_into(
            &mut rng,
            black_box(MESSAGE),
            &mut encoded_message,
            &mut signature,
            &mut salt,
        )
        .is_ok();
    let _ = black_box((encoded_message, signature, salt));
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
    rtt::print(format_args!(
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
    let platform = DwtMeasurementPlatform::enable(
        &mut peripherals.DCB,
        &mut peripherals.DWT,
        Some(hclk_hz as u64),
    )
    .unwrap();
    #[cfg(feature = "etm-single-trial")]
    {
        let _reporter = rtt::init_ct_compatible();
        let _ = platform;
        // SAFETY: the host writes this selector while the core is halted at
        // reset, before main executes.
        let key_index = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(embedded_measure_etm_key_index))
        };
        let key_input = match key_index {
            0 => &KEY_A,
            1 => &KEY_B,
            _ => {
                rtt::print(format_args!("SETUP_FAIL key:{}\n", key_index));
                stop();
            }
        };
        let Some(key) = prepare_key(key_input) else {
            rtt::print(format_args!("SETUP_FAIL key:{}\n", key_index));
            stop();
        };
        run_etm_single_trial(&key, key_index, hclk_hz);
    }

    #[cfg(all(not(feature = "etm-single-trial"), not(feature = "localize")))]
    {
        let Some(key_a) = prepare_key(&KEY_A) else {
            rtt::print(format_args!("SETUP_FAIL key:A\n"));
            stop();
        };
        run_campaign(key_a, platform, hclk_hz)
    }

    #[cfg(all(not(feature = "etm-single-trial"), feature = "localize"))]
    {
        let Some(key_a) = prepare_key(&KEY_A) else {
            rtt::print(format_args!("SETUP_FAIL key:A\n"));
            stop();
        };
        run_localize(key_a, platform, hclk_hz)
    }
}

#[cfg(not(feature = "etm-single-trial"))]
fn run_campaign(key_a: SigningKey, mut platform: DwtMeasurementPlatform<'_>, hclk_hz: u32) -> ! {
    let mut reporter = rtt::init_ct_compatible();
    let stack_probe = paint_stack();
    let Some(key_b) = prepare_key(&KEY_B) else {
        rtt::print(format_args!("SETUP_FAIL key:B\n"));
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
        Field::token("sign_conditioning", SIGN_CONDITIONING),
    ];
    let fixture_fields = [Field::token("carrier", CARRIER)];
    let summary_fields = [Field::token("carrier", CARRIER)];
    let mut suite = PairedSuite::<_, _, TRIALS>::start(
        &mut platform,
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
    // At 0 wait states the measurement is deterministic, so per-sample
    // conditioning is redundant; it stays behind `conditioning` for the caliper
    // lifecycle validation but is off for the (0-WS) gate, which halves the
    // sign count.
    #[cfg(feature = "conditioning")]
    suite
        .positive_conditioned(
            "pkcs1v15_blinded_sign",
            &key_a,
            &key_b,
            &mut (),
            |_, _, signing_key| {
                let outcome = sign_once(black_box(signing_key));
                assert!(
                    streams_matched && outcome.ok && outcome.rng_words == preflight_a.rng_words
                );
            },
            |_, signing_key| {
                let outcome = sign_once(signing_key);
                streams_matched && outcome.ok && outcome.rng_words == preflight_a.rng_words
            },
        )
        .unwrap();
    #[cfg(not(feature = "conditioning"))]
    suite
        .positive("pkcs1v15_blinded_sign", &key_a, &key_b, |signing_key| {
            let outcome = sign_once(signing_key);
            streams_matched && outcome.ok && outcome.rng_words == preflight_a.rng_words
        })
        .unwrap();
    // Second signing scheme on the gate. The measured private op is identical to
    // pkcs1v15; this covers the distinct EMSA-PSS encoding path. PSS draws a salt
    // on top of the blinding factor, so it has its own preflight/word count.
    #[cfg(feature = "rsa768")]
    {
        let Some(pss_key_a) = prepare_pss_key(&KEY_A) else {
            rtt::print(format_args!("SETUP_FAIL pss:A\n"));
            stop();
        };
        let Some(pss_key_b) = prepare_pss_key(&KEY_B) else {
            rtt::print(format_args!("SETUP_FAIL pss:B\n"));
            stop();
        };
        let pss_a = sign_once_pss(&pss_key_a);
        let pss_b = sign_once_pss(&pss_key_b);
        let pss_streams_matched = pss_a.ok && pss_b.ok && pss_a.rng_words == pss_b.rng_words;
        suite
            .positive("pss_blinded_sign", &pss_key_a, &pss_key_b, |signing_key| {
                let outcome = sign_once_pss(signing_key);
                pss_streams_matched && outcome.ok && outcome.rng_words == pss_a.rng_words
            })
            .unwrap();
    }
    const ZERO: [u8; KEY_BYTES] = [0; KEY_BYTES];
    suite
        .negative(
            "negative_early_exit",
            &ZERO,
            KEY_B.private_exponent,
            negative_early_exit,
        )
        .unwrap();
    // SAFETY: this single-threaded firmware exclusively owns its runtime stack.
    let stack = unsafe { stack_probe.measure() };
    suite
        .stack_measurement(stack, &[Field::token("carrier", CARRIER)])
        .unwrap();
    // Emit the summary before the overflow assert. finish() already fails the
    // verdict on overflow (the suite folds `passed &= !overflowed`), so sending
    // EM_SUMMARY first lets the host see the completion marker and fail fast
    // rather than waiting out the full rig timeout on a panic with no marker.
    suite.finish().unwrap();
    assert!(!stack.overflowed);
    stop();
}

// ── Per-stage localizer ────────────────────────────────────────────
// Times each sub-stage of the blinded private op for both keys; the stage
// carrying a key-dependent A-vs-B delta is the one to attribute.
#[cfg(feature = "localize")]
mod localize_probe {
    use core::sync::atomic::{AtomicU32, Ordering};

    pub const N_STAGES: usize = 10;
    pub const NAMES: [&str; N_STAGES] = [
        "sample_r",
        "r_to_monty",
        "invert_r",
        "r_pow_e",
        "c_to_monty",
        "blind_mul",
        "pow_d",
        "unblind_mul",
        "retrieve",
        "verify",
    ];
    static STAGE_TS: [AtomicU32; N_STAGES] = [const { AtomicU32::new(0) }; N_STAGES];
    static START: AtomicU32 = AtomicU32::new(0);

    // The probe cost is identical on every call, so it cancels in the per-stage
    // A-vs-B delta.
    pub fn record(stage: u32) {
        let now = cortex_m::peripheral::DWT::cycle_count();
        if let Some(slot) = STAGE_TS.get(stage as usize) {
            slot.store(now, Ordering::Relaxed);
        }
    }

    pub fn reset(start: u32) {
        START.store(start, Ordering::Relaxed);
        for slot in &STAGE_TS {
            slot.store(start, Ordering::Relaxed);
        }
    }

    // First stage is measured from START; the rest are inter-mark deltas.
    pub fn durations() -> [u32; N_STAGES] {
        let mut out = [0u32; N_STAGES];
        let mut prev = START.load(Ordering::Relaxed);
        for i in 0..N_STAGES {
            let ts = STAGE_TS[i].load(Ordering::Relaxed);
            out[i] = ts.wrapping_sub(prev);
            prev = ts;
        }
        out
    }
}

#[cfg(feature = "localize")]
fn run_localize(key_a: SigningKey, _platform: DwtMeasurementPlatform<'_>, hclk_hz: u32) -> ! {
    let _reporter = rtt::init_ct_compatible();
    let Some(key_b) = prepare_key(&KEY_B) else {
        rtt::print(format_args!("SETUP_FAIL key:B\n"));
        stop();
    };
    rsa::ct_probe::set_probe(localize_probe::record);

    // Warm caches/flash paths so the first-sample setup effect doesn't skew the
    // timed runs below (the same warm-up the campaign path uses).
    let _ = sign_once(black_box(&key_a));

    localize_probe::reset(cortex_m::peripheral::DWT::cycle_count());
    let out_a = sign_once(black_box(&key_a));
    let da = localize_probe::durations();

    localize_probe::reset(cortex_m::peripheral::DWT::cycle_count());
    let out_b = sign_once(black_box(&key_b));
    let db = localize_probe::durations();

    for i in 0..localize_probe::N_STAGES {
        rtt::print(format_args!(
            "LOCALIZE_STAGE name:{} a:{} b:{} delta:{}\n",
            localize_probe::NAMES[i],
            da[i],
            db[i],
            (da[i] as i64) - (db[i] as i64),
        ));
    }
    rtt::print(format_args!(
        "LOCALIZE_SUMMARY frequency_hz:{} a_ok:{} b_ok:{} rng_words_a:{} rng_words_b:{}\n",
        hclk_hz, out_a.ok as u8, out_b.ok as u8, out_a.rng_words, out_b.rng_words,
    ));
    stop()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    rtt::print(format_args!("PANIC: {}\n", info));
    loop {
        cortex_m::asm::nop();
    }
}
