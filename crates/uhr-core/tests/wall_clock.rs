use uhr_core::recording::*;
use uhr_core::wall_clock::{self, Error, Time, format, offsets, parse, utc_of};

const S: u64 = 1_000_000_000;

fn utc(text: &str) -> i64 {
    parse(text).unwrap()
}

/// A recording from 12:00:00 to 12:00:10 UTC, at 5 s to 15 s on its clock,
/// with the system clock read a second before and after.
fn manifest() -> Manifest {
    let noon = utc("2026-11-06T12:00:00Z");
    Manifest {
        format_version: FORMAT_VERSION,
        platform: Platform {
            os: "linux".into(),
            arch: "x86_64".into(),
        },
        target: Target {
            command: vec!["app".into()],
            launched: true,
            runtime_support: Some(Vec::new()),
            exit: None,
        },
        clock: Clock::Monotonic,
        start_ns: Some(5 * S),
        end_ns: Some(15 * S),
        wall_clock: Some(WallClock {
            start: ClockReading {
                time_ns: 4 * S,
                realtime_ns: noon - S as i64,
            },
            end: ClockReading {
                time_ns: 16 * S,
                realtime_ns: noon + 11 * S as i64,
            },
        }),
        streams: Vec::new(),
        missing_signals: Vec::new(),
        kernel_symbols: KernelSymbols::Saved,
    }
}

fn of_day(text: &str) -> Option<Time> {
    Some(Time::Utc(utc(text)))
}

#[test]
fn reads_times_of_day_with_their_offset_from_utc() {
    let noon = utc("2026-11-06T12:00:00Z");
    assert_eq!(utc("2026-11-06T13:00:00+01:00"), noon);
    assert_eq!(utc("2026-11-06T12:00:00.5Z"), noon + 500_000_000);
    for local in ["2026-11-06T12:00:00", "2026-11-06", "12:00:00Z", "1.5s"] {
        assert!(matches!(parse(local), Err(Error::Parse(_))), "{local}");
    }
}

#[test]
fn writes_times_of_day_in_utc_to_the_microsecond() {
    let noon = utc("2026-11-06T12:00:00Z");
    assert_eq!(format(noon + 1_234_567), "2026-11-06T12:00:00.001234Z");
}

#[test]
fn turns_times_of_day_into_offsets_and_back() {
    let manifest = manifest();
    let range = offsets(
        &manifest,
        of_day("2026-11-06T12:00:02Z"),
        of_day("2026-11-06T14:00:03.5+02:00"),
    );
    assert_eq!(range.unwrap(), (Some(2 * S), Some(3 * S + S / 2)));
    let mixed = offsets(
        &manifest,
        Some(Time::Offset(S)),
        of_day("2026-11-06T12:00:02Z"),
    );
    assert_eq!(mixed.unwrap(), (Some(S), Some(2 * S)));
    assert_eq!(
        utc_of(&manifest, 2 * S).unwrap(),
        utc("2026-11-06T12:00:02Z")
    );
}

#[test]
fn cuts_a_range_of_times_of_day_to_the_recording() {
    let range = offsets(
        &manifest(),
        of_day("2026-11-06T11:59:00Z"),
        of_day("2026-11-06T12:05:00Z"),
    );
    assert_eq!(range.unwrap(), (Some(0), Some(300 * S)));
}

#[test]
fn refuses_a_range_of_times_of_day_outside_the_recording() {
    let manifest = manifest();
    match offsets(&manifest, of_day("2026-11-06T12:00:10Z"), None) {
        Err(Error::AfterEnd { time, end }) => {
            assert_eq!(time, "2026-11-06T12:00:10.000000Z");
            assert_eq!(end, "2026-11-06T12:00:10.000000Z");
        }
        other => panic!("{other:?}"),
    }
    match offsets(&manifest, None, of_day("2026-11-06T12:00:00Z")) {
        Err(Error::BeforeStart { start, .. }) => {
            assert_eq!(start, "2026-11-06T12:00:00.000000Z");
        }
        other => panic!("{other:?}"),
    }
    // Past the end, an offset is no error: it covers less than it asks for.
    let past = offsets(&manifest, Some(Time::Offset(20 * S)), None);
    assert_eq!(past.unwrap(), (Some(20 * S), None));
}

#[test]
fn a_range_has_to_start_before_it_ends() {
    let manifest = manifest();
    let backwards = [
        (Some(Time::Offset(3 * S)), Time::Offset(3 * S)),
        (
            Some(Time::Offset(5 * S)),
            Time::Utc(utc("2026-11-06T12:00:04Z")),
        ),
        (None, Time::Offset(0)),
    ];
    for (from, to) in backwards {
        let range = offsets(&manifest, from, Some(to));
        assert!(matches!(range, Err(Error::Empty)), "{range:?}");
    }
}

#[test]
fn needs_the_system_clock_only_for_times_of_day() {
    let mut manifest = manifest();
    manifest.wall_clock = None;
    let range = offsets(&manifest, Some(Time::Offset(S)), Some(Time::Offset(2 * S)));
    assert_eq!(range.unwrap(), (Some(S), Some(2 * S)));
    let of_day = offsets(&manifest, of_day("2026-11-06T12:00:01Z"), None);
    assert!(matches!(of_day, Err(Error::NoWallClock)), "{of_day:?}");
}

#[test]
fn knows_no_times_of_day_if_the_system_clock_was_set_during_the_capture() {
    let mut manifest = manifest();
    let wall_clock = manifest.wall_clock.as_mut().unwrap();
    wall_clock.end.realtime_ns += 500_000;
    assert!(utc_of(&manifest, 0).is_ok());

    let wall_clock = manifest.wall_clock.as_mut().unwrap();
    wall_clock.end.realtime_ns -= 2 * S as i64;
    match utc_of(&manifest, 0) {
        Err(error @ Error::ClockSet { by_ns }) => {
            assert_eq!(by_ns, -2 * S as i64 + 500_000);
            assert!(error.to_string().contains("set back by"), "{error}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_recording_of_nothing_has_no_times_of_day() {
    let mut manifest = manifest();
    manifest.start_ns = None;
    manifest.end_ns = None;
    let result = wall_clock::utc_of(&manifest, 0);
    assert!(matches!(result, Err(Error::NothingRecorded)), "{result:?}");
}
