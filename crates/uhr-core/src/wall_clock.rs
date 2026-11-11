use std::str::FromStr;

use chrono::{DateTime, SecondsFormat, Utc};

use crate::recording::{ClockReading, Manifest, WallClock};

/// How far apart the readings at the start and stop can put the two clocks
/// before uhr takes the system clock to have been set during the capture.
/// NTP slews both clocks alike, so only setting the clock, as by hand, by
/// a step of NTP or at a leap second, moves one against the other.
const SET_NS: i64 = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "{0:?} is not a time of day with a date and a UTC offset, as in 2026-11-06T12:34:56.7Z"
    )]
    Parse(String),
    #[error("the recording has no times of day: uhr made it before it read the system clock")]
    NoWallClock,
    #[error(
        "the system clock was set {} by {:.3} s during the capture, so its times of day are not \
         known",
        if *by_ns < 0 { "back" } else { "forward" },
        by_ns.unsigned_abs() as f64 / 1e9
    )]
    ClockSet { by_ns: i64 },
    #[error("nothing was recorded, so no time of day is in the recording")]
    NothingRecorded,
    #[error("{time} is at or after the end of the recording, at {end}")]
    AfterEnd { time: String, end: String },
    #[error("{time} is at or before the start of the recording, at {start}")]
    BeforeStart { time: String, start: String },
    #[error("the start of the time range must be before its end")]
    Empty,
    #[error("needs a unit: ns, us, ms or s, as in 1.5s")]
    NoUnit,
    #[error("{0:?} is not a non-negative number")]
    NotANumber(String),
}

/// A bound of a time range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Time {
    /// From the recording's start.
    Offset(u64),
    /// Nanoseconds since 1970 began in UTC, as CLOCK_REALTIME counts them.
    Utc(i64),
}

/// An offset, or a time of day where it has the shape of one.
impl FromStr for Time {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        if text.contains([':', 'T']) || text.get(4..5) == Some("-") {
            parse(text).map(Time::Utc)
        } else {
            parse_offset(text).map(Time::Offset)
        }
    }
}

/// A duration with a unit, in nanoseconds.
pub fn parse_offset(text: &str) -> Result<u64, Error> {
    let units = [("ns", 1.0), ("us", 1e3), ("ms", 1e6), ("s", 1e9)];
    let Some((number, scale)) = units
        .iter()
        .find_map(|&(unit, scale)| text.strip_suffix(unit).map(|n| (n, scale)))
    else {
        return Err(Error::NoUnit);
    };
    match number.parse::<f64>() {
        Ok(value) if value.is_finite() && value >= 0.0 => Ok((value * scale).round() as u64),
        _ => Err(Error::NotANumber(number.to_owned())),
    }
}

/// Reads an RFC 3339 time, which has a date and a UTC offset: a time
/// without one would be in an unknown time zone.
pub fn parse(text: &str) -> Result<i64, Error> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .and_then(|time| time.timestamp_nanos_opt())
        .ok_or_else(|| Error::Parse(text.to_owned()))
}

/// RFC 3339 in UTC, to the microsecond, as logs most often have them.
pub fn format(utc_ns: i64) -> String {
    DateTime::<Utc>::from_timestamp_nanos(utc_ns).to_rfc3339_opts(SecondsFormat::Micros, true)
}

impl WallClock {
    /// CLOCK_REALTIME less the recording's clock. Fails if the system clock
    /// was set during the capture.
    pub fn offset_ns(&self) -> Result<i64, Error> {
        let offset = |r: &ClockReading| r.realtime_ns - r.time_ns as i64;
        let (start, end) = (offset(&self.start), offset(&self.end));
        match end - start {
            by_ns if by_ns.abs() > SET_NS => Err(Error::ClockSet { by_ns }),
            _ => Ok(start),
        }
    }
}

/// How the recording's times map to times of day.
struct Span {
    start_ns: u64,
    end_ns: u64,
    offset_ns: i64,
}

impl Span {
    fn of(manifest: &Manifest) -> Result<Self, Error> {
        let wall_clock = manifest.wall_clock.as_ref().ok_or(Error::NoWallClock)?;
        let offset_ns = wall_clock.offset_ns()?;
        let (start_ns, end_ns) = manifest
            .start_ns
            .zip(manifest.end_ns)
            .ok_or(Error::NothingRecorded)?;
        Ok(Self {
            start_ns,
            end_ns,
            offset_ns,
        })
    }

    /// `utc_ns` as an offset from the start, negative before it.
    fn offset(&self, utc_ns: i64) -> i128 {
        i128::from(utc_ns) - i128::from(self.offset_ns) - i128::from(self.start_ns)
    }

    fn utc(&self, offset_ns: u64) -> i64 {
        (self.start_ns + offset_ns) as i64 + self.offset_ns
    }
}

/// The time of day an offset into the recording was at.
pub fn utc_of(manifest: &Manifest, offset_ns: u64) -> Result<i64, Error> {
    Ok(Span::of(manifest)?.utc(offset_ns))
}

/// A time range as offsets into the recording, as filters take it. A time
/// of day before the start is the start, and one after the end is past it,
/// as an offset can be, but a range of times of day that ends before the
/// recording or starts after it is refused, as it is more likely a mistake
/// of date or time zone than a question.
pub fn offsets(
    manifest: &Manifest,
    from: Option<Time>,
    to: Option<Time>,
) -> Result<(Option<u64>, Option<u64>), Error> {
    let from = match from {
        Some(Time::Offset(ns)) => Some(ns),
        Some(Time::Utc(utc_ns)) => {
            let span = Span::of(manifest)?;
            let duration = span.end_ns - span.start_ns;
            let offset = span.offset(utc_ns);
            if offset >= i128::from(duration) {
                return Err(Error::AfterEnd {
                    time: format(utc_ns),
                    end: format(span.utc(duration)),
                });
            }
            Some(offset.max(0) as u64)
        }
        None => None,
    };
    let to = match to {
        Some(Time::Offset(ns)) => Some(ns),
        Some(Time::Utc(utc_ns)) => {
            let span = Span::of(manifest)?;
            let offset = span.offset(utc_ns);
            if offset <= 0 {
                return Err(Error::BeforeStart {
                    time: format(utc_ns),
                    start: format(span.utc(0)),
                });
            }
            Some(u64::try_from(offset).unwrap_or(u64::MAX))
        }
        None => None,
    };
    // Without a start, a range starts at the recording's.
    if let Some(to) = to
        && from.unwrap_or(0) >= to
    {
        return Err(Error::Empty);
    }
    Ok((from, to))
}
