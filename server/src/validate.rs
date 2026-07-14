//! Validation of minute ids, messages and names.
//! Rust port of the page's tested core functions (71 JS assertions).
//! The server is the authority: everything engraved passes through here.

pub fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

pub fn days_in_month(y: i64, mo: u32) -> u32 {
    const D: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) {
        return 0; // no such month: total function, never panics on a bad index
    }
    if mo == 2 && is_leap_year(y) {
        29
    } else {
        D[(mo - 1) as usize]
    }
}

/// Canonical UTC minute id "YYYY-MM-DDTHH:MMZ", or None if the minute does not exist.
pub fn canonical_minute_id(y: i64, mo: u32, d: u32, h: u32, mi: u32) -> Option<String> {
    if !(1900..=2126).contains(&y) {
        return None;
    }
    if !(1..=12).contains(&mo) {
        return None;
    }
    if d < 1 || d > days_in_month(y, mo) {
        return None;
    }
    if h > 23 || mi > 59 {
        return None;
    }
    Some(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}Z"))
}

/// Days from 1970-01-01 for a civil date (proleptic Gregorian).
/// Howard Hinnant's days_from_civil algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Civil date from days since 1970-01-01 (proleptic Gregorian).
/// Howard Hinnant's civil_from_days algorithm (inverse of days_from_civil).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Canonical minute id from epoch seconds, or None outside 1900-2126.
pub fn epoch_to_minute_id(epoch: i64) -> Option<String> {
    let minutes = epoch.div_euclid(60);
    let (y, mo, d) = civil_from_days(minutes.div_euclid(1440));
    let of_day = minutes.rem_euclid(1440);
    canonical_minute_id(y, mo, d, (of_day / 60) as u32, (of_day % 60) as u32)
}

/// Strict parse of a canonical minute id. Returns epoch seconds (multiple
/// of 60), or None. Rejects non-canonical forms and impossible dates
/// (e.g. 2027-02-29).
pub fn minute_id_to_epoch(id: &str) -> Option<i64> {
    let b = id.as_bytes();
    if b.len() != 17
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = &id[r];
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse::<i64>().ok()
    };
    let y = num(0..4)?;
    let mo = num(5..7)? as u32;
    let d = num(8..10)? as u32;
    let h = num(11..13)? as u32;
    let mi = num(14..16)? as u32;
    if canonical_minute_id(y, mo, d, h, mi)? != id {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86400 + (h * 3600 + mi * 60) as i64)
}

/// A character forbidden from any engraved text. Rejects C0/C1 controls AND
/// every bidi/format/zero-width code point: those are invisible or reorder
/// text, so they would let a permanent engraving render deceptively
/// (Trojan-Source) while its blake3 seal still matches the bytes. U+FEFF is
/// included so the Rust normalization can never diverge from the client's
/// `\s`-based one (JS treats U+FEFF as whitespace, Rust does not).
pub fn is_forbidden_char(c: char) -> bool {
    let u = c as u32;
    u < 0x20                              // C0 controls
        || (0x7f..=0x9f).contains(&u)     // DEL + C1 controls
        || (0x200b..=0x200f).contains(&u) // zero-width, LRM/RLM/ALM
        || (0x202a..=0x202e).contains(&u) // bidi embeddings/overrides
        || (0x2060..=0x2064).contains(&u) // word joiner + invisible operators
        || (0x2066..=0x206f).contains(&u) // bidi isolates + deprecated format
        || u == 0xfeff                    // BOM / zero-width no-break space
        || (0xfff9..=0xfffb).contains(&u) // interlinear annotation anchors
}

/// Message: whitespace collapsed, 1..=108 chars, no control/bidi/invisible.
pub fn validate_message(raw: &str) -> Result<String, &'static str> {
    let msg = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if msg.is_empty() {
        return Err("empty");
    }
    if msg.chars().count() > 108 {
        return Err("too long (max 108 characters)");
    }
    if msg.chars().any(is_forbidden_char) {
        return Err("invalid characters");
    }
    Ok(msg)
}

/// Name: optional (empty = Anonymous), max 24 chars, same charset rule.
pub fn validate_name(raw: &str) -> Result<String, &'static str> {
    let name = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.chars().count() > 24 {
        return Err("too long (max 24 characters)");
    }
    if name.chars().any(is_forbidden_char) {
        return Err("invalid characters");
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leap_years() {
        assert!(is_leap_year(2028));
        assert!(!is_leap_year(2027));
        assert!(!is_leap_year(2100)); // century rule
        assert!(is_leap_year(2000)); // 400 rule
        assert!(!is_leap_year(1900));
    }

    #[test]
    fn canonical_ids() {
        assert_eq!(
            canonical_minute_id(2028, 2, 29, 12, 0).as_deref(),
            Some("2028-02-29T12:00Z")
        );
        assert_eq!(canonical_minute_id(2027, 2, 29, 12, 0), None);
        assert_eq!(canonical_minute_id(2100, 2, 29, 0, 0), None);
        assert_eq!(canonical_minute_id(2026, 4, 31, 0, 0), None);
        assert_eq!(canonical_minute_id(2026, 6, 30, 23, 60), None); // minute 60
        assert_eq!(canonical_minute_id(2026, 6, 30, 24, 0), None);
        assert_eq!(canonical_minute_id(1899, 1, 1, 0, 0), None);
        assert_eq!(canonical_minute_id(10000, 1, 1, 0, 0), None);
        assert_eq!(canonical_minute_id(2026, 0, 1, 0, 0), None);
    }

    #[test]
    fn epochs() {
        // Known values, independently derived.
        assert_eq!(minute_id_to_epoch("1970-01-01T00:00Z"), Some(0));
        assert_eq!(minute_id_to_epoch("2026-01-01T00:00Z"), Some(1_767_225_600));
        assert_eq!(
            minute_id_to_epoch("2026-07-10T00:00Z"),
            Some(1_767_225_600 + 190 * 86400)
        );
        // 2000-03-01 minus one minute
        assert_eq!(minute_id_to_epoch("2000-02-29T23:59Z"), Some(951_868_740));
    }

    #[test]
    fn strict_parse() {
        assert_eq!(minute_id_to_epoch("2027-02-29T12:00Z"), None);
        assert_eq!(minute_id_to_epoch("2026-7-10T00:00Z"), None);
        assert_eq!(minute_id_to_epoch("2026-07-10 00:00Z"), None);
        assert_eq!(minute_id_to_epoch("2026-07-10T00:00"), None);
        assert_eq!(minute_id_to_epoch("2026-07-10T00:00:00Z"), None); // second format
        assert_eq!(minute_id_to_epoch(""), None);
        assert_eq!(minute_id_to_epoch("abcd-ef-ghTij:klZ"), None);
    }

    #[test]
    fn epoch_to_id_inverse() {
        assert_eq!(epoch_to_minute_id(0).as_deref(), Some("1970-01-01T00:00Z"));
        assert_eq!(epoch_to_minute_id(59).as_deref(), Some("1970-01-01T00:00Z")); // floors
        assert_eq!(
            epoch_to_minute_id(951_868_740).as_deref(),
            Some("2000-02-29T23:59Z")
        );
        for id in [
            "1900-01-01T00:00Z",
            "2028-02-29T12:34Z",
            "2126-12-31T23:59Z",
        ] {
            let e = minute_id_to_epoch(id).expect("boundary id must parse");
            assert_eq!(epoch_to_minute_id(e).as_deref(), Some(id));
        }
        let first = minute_id_to_epoch("1900-01-01T00:00Z").expect("first minute");
        let last = minute_id_to_epoch("2126-12-31T23:59Z").expect("last minute");
        assert_eq!(epoch_to_minute_id(first - 60), None);
        assert_eq!(epoch_to_minute_id(last + 60), None);
    }

    #[test]
    fn round_trip_boundaries() {
        for id in [
            "1900-01-01T00:00Z",
            "2000-02-29T23:59Z",
            "2026-12-31T23:59Z",
            "2028-02-29T00:00Z",
            "2126-12-31T23:59Z",
        ] {
            let e = minute_id_to_epoch(id).expect("boundary id must parse");
            assert_eq!(e % 60, 0); // minute ids sit on minute boundaries
            assert_eq!(minute_id_to_epoch(id), Some(e));
        }
    }

    #[test]
    fn messages() {
        assert_eq!(
            validate_message("Hello world").as_deref(),
            Ok("Hello world")
        );
        assert_eq!(
            validate_message("  spaced   out  ").as_deref(),
            Ok("spaced out")
        );
        assert!(validate_message("").is_err());
        assert!(validate_message(&"a".repeat(108)).is_ok());
        assert!(validate_message(&"a".repeat(109)).is_err());
        assert_eq!(validate_message("line\nbreak").as_deref(), Ok("line break"));
        assert!(validate_message("bad\u{7}bell").is_err());
        assert!(validate_message("plain text ok").is_ok());
    }

    #[test]
    fn rejects_bidi_and_invisible_unicode() {
        // Trojan-Source: RTL override that reorders the rendered text
        assert!(validate_message("Paid \u{202e}drac tiderc a htiw").is_err());
        // zero-width chars hidden inside the words
        assert!(validate_message("in\u{200b}vis\u{200b}ible").is_err());
        assert!(validate_message("join\u{200d}er").is_err());
        // BOM / ZWNBSP: JS \s would strip it, Rust must reject not diverge
        assert!(validate_message("\u{feff}hello").is_err());
        // bidi isolates and word joiner
        assert!(validate_message("a\u{2066}b\u{2069}c").is_err());
        assert!(validate_message("word\u{2060}joiner").is_err());
        // same guard on names
        assert!(validate_name("Ann\u{202e}a").is_err());
        assert!(validate_name("z\u{200b}w").is_err());
        // legitimate accents / non-ASCII letters still pass
        assert!(validate_message("cafe creme a Montreal").is_ok());
        assert!(validate_name("Jose").is_ok());
    }

    #[test]
    fn names() {
        assert_eq!(validate_name("").as_deref(), Ok(""));
        assert_eq!(validate_name("Jean").as_deref(), Ok("Jean"));
        assert!(validate_name(&"a".repeat(25)).is_err());
    }
}
