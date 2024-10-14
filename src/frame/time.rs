use std::io::Cursor;

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};

// CP56Time2a := CP56{Milliseconds,Minutes,Reserve1, Invalid, Hours, Reserve2, Summer time,
// Day of month, Day of week, Months, Reserve3, Years, Reserve4}
//    Milliseconds := UI16[1...16]<0...59999>
//    Minutes := UI16[17...22]<0...59>
//    Reserve1=RES1 := BS1[23]
//        Invalid=IV := BS1[24]<0...1>    IV<0> := 有效
//                                        IV<1> := 无效
//        Hours := UI5[25...29]<0...23>
//    Reserve2=RES2 := BS2<30...31>
// Summer time=SU := BS1[32]<0...1>       SU<0> := 标准时间
//                                        SU<1> := 夏季时间
//     Day of month := UI5[33...37]<1...31>
//     Day of week  := UI3[38...40]<1...7>
//     Months       := UI4<41...44><1...12>
// Reserve3=RES3 := BS4[45...48]
// Years := UI7[49...55]<0...99>
// Reserve4=RES4 := Bs1[56]
// |   8   |   7   |   6   |   5   |   4   |   3   |   2   |   1    |
// | 2⁷                               ms                         2⁰ |
// | 2¹⁵                              ms                         2⁸ |
// | IV    | RES1  | 2⁵               min                        2⁰ |
// | SU    |      RES2     | 2⁴       hour                       2⁰ |
// | 2²   Day of week   2⁰ | 2⁴   Day of month                   2⁰ |
// |      RES3                     | 2³       mon                2⁰ |
// | RES4  | 2⁶                      a                           2⁰ |
// CP56Time2a , CP24Time2a, CP16Time2a
// |         Milliseconds(D7--D0)        | Milliseconds = 0-59999
// |         Milliseconds(D15--D8)       |
// | IV(D7)   RES1(D6)  Minutes(D5--D0)  | Minutes = 1-59, IV = invalid,0 = valid, 1 = invalid
// | SU(D7)   RES2(D6-D5)  Hours(D4--D0) | Hours = 0-23, SU = summer Time,0 = standard time, 1 = summer time,
// | DayOfWeek(D7--D5) DayOfMonth(D4--D0)| DayOfMonth = 1-31  DayOfWeek = 1-7
// | RES3(D7--D4)        Months(D3--D0)  | Months = 1-12
// | RES4(D7)            Year(D6--D0)    | Year = 0-99

pub fn cp56time2a(time: DateTime<Utc>) -> Bytes {
    let mut buf = BytesMut::with_capacity(8);

    let msec = (time.nanosecond() / 1000000) as u16 + time.second() as u16 * 1000;
    let minute = time.minute() as u8;
    let hour = time.hour() as u8;
    let weekday = time.weekday().number_from_monday() as u8;
    let day = time.day() as u8;
    let month = time.month() as u8;
    let year = (time.year() - 2000) as u8;

    buf.put_u16_le(msec);
    buf.put_u8(minute);
    buf.put_u8(hour);
    buf.put_u8(weekday << 5 | day);
    buf.put_u8(month);
    buf.put_u8(year);

    buf.freeze()
}

// CP24Time2a := CP24 {Milliseconds,Minutes,Reserve1, Invalid}
//    Milliseconds := UI16[1...16]<0...59999>
//    Minutes := UI16[17...22]<0...59>
//    Reserve1=RES1 := BS1[23]
//        Invalid=IV := BS1[24]<0...1>    IV<0> := 有效
//                                        IV<1> := 无效
// |   8   |   7   |   6   |   5   |   4   |   3   |   2   |   1    |
// | 2⁷                               ms                         2⁰ |
// | 2¹⁵                              ms                         2⁸ |
// | IV    | RES1  | 2⁵               min                        2⁰ |
pub fn cp24time2a(time: DateTime<Utc>) -> Bytes {
    let mut buf = BytesMut::with_capacity(3);

    let msec = (time.nanosecond() / 1000000) as u16 + time.second() as u16 * 1000;
    let minute = time.minute() as u8;

    buf.put_u16_le(msec);
    buf.put_u8(minute);

    buf.freeze()
}

// CP16Time2a := UI16 [1...16]<0...59999>
// 二进制时间是用于动作时间如"继电器动作时间"或者“继电器持续时间”
pub fn cp16time2a(time: DateTime<Utc>) -> Bytes {
    let mut buf = BytesMut::with_capacity(2);

    let msec = (time.nanosecond() / 1000000) as u16 + time.second() as u16 * 1000;

    buf.put_u16_le(msec);
    buf.freeze()
}

pub fn cp16time2a_from_msec(msec: u16) -> Bytes {
    let mut buf = BytesMut::with_capacity(2);
    buf.put_u16_le(msec);
    buf.freeze()
}

// decode info object byte to CP56Time2a
pub fn decode_cp56time2a(rdr: &mut Cursor<&Bytes>) -> Result<Option<DateTime<Utc>>> {
    if rdr.remaining() < 7 {
        return Ok(None);
    }
    let millisecond = rdr.read_u16::<LittleEndian>()?;
    let msec = millisecond % 1000;
    let sec = (millisecond / 1000) as u32;
    let min = rdr.read_u8()?;
    let invalid = min & 0x80;
    let min = (min & 0x3f) as u32;
    let hour = (rdr.read_u8()? & 0x1f) as u32;
    let day = (rdr.read_u8()? & 0x1f) as u32;
    let month = (rdr.read_u8()? & 0x0f) as u32;
    let year = 2000 + (rdr.read_u8()? & 0x7f) as i32;

    if invalid != 0 {
        Ok(None)
    } else {
        Ok(Some(
            Utc.with_ymd_and_hms(year, month, day, hour, min, sec)
                .unwrap(),
        ))
    }
}

// Decode info object byte to CP24Time2a
pub fn decode_cp24time2a(rdr: &mut Cursor<&Bytes>) -> Result<Option<DateTime<Utc>>> {
    if rdr.remaining() < 3 {
        return Ok(None);
    }
    let millisecond = rdr.read_u16::<LittleEndian>()?;
    let msec = millisecond % 1000;
    let sec = (millisecond / 1000) as u32;
    let min = rdr.read_u8()?;
    let invalid = min & 0x80;
    let min = (min & 0x3f) as u32;

    let now_utc = Utc::now();
    let hour = now_utc.hour();
    let day = now_utc.day();
    let month = now_utc.month();
    let year = now_utc.year();
    if invalid != 0 {
        Ok(None)
    } else {
        Ok(Some(
            Utc.with_ymd_and_hms(year, month, day, hour, min, sec)
                .unwrap(),
        ))
    }
}
