use nom::bytes::streaming::tag;
use nom::combinator::map;
use nom::sequence::tuple;
use nom::IResult;
use nom::{branch::alt, character::streaming::digit1};
use AnsiItem::{Escape, Text};

//https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
#[derive(Debug, PartialEq, Clone)]
pub enum EscapeItem {
    //Cursor Controls
    CursorPos(Option<(u32, u32)>),
    CursorUp(u32),
    CursorDown(u32),
    CursorRight(u32),
    CursorLeft(u32),
    CursorNext(u32),
    CursorPrevious(u32),
    CursorColumn(u32),
    CursorSave,
    CursorRestore,

    //Erase Functions
    EraseDisplay(Option<u8>),
    EraseLine(Option<u8>),

    //Graphics Mode
    SetGraphicsMode(Vec<u8>),

    //Screen Modes
    SetMode(u8),
    ResetMode(u8),

    //Common Private Modes
    HideCursor,
    ShowCursor,
}

use core::fmt::{Display, Formatter, Result as DisplayResult};

impl Display for EscapeItem {
    fn fmt(&self, formatter: &mut Formatter) -> DisplayResult {
        write!(formatter, "\u{1b}")?;
        use EscapeItem::*;
        match self {
            CursorPos(None) => write!(formatter, "[H"),
            CursorPos(Some((line, col))) => write!(formatter, "[{};{}H", line, col),
            CursorUp(amt) => write!(formatter, "[{}A", amt),
            CursorDown(amt) => write!(formatter, "[{}B", amt),
            CursorRight(amt) => write!(formatter, "[{}C", amt),
            CursorLeft(amt) => write!(formatter, "[{}D", amt),
            CursorNext(amt) => write!(formatter, "[{}E", amt),
            CursorPrevious(amt) => write!(formatter, "[{}F", amt),
            CursorColumn(amt) => write!(formatter, "[{}G", amt),
            CursorSave => write!(formatter, "[s"),
            CursorRestore => write!(formatter, "[u"),

            EraseDisplay(None) => write!(formatter, "[J"),
            EraseDisplay(Some(amt)) => write!(formatter, "[{}J", amt),
            EraseLine(None) => write!(formatter, "[K"),
            EraseLine(Some(amt)) => write!(formatter, "[{}K", amt),
            SetGraphicsMode(vec) => match vec.len() {
                0 => write!(formatter, "[m"),
                1 => write!(formatter, "[{}m", vec[0]),
                2 => write!(formatter, "[{};{}m", vec[0], vec[1]),
                3 => write!(formatter, "[{};{};{}m", vec[0], vec[1], vec[2]),
                5 => write!(
                    formatter,
                    "[{};{};{};{};{}m",
                    vec[0], vec[1], vec[2], vec[3], vec[4]
                ),
                _ => unreachable!(),
            },
            SetMode(mode) => write!(formatter, "[={}h", mode),
            ResetMode(mode) => write!(formatter, "[={}l", mode),
            ShowCursor => write!(formatter, "[?25h"),
            HideCursor => write!(formatter, "[?25l"),
        }
    }
}

fn stag(p: &str) -> impl Fn(&str) -> IResult<&str, &str> + '_ {
    move |input: &str| tag(p)(input)
}

fn cursor_control_parser(input: &str) -> IResult<&str, EscapeItem> {
    return alt((
        map(tag("[H"), |_| EscapeItem::CursorPos(None)),
        //ESC[{line};{column}H ESC[{line};{column}f
        map(
            tuple((
                stag("["),
                digit1,
                tag(";"),
                digit1,
                alt((tag("H"), tag("f"))),
            )),
            |(_, s2, _, s4, _)| {
                EscapeItem::CursorPos(Some((s2.parse().unwrap(), s4.parse().unwrap())))
            },
        ),
        //moves cursor up # lines
        map(tuple((stag("["), digit1, tag("A"))), |(_, s1, _)| {
            EscapeItem::CursorUp(s1.parse().unwrap())
        }),
        //moves cursor down # lines
        map(tuple((stag("["), digit1, tag("B"))), |(_, s1, _)| {
            EscapeItem::CursorDown(s1.parse().unwrap())
        }),
        //moves cursor right # lines
        map(tuple((stag("["), digit1, tag("C"))), |(_, s1, _)| {
            EscapeItem::CursorRight(s1.parse().unwrap())
        }),
        //moves cursor left # lines
        map(tuple((stag("["), digit1, tag("D"))), |(_, s1, _)| {
            EscapeItem::CursorLeft(s1.parse().unwrap())
        }),
        //moves cursor to beginning of next line, # lines down
        map(tuple((stag("["), digit1, tag("E"))), |(_, s1, _)| {
            EscapeItem::CursorNext(s1.parse().unwrap())
        }),
        //moves cursor to beginning of previous line, # lines up
        map(tuple((stag("["), digit1, tag("F"))), |(_, s1, _)| {
            EscapeItem::CursorPrevious(s1.parse().unwrap())
        }),
        //moves cursor to column #
        map(tuple((stag("["), digit1, tag("G"))), |(_, s1, _)| {
            EscapeItem::CursorColumn(s1.parse().unwrap())
        }),
        map(tag("[s"), |_| EscapeItem::CursorSave),
        map(tag("[u"), |_| EscapeItem::CursorRestore),
    ))(input);
}

fn erase_parser(input: &str) -> IResult<&str, EscapeItem> {
    return alt((
        map(tag("[J"), |_| EscapeItem::EraseDisplay(None)),
        map(tag("[0J"), |_| EscapeItem::EraseDisplay(Some(0))),
        map(tag("[1J"), |_| EscapeItem::EraseDisplay(Some(1))),
        map(tag("[2J"), |_| EscapeItem::EraseDisplay(Some(2))),
        map(tag("[3J"), |_| EscapeItem::EraseDisplay(Some(3))),
        map(tag("[K"), |_| EscapeItem::EraseLine(None)),
        map(tag("[0K"), |_| EscapeItem::EraseLine(Some(0))),
        map(tag("[1K"), |_| EscapeItem::EraseLine(Some(1))),
        map(tag("[2K"), |_| EscapeItem::EraseLine(Some(2))),
    ))(input);
}

fn graphics_mode_parser(input: &str) -> IResult<&str, EscapeItem> {
    return alt((
        // "ESC[{i}m", i is colors/graphics mode
        map(tuple((stag("["), digit1, tag("m"))), |(_, s2, _)| {
            EscapeItem::SetGraphicsMode(vec![s2.parse().unwrap()])
        }),
        //"ESC[{i};{j}m" i is foreground color code, j is background color code
        map(
            tuple((stag("["), digit1, tag(";"), digit1, tag("m"))),
            |(_, s2, _, s4, _)| {
                EscapeItem::SetGraphicsMode(vec![s2.parse().unwrap(), s4.parse().unwrap()])
            },
        ),
        //"ESC[0;{i};{j}m" i is foreground color code, j is background color code
        map(
            tuple((stag("[0;"), digit1, tag(";"), digit1, tag("m"))),
            |(_, s2, _, s4, _)| {
                EscapeItem::SetGraphicsMode(vec![s2.parse().unwrap(), s4.parse().unwrap()])
            },
        ),
        //ESC[38;5;{ID}m set foreground color. {ID} is is color
        map(tuple((stag("[38;5;"), digit1, tag("m"))), |(_, s2, _)| {
            EscapeItem::SetGraphicsMode(vec![38, 5, s2.parse().unwrap()])
        }),
        //ESC[38;5;{ID}m set background color. {ID} is is color
        map(tuple((stag("[48;5;"), digit1, tag("m"))), |(_, s2, _)| {
            EscapeItem::SetGraphicsMode(vec![48, 5, s2.parse().unwrap()])
        }),
        //ESC[38;2;{r};{g};{b}m, set foreground color as rgb.
        map(
            tuple((
                stag("[38;2;"),
                digit1,
                tag(";"),
                digit1,
                tag(";"),
                digit1,
                tag(";"),
                tag("m"),
            )),
            |(_, s2, _, s4, _, s6, _, _)| {
                EscapeItem::SetGraphicsMode(vec![
                    38,
                    2,
                    s2.parse().unwrap(),
                    s4.parse().unwrap(),
                    s6.parse().unwrap(),
                ])
            },
        ),
        //ESC[38;2;{r};{g};{b}m, set background color as rgb.
        map(
            tuple((
                stag("[48;2;"),
                digit1,
                tag(";"),
                digit1,
                tag(";"),
                digit1,
                tag(";"),
                tag("m"),
            )),
            |(_, s2, _, s4, _, s6, _, _)| {
                EscapeItem::SetGraphicsMode(vec![
                    48,
                    2,
                    s2.parse().unwrap(),
                    s4.parse().unwrap(),
                    s6.parse().unwrap(),
                ])
            },
        ),
    ))(input);
}

fn screen_mode_parser(input: &str) -> IResult<&str, EscapeItem> {
    return alt((
        //Changes the screen width or type to the mode specified by value.
        map(tag("[?25h"), |_| EscapeItem::ShowCursor),
        map(tag("[?25l"), |_| EscapeItem::HideCursor),
    ))(input);
}

fn common_private_parser(input: &str) -> IResult<&str, EscapeItem> {
    return alt((
        //Changes the screen width or type to the mode specified by value.
        map(tuple((stag("[="), digit1, tag("H"))), |(_, s1, _)| {
            EscapeItem::SetMode(s1.parse().unwrap())
        }),
        map(tuple((stag("[="), digit1, tag("l"))), |(_, s1, _)| {
            EscapeItem::ResetMode(s1.parse().unwrap())
        }),
    ))(input);
}

fn escape_parse(input: &str) -> IResult<&str, EscapeItem> {
    return alt((
        cursor_control_parser,
        erase_parser,
        graphics_mode_parser,
        screen_mode_parser,
        common_private_parser,
    ))(input);
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnsiItem {
    Text(String),
    Escape(EscapeItem),
}

impl Display for AnsiItem {
    fn fmt(&self, formatter: &mut Formatter) -> DisplayResult {
        match self {
            Text(txt) => write!(formatter, "{}", txt),
            Escape(seq) => write!(formatter, "{}", seq),
        }
    }
}

pub fn do_parse(input: &str) -> Vec<AnsiItem> {
    let mut result: Vec<AnsiItem> = Vec::new();
    let mut buf = input;
    let mut pos = 0;

    loop {
        if buf[pos..].is_empty() {
            return result;
        }
        let loc = match buf[pos..].find('\u{1b}') {
            Some(loc) => loc,
            None if buf[..pos].len() != 0 => break result.push(Text(buf[..pos].to_string())),
            None => break,
        };
        pos += loc;
        match escape_parse(&buf[pos + 1..]) {
            Ok(seq) => {
                if buf[..pos].len() != 0 {
                    result.push(Text(buf[..pos].to_string()));
                }
                result.push(Escape(seq.1));
                buf = seq.0;
                pos = 0;
            }
            Err(_) => pos += 1, //skip esc
        };
    }
    return result;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let buf = "\x1b[?25hfoo\x1b[?25l\x1b[0Kdot\x1b[5;20Hbo\x1b[4G";
        let result = do_parse(&buf[0..]);

        let expected = vec![
            Escape(EscapeItem::ShowCursor),
            Text("foo".to_string()),
            Escape(EscapeItem::HideCursor),
            Escape(EscapeItem::EraseLine(Some(0))),
            Text("dot".to_string()),
            Escape(EscapeItem::CursorPos(Some((5, 20)))),
            Text("bo".to_string()),
            Escape(EscapeItem::CursorColumn(4)),
        ];
        assert_eq!(result, expected);

        let mut expected_s = "".to_string();
        for it in expected {
            expected_s = expected_s + &it.to_string();
        }
        assert_eq!(buf, &expected_s)
    }
}
