// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Lexer for the Prometheus text format 0.0.4, a hand-written port of
//! [`promlex.l`](https://github.com/prometheus/prometheus/blob/main/model/textparse/promlex.l).

use super::ByteSpan;

/// Lexer states, named after the start conditions in `promlex.l`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Init,
    Comment,
    /// After `# HELP` or `# TYPE`, before the metric name.
    Meta1,
    /// The rest of a `# HELP` or `# TYPE` line.
    Meta2,
    Labels,
    LValue,
    Value,
    Timestamp,
}

/// Lifetime-free cursor state of [`Lexer`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LexerState {
    pub(super) pos: usize,
    pub(super) token_start: usize,
    state: State,
}

/// Lexer tokens, named after the tokens in Go's promparse.go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Token {
    Invalid,
    Eof,
    Linebreak,
    Whitespace,
    Help,
    Type,
    Text,
    Comment,
    MName,
    QString,
    BraceOpen,
    BraceClose,
    LName,
    LValue,
    Comma,
    Equal,
    Timestamp,
    Value,
}

const CLASS_BLANK: u8 = 1 << 0;
const CLASS_NAME_START: u8 = 1 << 1;
const CLASS_NAME_CHAR: u8 = 1 << 2;
const CLASS_LABEL_START: u8 = 1 << 3;
const CLASS_LABEL_CHAR: u8 = 1 << 4;
const CLASS_VALUE_CHAR: u8 = 1 << 5;

const CHAR_CLASS: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        let mut flags = 0u8;
        if b == b' ' || b == b'\t' {
            flags |= CLASS_BLANK;
        }
        let is_alpha = (b >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z');
        let is_digit = b >= b'0' && b <= b'9';
        if is_alpha || b == b'_' {
            flags |= CLASS_LABEL_START | CLASS_LABEL_CHAR | CLASS_NAME_START | CLASS_NAME_CHAR;
        } else if b == b':' {
            flags |= CLASS_NAME_START | CLASS_NAME_CHAR;
        } else if is_digit {
            flags |= CLASS_LABEL_CHAR | CLASS_NAME_CHAR;
        }
        if b != 0 && b != b'\n' && b != b' ' && b != b'\t' && b != b'{' {
            flags |= CLASS_VALUE_CHAR;
        }
        table[i] = flags;
        i += 1;
    }
    table
};

#[inline]
fn is_blank(byte: u8) -> bool {
    (CHAR_CLASS[byte as usize] & CLASS_BLANK) != 0
}

#[inline]
fn is_name_start(byte: u8) -> bool {
    (CHAR_CLASS[byte as usize] & CLASS_NAME_START) != 0
}

#[inline]
fn is_label_start(byte: u8) -> bool {
    (CHAR_CLASS[byte as usize] & CLASS_LABEL_START) != 0
}

#[inline]
fn is_name_char(byte: u8) -> bool {
    (CHAR_CLASS[byte as usize] & CLASS_NAME_CHAR) != 0
}

#[inline]
fn is_label_char(byte: u8) -> bool {
    (CHAR_CLASS[byte as usize] & CLASS_LABEL_CHAR) != 0
}

#[inline]
fn is_value_char(byte: u8) -> bool {
    (CHAR_CLASS[byte as usize] & CLASS_VALUE_CHAR) != 0
}

/// Hand-written port of the `promlex.l` rules. The input behaves as if a `\n`
/// were appended, like Go's `append(b, '\n')`, without copying it.
pub(super) struct Lexer<'a> {
    pub(super) input: &'a [u8],
    pub(super) pos: usize,
    pub(super) token_start: usize,
    state: State,
}

impl<'a> Lexer<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            token_start: 0,
            state: State::Init,
        }
    }

    #[inline]
    pub(super) fn into_state(self) -> LexerState {
        LexerState {
            pos: self.pos,
            token_start: self.token_start,
            state: self.state,
        }
    }

    #[inline]
    pub(super) fn from_state(input: &'a [u8], state: LexerState) -> Self {
        Self {
            input,
            pos: state.pos,
            token_start: state.token_start,
            state: state.state,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.input.len() + 1
    }

    #[inline]
    fn byte(&self, index: usize) -> u8 {
        match self.input.get(index) {
            Some(&byte) => byte,
            None if index == self.input.len() => b'\n',
            None => 0,
        }
    }

    #[inline]
    fn current(&self) -> u8 {
        self.byte(self.pos)
    }

    #[inline]
    pub(super) fn token_span(&self) -> ByteSpan {
        let end = self.input.len();
        ByteSpan::new(self.token_start.min(end), self.pos.min(end))
    }

    #[inline]
    pub(super) fn token(&self) -> &'a [u8] {
        &self.input[self.token_span()]
    }

    // Go's lexer skips NUL bytes inside label values, help text and comments,
    // and returns 0 (EOF) past the end of the input.
    #[inline]
    fn next(&mut self) -> u8 {
        self.pos += 1;
        if self.pos >= self.len() {
            return 0;
        }
        let mut byte = self.byte(self.pos);
        while byte == 0 && matches!(self.state, State::LValue | State::Meta2 | State::Comment) {
            self.pos += 1;
            byte = self.byte(self.pos);
        }
        byte
    }

    fn eat_while(&mut self, mut byte: u8, pred: impl Fn(u8) -> bool) -> u8 {
        while pred(byte) {
            byte = self.next();
        }
        byte
    }

    /// Slice-scans `self.input` directly for predicates that reject both `0` and `\n`,
    /// falling back to `eat_while` only when a NUL byte is encountered in a NUL-skipping state.
    #[inline]
    fn scan_while(&mut self, pred: impl Fn(u8) -> bool) -> u8 {
        let clamped = self.pos.min(self.input.len());
        let rest = &self.input[clamped..];
        let count = rest.iter().position(|&b| !pred(b)).unwrap_or(rest.len());
        self.pos += count;
        let byte = self.current();
        if byte == 0 && matches!(self.state, State::LValue | State::Meta2 | State::Comment) {
            let next = self.next();
            return self.eat_while(next, pred);
        }
        byte
    }

    #[inline]
    fn scan_after(&mut self, pred: impl Fn(u8) -> bool) -> u8 {
        let first = self.next();
        if !pred(first) {
            return first;
        }
        self.scan_while(pred)
    }

    /// Consumes `"(\\.|[^\\"])*"` starting at the opening quote.
    fn quoted(&mut self) -> bool {
        // Fast path: scan directly to the closing quote when there are no escapes or NUL bytes.
        let start = self.pos + 1;
        if let Some(rest) = self.input.get(start..) {
            match rest.iter().position(|&b| matches!(b, b'"' | b'\\' | 0)) {
                Some(offset) if rest[offset] == b'"' => {
                    self.pos = start + offset;
                    self.next();
                    return true;
                }
                Some(offset) => {
                    // Position right before the escape or NUL so `self.next()` handles it with
                    // exact state-dependent NUL-skipping semantics.
                    self.pos = start + offset - 1;
                }
                None => {
                    // Reached virtual `\n` and EOF without a closing quote.
                    self.pos = self.len();
                    return false;
                }
            }
        }
        loop {
            match self.next() {
                b'"' => {
                    self.next();
                    return true;
                }
                b'\\' => {
                    if matches!(self.next(), 0 | b'\n') {
                        return false;
                    }
                }
                0 => return false,
                _ => {}
            }
        }
    }

    fn consume_comment(&mut self) -> Token {
        if let Some(rest) = self.input.get(self.pos..) {
            match rest.iter().position(|&b| b == b'\n' || b == 0) {
                Some(offset) if rest[offset] == b'\n' => {
                    self.pos += offset;
                    self.state = State::Init;
                    return Token::Comment;
                }
                Some(offset) => {
                    if offset > 0 {
                        self.pos += offset - 1;
                    }
                }
                None => {
                    // Virtual trailing `\n` terminates the comment at `self.input.len()`.
                    self.pos = self.input.len();
                    self.state = State::Init;
                    return Token::Comment;
                }
            }
        }
        let mut byte = self.current();
        loop {
            match byte {
                0 => return Token::Eof,
                b'\n' => {
                    self.state = State::Init;
                    return Token::Comment;
                }
                _ => byte = self.next(),
            }
        }
    }

    #[inline]
    fn whitespace(&mut self) -> Token {
        self.scan_after(is_blank);
        Token::Whitespace
    }

    /// Consumes one byte, then moves to `state` and returns `token`.
    #[inline]
    fn emit(&mut self, state: State, token: Token) -> Token {
        self.next();
        self.state = state;
        token
    }

    /// Consumes a quoted string, then moves to `state` and returns `token`.
    #[inline]
    fn emit_quoted(&mut self, state: State, token: Token) -> Token {
        if !self.quoted() {
            return Token::Invalid;
        }
        self.state = state;
        token
    }

    pub(super) fn lex(&mut self) -> Token {
        if self.pos >= self.len() {
            return Token::Eof;
        }
        self.token_start = self.pos;
        let byte = self.current();
        if is_blank(byte) && self.state != State::Meta2 {
            return self.whitespace();
        }
        match self.state {
            State::Init => self.lex_init(byte),
            State::Comment => self.lex_comment(byte),
            State::Meta1 => self.lex_meta1(byte),
            State::Meta2 => self.lex_meta2(byte),
            State::Labels => self.lex_labels(byte),
            State::LValue => self.lex_lvalue(byte),
            State::Value => self.lex_value(byte),
            State::Timestamp => self.lex_timestamp(byte),
        }
    }

    fn lex_init(&mut self, byte: u8) -> Token {
        match byte {
            0 => Token::Eof,
            b'\n' => self.emit(State::Init, Token::Linebreak),
            b'#' => {
                if !is_blank(self.next()) {
                    return self.consume_comment();
                }
                let byte = self.scan_after(is_blank);
                self.state = State::Comment;
                self.lex_comment(byte)
            }
            b'{' => self.emit(State::Labels, Token::BraceOpen),
            _ if is_name_start(byte) => {
                self.scan_after(is_name_char);
                self.state = State::Value;
                Token::MName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_comment(&mut self, byte: u8) -> Token {
        let (rest, token) = match byte {
            b'H' => (b"ELP", Token::Help),
            b'T' => (b"YPE", Token::Type),
            _ => return self.consume_comment(),
        };
        if rest.iter().all(|&expected| self.next() == expected) && is_blank(self.next()) {
            self.whitespace();
            self.state = State::Meta1;
            return token;
        }
        self.consume_comment()
    }

    fn lex_meta1(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(State::Meta2, Token::MName),
            _ if is_name_start(byte) => {
                self.scan_after(is_name_char);
                self.state = State::Meta2;
                Token::MName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_meta2(&mut self, mut byte: u8) -> Token {
        // `[ \t]+` wins over `[^\n]*` on a tie, so trailing blanks are whitespace.
        if is_blank(byte) {
            byte = self.scan_after(is_blank);
            if byte == 0 || byte == b'\n' {
                return Token::Whitespace;
            }
        }
        self.scan_while(|next_byte| next_byte != 0 && next_byte != b'\n');
        self.state = State::Init;
        Token::Text
    }

    fn lex_labels(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(State::Labels, Token::QString),
            b',' => self.emit(State::Labels, Token::Comma),
            b'=' => self.emit(State::LValue, Token::Equal),
            b'}' => self.emit(State::Value, Token::BraceClose),
            _ if is_label_start(byte) => {
                self.scan_after(is_label_char);
                Token::LName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_lvalue(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(State::Labels, Token::LValue),
            _ => Token::Invalid,
        }
    }

    fn lex_value(&mut self, byte: u8) -> Token {
        match byte {
            b'{' => self.emit(State::Labels, Token::BraceOpen),
            0 | b'\n' => Token::Invalid,
            _ => {
                self.scan_after(is_value_char);
                self.state = State::Timestamp;
                Token::Value
            }
        }
    }

    fn lex_timestamp(&mut self, byte: u8) -> Token {
        match byte {
            b'\n' => self.emit(State::Init, Token::Linebreak),
            b'0'..=b'9' => {
                self.scan_after(|next_byte| next_byte.is_ascii_digit());
                Token::Timestamp
            }
            _ => Token::Invalid,
        }
    }
}
