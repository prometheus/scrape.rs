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

//! Lexer for the OpenMetrics 1.0 text format, a hand-written port of
//! [`openmetricslex.l`](https://github.com/prometheus/prometheus/blob/main/model/textparse/openmetricslex.l).

use super::ByteSpan;

/// Lexer states, named after the start conditions in `openmetricslex.l`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Init,
    Comment,
    /// After `# HELP`, `# TYPE` or `# UNIT`, before the metric name.
    Meta1,
    /// The rest of a `# HELP`, `# TYPE` or `# UNIT` line.
    Meta2,
    Labels,
    LValue,
    Value,
    Timestamp,
    Exemplar,
    EValue,
    ETimestamp,
}

/// Lifetime-free cursor state of [`Lexer`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LexerState {
    pub(super) pos: usize,
    pub(super) token_start: usize,
    state: State,
}

/// Lexer tokens, named after the tokens in Go's openmetricsparse.go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Token {
    Eof,
    Invalid,
    Linebreak,
    Help,
    Type,
    Unit,
    EofWord,
    Text,
    MName,
    BraceOpen,
    BraceClose,
    LName,
    QString,
    LValue,
    Comma,
    Equal,
    Value,
    Timestamp,
    Comment,
}

fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b':'
}

fn is_label_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_name_char(byte: u8) -> bool {
    is_name_start(byte) || byte.is_ascii_digit()
}

fn is_label_char(byte: u8) -> bool {
    is_label_start(byte) || byte.is_ascii_digit()
}

fn is_value_char(byte: u8) -> bool {
    !matches!(byte, 0 | b'\n' | b' ')
}

/// Hand-written port of the `openmetricslex.l` rules. Like golex, it never
/// backtracks: a failed pattern returns [`Token::Invalid`] with `pos` on the
/// byte that broke it.
#[derive(Clone, Debug)]
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
    pub(super) fn token_span(&self) -> ByteSpan {
        ByteSpan::new(self.token_start, self.pos)
    }

    pub(super) fn token(&self) -> &'a [u8] {
        &self.input[self.token_span()]
    }

    // Go's lexer skips NUL bytes inside label values, help text and comments,
    // and returns 0 (EOF) past the end of the input.
    fn next(&mut self) -> u8 {
        self.pos += 1;
        while let Some(&byte) = self.input.get(self.pos) {
            if byte != 0 || !matches!(self.state, State::LValue | State::Meta2 | State::Comment) {
                return byte;
            }
            self.pos += 1;
        }
        0
    }

    fn eat_while(&mut self, mut byte: u8, pred: impl Fn(u8) -> bool) -> u8 {
        while pred(byte) {
            byte = self.next();
        }
        byte
    }

    fn eat_after(&mut self, pred: impl Fn(u8) -> bool) -> u8 {
        let next = self.next();
        self.eat_while(next, pred)
    }

    /// Consumes `"(\\.|[^\\"])*"` starting at the opening quote, or
    /// `"(\\.|[^\\"\n])*"` when `newline` is false.
    fn quoted(&mut self, newline: bool) -> bool {
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
                b'\n' if !newline => return false,
                _ => {}
            }
        }
    }

    /// Consumes one byte, then moves to `state` and returns `token`.
    fn emit(&mut self, state: State, token: Token) -> Token {
        self.next();
        self.state = state;
        token
    }

    /// Consumes a quoted string, then moves to `state` and returns `token`.
    fn emit_quoted(&mut self, newline: bool, state: State, token: Token) -> Token {
        if !self.quoted(newline) {
            return Token::Invalid;
        }
        self.state = state;
        token
    }

    /// Consumes `{S}[^ \n]+` starting at the space, then moves to `state`.
    fn emit_value(&mut self, state: State, token: Token) -> Token {
        if !is_value_char(self.next()) {
            return Token::Invalid;
        }
        self.eat_after(is_value_char);
        self.state = state;
        token
    }

    pub(super) fn lex(&mut self) -> Token {
        self.token_start = self.pos.min(self.input.len());
        if self.pos >= self.input.len() {
            return Token::Eof;
        }
        let byte = self.input[self.pos];
        match self.state {
            State::Init => self.lex_init(byte),
            State::Comment => self.lex_comment(byte),
            State::Meta1 => self.lex_meta1(byte),
            State::Meta2 => self.lex_meta2(byte),
            State::Labels => self.lex_labels(byte),
            State::LValue => self.lex_lvalue(byte),
            State::Value => self.lex_value(byte),
            State::Timestamp => self.lex_timestamp(byte),
            State::Exemplar => self.lex_exemplar(byte),
            State::EValue => self.lex_evalue(byte),
            State::ETimestamp => self.lex_etimestamp(byte),
        }
    }

    fn lex_init(&mut self, byte: u8) -> Token {
        match byte {
            b'#' => {
                if self.next() != b' ' {
                    return Token::Invalid;
                }
                // `#{S}` returns no token, so the next rule's token keeps the `# ` prefix.
                let byte = self.next();
                self.state = State::Comment;
                self.lex_comment(byte)
            }
            b'{' => self.emit(State::Labels, Token::BraceOpen),
            _ if is_name_start(byte) => {
                self.eat_after(is_name_char);
                self.state = State::Value;
                Token::MName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_comment(&mut self, byte: u8) -> Token {
        let (rest, token): (&[u8], Token) = match byte {
            b'E' => (b"OF", Token::EofWord),
            b'H' => (b"ELP ", Token::Help),
            b'T' => (b"YPE ", Token::Type),
            b'U' => (b"NIT ", Token::Unit),
            _ => return Token::Invalid,
        };
        if !rest.iter().all(|&expected| self.next() == expected) {
            return Token::Invalid;
        }
        if token != Token::EofWord {
            return self.emit(State::Meta1, token);
        }
        if self.next() == b'\n' {
            self.next();
        }
        self.state = State::Init;
        token
    }

    fn lex_meta1(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(true, State::Meta2, Token::MName),
            _ if is_name_start(byte) => {
                self.eat_after(is_name_char);
                self.state = State::Meta2;
                Token::MName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_meta2(&mut self, byte: u8) -> Token {
        if byte != b' ' {
            return Token::Invalid;
        }
        match self.eat_after(|next_byte| !matches!(next_byte, 0 | b'\n')) {
            b'\n' => self.emit(State::Init, Token::Text),
            _ => Token::Invalid,
        }
    }

    fn lex_labels(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(true, State::Labels, Token::QString),
            b',' => self.emit(State::Labels, Token::Comma),
            b'=' => self.emit(State::LValue, Token::Equal),
            b'}' => self.emit(State::Value, Token::BraceClose),
            _ if is_label_start(byte) => {
                self.eat_after(is_label_char);
                Token::LName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_lvalue(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(false, State::Labels, Token::LValue),
            _ => Token::Invalid,
        }
    }

    fn lex_value(&mut self, byte: u8) -> Token {
        match byte {
            b' ' => self.emit_value(State::Timestamp, Token::Value),
            b'{' => self.emit(State::Labels, Token::BraceOpen),
            _ => Token::Invalid,
        }
    }

    fn lex_timestamp(&mut self, byte: u8) -> Token {
        match byte {
            b'\n' => self.emit(State::Init, Token::Linebreak),
            b' ' => match self.next() {
                b'#' => match self.next() {
                    b' ' => match self.next() {
                        b'{' => self.emit(State::Exemplar, Token::Comment),
                        _ => Token::Invalid,
                    },
                    byte => {
                        self.eat_while(byte, is_value_char);
                        Token::Timestamp
                    }
                },
                byte if is_value_char(byte) => {
                    self.eat_after(is_value_char);
                    Token::Timestamp
                }
                _ => Token::Invalid,
            },
            _ => Token::Invalid,
        }
    }

    fn lex_exemplar(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(false, State::Exemplar, Token::QString),
            b',' => self.emit(State::Exemplar, Token::Comma),
            b'=' => self.emit(State::EValue, Token::Equal),
            b'}' => self.emit(State::EValue, Token::BraceClose),
            _ if is_label_start(byte) => {
                self.eat_after(is_label_char);
                Token::LName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_evalue(&mut self, byte: u8) -> Token {
        match byte {
            b' ' => self.emit_value(State::ETimestamp, Token::Value),
            b'"' => self.emit_quoted(false, State::Exemplar, Token::LValue),
            _ => Token::Invalid,
        }
    }

    fn lex_etimestamp(&mut self, byte: u8) -> Token {
        match byte {
            b'\n' => self.emit(State::Init, Token::Linebreak),
            b' ' => self.emit_value(State::ETimestamp, Token::Timestamp),
            _ => Token::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Lexer, Token};

    fn lex_all(input: &[u8]) -> Vec<(Token, &[u8])> {
        let mut lexer = Lexer::new(input);
        let mut tokens = Vec::new();
        loop {
            let token = lexer.lex();
            if matches!(token, Token::Eof | Token::Invalid) {
                tokens.push((token, &input[lexer.pos.min(input.len())..]));
                return tokens;
            }
            tokens.push((token, lexer.token()));
        }
    }

    #[test]
    fn metadata() {
        let input = b"# HELP \"a.b\" some help\n# TYPE a counter\n# UNIT a seconds\n";
        assert_eq!(
            lex_all(input),
            [
                (Token::Help, &b"# HELP "[..]),
                (Token::MName, b"\"a.b\""),
                (Token::Text, b" some help\n"),
                (Token::Type, b"# TYPE "),
                (Token::MName, b"a"),
                (Token::Text, b" counter\n"),
                (Token::Unit, b"# UNIT "),
                (Token::MName, b"a"),
                (Token::Text, b" seconds\n"),
                (Token::Eof, b""),
            ]
        );
    }

    #[test]
    fn series_with_exemplar() {
        let input = b"a_total{x=\"1\",y=\"2\"} 3 4 # {id=\"z\"} 5 6\n";
        assert_eq!(
            lex_all(input),
            [
                (Token::MName, &b"a_total"[..]),
                (Token::BraceOpen, b"{"),
                (Token::LName, b"x"),
                (Token::Equal, b"="),
                (Token::LValue, b"\"1\""),
                (Token::Comma, b","),
                (Token::LName, b"y"),
                (Token::Equal, b"="),
                (Token::LValue, b"\"2\""),
                (Token::BraceClose, b"}"),
                (Token::Value, b" 3"),
                (Token::Timestamp, b" 4"),
                (Token::Comment, b" # {"),
                (Token::LName, b"id"),
                (Token::Equal, b"="),
                (Token::LValue, b"\"z\""),
                (Token::BraceClose, b"}"),
                (Token::Value, b" 5"),
                (Token::Timestamp, b" 6"),
                (Token::Linebreak, b"\n"),
                (Token::Eof, b""),
            ]
        );
    }

    #[test]
    fn eof_word() {
        assert_eq!(
            lex_all(b"# EOF\n"),
            [(Token::EofWord, &b"# EOF\n"[..]), (Token::Eof, b"")]
        );
        assert_eq!(
            lex_all(b"# EOF"),
            [(Token::EofWord, &b"# EOF"[..]), (Token::Eof, b"")]
        );
        assert_eq!(
            lex_all(b"# EOFx"),
            [
                (Token::EofWord, &b"# EOF"[..]),
                (Token::MName, b"x"),
                (Token::Eof, b"")
            ]
        );
        assert_eq!(
            lex_all(b"# EOF\n\n"),
            [(Token::EofWord, &b"# EOF\n"[..]), (Token::Invalid, b"\n")]
        );
    }

    #[test]
    fn nul_in_label_value_is_skipped() {
        let input = b"a{b=\"\0c\0\"\0} 1\n";
        let tokens = lex_all(input);
        assert_eq!(tokens[4], (Token::LValue, &b"\"\0c\0\"\0"[..]));
        assert_eq!(tokens[5], (Token::BraceClose, &b"}"[..]));
    }

    #[test]
    fn unterminated_label_value() {
        assert_eq!(
            lex_all(b"a{b=\"c\n"),
            [
                (Token::MName, &b"a"[..]),
                (Token::BraceOpen, b"{"),
                (Token::LName, b"b"),
                (Token::Equal, b"="),
                (Token::Invalid, b"\n"),
            ]
        );
    }
}
