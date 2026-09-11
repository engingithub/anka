//! C lexer for AnkaCC.

use super::CcError;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    Int, Char, Void, If, Else, While, For, Return,
    // Identifiers and literals
    Ident(String),
    IntLit(i32),
    StrLit(String),
    CharLit(i32),
    // Operators
    Plus, Minus, Star, Slash, Percent,
    Amp, Bang,
    Assign,
    Eq, Ne, Lt, Gt, Le, Ge,
    AndAnd, OrOr,
    PlusPlus, MinusMinus,
    // Punctuation
    LParen, RParen, LBrace, RBrace,
    Semi, Comma,
    // End
    Eof,
}

pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    pub line: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self { src: src.as_bytes(), pos: 0, line: 1 }
    }

    fn peek(&self) -> u8 {
        if self.pos < self.src.len() { self.src[self.pos] } else { 0 }
    }

    fn advance(&mut self) -> u8 {
        let c = self.peek();
        if c == b'\n' { self.line += 1; }
        self.pos += 1;
        c
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            // Whitespace
            while self.pos < self.src.len() && self.peek().is_ascii_whitespace() {
                self.advance();
            }
            // Line comment
            if self.pos + 1 < self.src.len()
                && self.src[self.pos] == b'/' && self.src[self.pos + 1] == b'/'
            {
                while self.pos < self.src.len() && self.peek() != b'\n' {
                    self.advance();
                }
                continue;
            }
            // Block comment
            if self.pos + 1 < self.src.len()
                && self.src[self.pos] == b'/' && self.src[self.pos + 1] == b'*'
            {
                self.advance(); self.advance();
                while self.pos + 1 < self.src.len() {
                    if self.src[self.pos] == b'*' && self.src[self.pos + 1] == b'/' {
                        self.advance(); self.advance();
                        break;
                    }
                    self.advance();
                }
                continue;
            }
            break;
        }
    }

    pub fn next_token(&mut self) -> Result<Token, CcError> {
        self.skip_ws_and_comments();

        if self.pos >= self.src.len() {
            return Ok(Token::Eof);
        }

        let c = self.peek();

        // String literal
        if c == b'"' {
            return self.lex_string();
        }

        // Char literal
        if c == b'\'' {
            return self.lex_char();
        }

        // Number
        if c.is_ascii_digit() {
            return self.lex_number();
        }

        // Identifier / keyword
        if c.is_ascii_alphabetic() || c == b'_' {
            return Ok(self.lex_ident());
        }

        // Operators and punctuation
        self.advance();
        match c {
            b'+' => {
                if self.peek() == b'+' { self.advance(); Ok(Token::PlusPlus) }
                else { Ok(Token::Plus) }
            }
            b'-' => {
                if self.peek() == b'-' { self.advance(); Ok(Token::MinusMinus) }
                else { Ok(Token::Minus) }
            }
            b'*' => Ok(Token::Star),
            b'/' => Ok(Token::Slash),
            b'%' => Ok(Token::Percent),
            b'&' => {
                if self.peek() == b'&' { self.advance(); Ok(Token::AndAnd) }
                else { Ok(Token::Amp) }
            }
            b'|' => {
                if self.peek() == b'|' { self.advance(); Ok(Token::OrOr) }
                else { Err(self.err("unexpected '|' (use '||')")) }
            }
            b'!' => {
                if self.peek() == b'=' { self.advance(); Ok(Token::Ne) }
                else { Ok(Token::Bang) }
            }
            b'=' => {
                if self.peek() == b'=' { self.advance(); Ok(Token::Eq) }
                else { Ok(Token::Assign) }
            }
            b'<' => {
                if self.peek() == b'=' { self.advance(); Ok(Token::Le) }
                else { Ok(Token::Lt) }
            }
            b'>' => {
                if self.peek() == b'=' { self.advance(); Ok(Token::Ge) }
                else { Ok(Token::Gt) }
            }
            b'(' => Ok(Token::LParen),
            b')' => Ok(Token::RParen),
            b'{' => Ok(Token::LBrace),
            b'}' => Ok(Token::RBrace),
            b';' => Ok(Token::Semi),
            b',' => Ok(Token::Comma),
            _ => Err(self.err(&format!("unexpected character: '{}'", c as char))),
        }
    }

    fn lex_string(&mut self) -> Result<Token, CcError> {
        self.advance(); // skip opening "
        let mut s = Vec::new();
        loop {
            let c = self.peek();
            if c == 0 { return Err(self.err("unterminated string")); }
            self.advance();
            if c == b'"' { break; }
            if c == b'\\' {
                let esc = self.advance();
                match esc {
                    b'n' => s.push(b'\n'),
                    b'r' => s.push(b'\r'),
                    b't' => s.push(b'\t'),
                    b'0' => s.push(0),
                    b'\\' => s.push(b'\\'),
                    b'"' => s.push(b'"'),
                    _ => return Err(self.err(&format!("unknown escape: \\{}", esc as char))),
                }
            } else {
                s.push(c);
            }
        }
        Ok(Token::StrLit(String::from_utf8(s).unwrap_or_default()))
    }

    fn lex_char(&mut self) -> Result<Token, CcError> {
        self.advance(); // skip '
        let val = if self.peek() == b'\\' {
            self.advance();
            match self.advance() {
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'0' => 0,
                b'\\' => b'\\',
                b'\'' => b'\'',
                c => return Err(self.err(&format!("unknown char escape: \\{}", c as char))),
            }
        } else {
            self.advance()
        };
        if self.advance() != b'\'' {
            return Err(self.err("expected closing '"));
        }
        Ok(Token::CharLit(val as i32))
    }

    fn lex_number(&mut self) -> Result<Token, CcError> {
        let start = self.pos;
        if self.peek() == b'0' && self.pos + 1 < self.src.len()
            && (self.src[self.pos + 1] == b'x' || self.src[self.pos + 1] == b'X')
        {
            self.advance(); self.advance();
            while self.peek().is_ascii_hexdigit() { self.advance(); }
            let hex = std::str::from_utf8(&self.src[start+2..self.pos]).unwrap();
            let val = i64::from_str_radix(hex, 16)
                .map_err(|_| self.err("bad hex literal"))?;
            return Ok(Token::IntLit(val as i32));
        }
        while self.peek().is_ascii_digit() { self.advance(); }
        let num = std::str::from_utf8(&self.src[start..self.pos]).unwrap();
        let val: i64 = num.parse().map_err(|_| self.err("bad integer literal"))?;
        Ok(Token::IntLit(val as i32))
    }

    fn lex_ident(&mut self) -> Token {
        let start = self.pos;
        while self.peek().is_ascii_alphanumeric() || self.peek() == b'_' {
            self.advance();
        }
        let word = std::str::from_utf8(&self.src[start..self.pos]).unwrap();
        match word {
            "int"    => Token::Int,
            "char"   => Token::Char,
            "void"   => Token::Void,
            "if"     => Token::If,
            "else"   => Token::Else,
            "while"  => Token::While,
            "for"    => Token::For,
            "return" => Token::Return,
            _        => Token::Ident(word.to_string()),
        }
    }

    fn err(&self, msg: &str) -> CcError {
        CcError { line: self.line, message: msg.into() }
    }
}
