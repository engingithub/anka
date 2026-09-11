//! Recursive-descent parser for AnkaCC.

use super::lex::{Lexer, Token};
use super::{BinOp, CcError, Expr, Function, Param, Program, Stmt, Type, UnOp};

pub struct Parser<'a> {
    lex: Lexer<'a>,
    cur: Token,
}

impl<'a> Parser<'a> {
    pub fn new(source: &'a str) -> Result<Self, CcError> {
        let mut lex = Lexer::new(source);
        let cur = lex.next_token()?;
        Ok(Self { lex, cur })
    }

    fn line(&self) -> usize { self.lex.line }

    fn err(&self, msg: &str) -> CcError {
        CcError { line: self.line(), message: msg.into() }
    }

    fn advance(&mut self) -> Result<Token, CcError> {
        let old = std::mem::replace(&mut self.cur, Token::Eof);
        self.cur = self.lex.next_token()?;
        Ok(old)
    }

    fn expect(&mut self, tok: &Token) -> Result<(), CcError> {
        if &self.cur == tok {
            self.advance()?;
            Ok(())
        } else {
            Err(self.err(&format!("expected {:?}, got {:?}", tok, self.cur)))
        }
    }

    fn eat_ident(&mut self) -> Result<String, CcError> {
        match self.advance()? {
            Token::Ident(s) => Ok(s),
            other => Err(self.err(&format!("expected identifier, got {:?}", other))),
        }
    }

    // ───────────────────────────────────────────────────────────
    // Type parsing
    // ───────────────────────────────────────────────────────────

    fn parse_base_type(&mut self) -> Result<Type, CcError> {
        match &self.cur {
            Token::Int  => { self.advance()?; Ok(Type::Int) }
            Token::Char => { self.advance()?; Ok(Type::Char) }
            Token::Void => { self.advance()?; Ok(Type::Void) }
            _ => Err(self.err(&format!("expected type, got {:?}", self.cur))),
        }
    }

    fn parse_type(&mut self) -> Result<Type, CcError> {
        let mut ty = self.parse_base_type()?;
        while self.cur == Token::Star {
            self.advance()?;
            ty = Type::Ptr(Box::new(ty));
        }
        Ok(ty)
    }

    // ───────────────────────────────────────────────────────────
    // Program / functions
    // ───────────────────────────────────────────────────────────

    pub fn parse_program(&mut self) -> Result<Program, CcError> {
        let mut functions = Vec::new();
        while self.cur != Token::Eof {
            functions.push(self.parse_function()?);
        }
        Ok(Program { functions })
    }

    fn parse_function(&mut self) -> Result<Function, CcError> {
        let ret_type = self.parse_type()?;
        let name = self.eat_ident()?;
        self.expect(&Token::LParen)?;

        let mut params = Vec::new();
        if self.cur != Token::RParen {
            loop {
                let ty = self.parse_type()?;
                let pname = self.eat_ident()?;
                params.push(Param { ty, name: pname });
                if self.cur != Token::Comma { break; }
                self.advance()?;
            }
        }
        self.expect(&Token::RParen)?;

        let body = if self.cur == Token::Semi {
            self.advance()?;
            None
        } else {
            Some(self.parse_block_stmts()?)
        };

        Ok(Function { ret_type, name, params, body })
    }

    // ───────────────────────────────────────────────────────────
    // Statements
    // ───────────────────────────────────────────────────────────

    fn parse_block_stmts(&mut self) -> Result<Vec<Stmt>, CcError> {
        self.expect(&Token::LBrace)?;
        let mut stmts = Vec::new();
        while self.cur != Token::RBrace {
            stmts.push(self.parse_stmt()?);
        }
        self.expect(&Token::RBrace)?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, CcError> {
        match &self.cur {
            Token::Return => {
                self.advance()?;
                let expr = if self.cur == Token::Semi {
                    None
                } else {
                    Some(self.parse_expr()?)
                };
                self.expect(&Token::Semi)?;
                Ok(Stmt::Return(expr))
            }
            Token::If => {
                self.advance()?;
                self.expect(&Token::LParen)?;
                let cond = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                let then = Box::new(self.parse_stmt()?);
                let els = if self.cur == Token::Else {
                    self.advance()?;
                    Some(Box::new(self.parse_stmt()?))
                } else {
                    None
                };
                Ok(Stmt::If(cond, then, els))
            }
            Token::While => {
                self.advance()?;
                self.expect(&Token::LParen)?;
                let cond = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                let body = Box::new(self.parse_stmt()?);
                Ok(Stmt::While(cond, body))
            }
            Token::LBrace => {
                let stmts = self.parse_block_stmts()?;
                Ok(Stmt::Block(stmts))
            }
            Token::Int | Token::Char | Token::Void => {
                let ty = self.parse_type()?;
                let name = self.eat_ident()?;
                let init = if self.cur == Token::Assign {
                    self.advance()?;
                    Some(self.parse_expr()?)
                } else {
                    None
                };
                self.expect(&Token::Semi)?;
                Ok(Stmt::VarDecl(ty, name, init))
            }
            _ => {
                let expr = self.parse_expr()?;
                self.expect(&Token::Semi)?;
                Ok(Stmt::Expr(expr))
            }
        }
    }

    // ───────────────────────────────────────────────────────────
    // Expressions (precedence climbing)
    // ───────────────────────────────────────────────────────────

    fn parse_expr(&mut self) -> Result<Expr, CcError> {
        self.parse_assign()
    }

    fn parse_assign(&mut self) -> Result<Expr, CcError> {
        let lhs = self.parse_or()?;
        if self.cur == Token::Assign {
            self.advance()?;
            let rhs = self.parse_assign()?;
            if let Expr::Var(name) = lhs {
                return Ok(Expr::Assign(name, Box::new(rhs)));
            }
            return Err(self.err("left side of assignment must be a variable"));
        }
        Ok(lhs)
    }

    fn parse_or(&mut self) -> Result<Expr, CcError> {
        let mut lhs = self.parse_and()?;
        while self.cur == Token::OrOr {
            self.advance()?;
            let rhs = self.parse_and()?;
            lhs = Expr::Binary(BinOp::Or, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, CcError> {
        let mut lhs = self.parse_cmp()?;
        while self.cur == Token::AndAnd {
            self.advance()?;
            let rhs = self.parse_cmp()?;
            lhs = Expr::Binary(BinOp::And, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_cmp(&mut self) -> Result<Expr, CcError> {
        let mut lhs = self.parse_add()?;
        loop {
            let op = match &self.cur {
                Token::Eq => BinOp::Eq,
                Token::Ne => BinOp::Ne,
                Token::Lt => BinOp::Lt,
                Token::Gt => BinOp::Gt,
                Token::Le => BinOp::Le,
                Token::Ge => BinOp::Ge,
                _ => break,
            };
            self.advance()?;
            let rhs = self.parse_add()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> Result<Expr, CcError> {
        let mut lhs = self.parse_mul()?;
        loop {
            let op = match &self.cur {
                Token::Plus  => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance()?;
            let rhs = self.parse_mul()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<Expr, CcError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match &self.cur {
                Token::Star    => BinOp::Mul,
                Token::Slash   => BinOp::Div,
                Token::Percent => BinOp::Mod,
                _ => break,
            };
            self.advance()?;
            let rhs = self.parse_unary()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, CcError> {
        match &self.cur {
            Token::Minus => {
                self.advance()?;
                let e = self.parse_unary()?;
                Ok(Expr::Unary(UnOp::Neg, Box::new(e)))
            }
            Token::Bang => {
                self.advance()?;
                let e = self.parse_unary()?;
                Ok(Expr::Unary(UnOp::Not, Box::new(e)))
            }
            Token::Star => {
                self.advance()?;
                let e = self.parse_unary()?;
                Ok(Expr::Unary(UnOp::Deref, Box::new(e)))
            }
            Token::Amp => {
                self.advance()?;
                let e = self.parse_unary()?;
                Ok(Expr::Unary(UnOp::AddrOf, Box::new(e)))
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, CcError> {
        let mut expr = self.parse_primary()?;
        loop {
            match &self.cur {
                Token::LParen => {
                    // Function call
                    if let Expr::Var(name) = expr {
                        self.advance()?;
                        let mut args = Vec::new();
                        if self.cur != Token::RParen {
                            loop {
                                args.push(self.parse_expr()?);
                                if self.cur != Token::Comma { break; }
                                self.advance()?;
                            }
                        }
                        self.expect(&Token::RParen)?;
                        expr = Expr::Call(name, args);
                    } else {
                        return Err(self.err("function call on non-identifier"));
                    }
                }
                Token::PlusPlus => {
                    self.advance()?;
                    if let Expr::Var(name) = expr {
                        expr = Expr::PostInc(name);
                    } else {
                        return Err(self.err("++ on non-lvalue"));
                    }
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, CcError> {
        match self.advance()? {
            Token::IntLit(v) => Ok(Expr::IntLit(v)),
            Token::CharLit(v) => Ok(Expr::IntLit(v)),
            Token::StrLit(s) => Ok(Expr::StrLit(s)),
            Token::Ident(name) => Ok(Expr::Var(name)),
            Token::LParen => {
                let e = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(e)
            }
            other => Err(self.err(&format!("unexpected token in expression: {:?}", other))),
        }
    }
}
