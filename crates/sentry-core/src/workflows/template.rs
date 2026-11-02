//! Hand-rolled `{{ expr }}` templating (spec §9.2). An expression is terms joined by `+`/`-`;
//! a term is an identifier, an integer or a double-quoted string. `+`/`-` need integers
//! (`{{ current_version + 1 }}`); `{{ "{{" }}` emits a literal `{{`.

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Int(i64),
    Str(String),
}

impl Val {
    fn text(self) -> String {
        match self {
            Val::Int(i) => i.to_string(),
            Val::Str(s) => s,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Int(i64),
    Str(String),
    Op(char),
}

/// Split a template into literal text and expression sources.
fn segments(s: &str) -> Result<Vec<(bool, String)>, String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        out.push((false, rest[..i].to_string()));
        let body = &rest[i + 2..];
        // Find the closing `}}` outside string literals.
        let mut in_str = false;
        let mut end = None;
        let b = body.as_bytes();
        let mut j = 0;
        while j < b.len() {
            match b[j] {
                b'"' => in_str = !in_str,
                b'}' if !in_str && b.get(j + 1) == Some(&b'}') => {
                    end = Some(j);
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        let end = end.ok_or_else(|| format!("unclosed `{{{{` in {s:?}"))?;
        out.push((true, body[..end].to_string()));
        rest = &body[end + 2..];
    }
    out.push((false, rest.to_string()));
    Ok(out)
}

fn lex(expr: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut it = expr.chars().peekable();
    while let Some(&c) = it.peek() {
        match c {
            c if c.is_whitespace() => {
                it.next();
            }
            '+' | '-' => {
                toks.push(Tok::Op(c));
                it.next();
            }
            '"' => {
                it.next();
                let mut s = String::new();
                loop {
                    match it.next() {
                        Some('"') => break,
                        Some(c) => s.push(c),
                        None => return Err(format!("unterminated string in {{{{ {expr} }}}}")),
                    }
                }
                toks.push(Tok::Str(s));
            }
            c if c.is_ascii_digit() => {
                let mut n = String::new();
                while let Some(&d) = it.peek().filter(|d| d.is_ascii_digit()) {
                    n.push(d);
                    it.next();
                }
                toks.push(Tok::Int(n.parse().map_err(|e| format!("{e}"))?));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut id = String::new();
                while let Some(&d) = it
                    .peek()
                    .filter(|d| d.is_ascii_alphanumeric() || **d == '_')
                {
                    id.push(d);
                    it.next();
                }
                toks.push(Tok::Ident(id));
            }
            c => return Err(format!("unexpected {c:?} in {{{{ {expr} }}}}")),
        }
    }
    Ok(toks)
}

/// Identifiers referenced anywhere in `s` (for lint and lazy built-ins).
pub fn idents(s: &str) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    for (is_expr, src) in segments(s)? {
        if is_expr {
            for t in lex(&src)? {
                if let Tok::Ident(i) = t
                    && !v.contains(&i)
                {
                    v.push(i);
                }
            }
        }
    }
    Ok(v)
}

fn eval(expr: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Val, String> {
    let toks = lex(expr)?;
    let term = |t: &Tok| -> Result<Val, String> {
        Ok(match t {
            Tok::Int(i) => Val::Int(*i),
            Tok::Str(s) => Val::Str(s.clone()),
            Tok::Ident(id) => {
                let v = lookup(id).ok_or_else(|| format!("undefined variable `{id}`"))?;
                match v.trim().parse::<i64>() {
                    Ok(i) => Val::Int(i),
                    Err(_) => Val::Str(v),
                }
            }
            Tok::Op(o) => return Err(format!("unexpected `{o}` in {{{{ {expr} }}}}")),
        })
    };
    let mut it = toks.iter();
    let mut acc = term(it.next().ok_or("empty {{ }}")?)?;
    while let Some(op) = it.next() {
        let Tok::Op(op) = op else {
            return Err(format!("expected + or - in {{{{ {expr} }}}}"));
        };
        let rhs = term(it.next().ok_or_else(|| format!("dangling `{op}`"))?)?;
        acc = match (acc, rhs) {
            (Val::Int(a), Val::Int(b)) => Val::Int(if *op == '+' { a + b } else { a - b }),
            _ => return Err(format!("`{op}` needs integers in {{{{ {expr} }}}}")),
        };
    }
    Ok(acc)
}

pub fn render(s: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let mut out = String::new();
    for (is_expr, src) in segments(s)? {
        if is_expr {
            out.push_str(&eval(&src, lookup)?.text());
        } else {
            out.push_str(&src);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(k: &str) -> Option<String> {
        match k {
            "current_version" => Some("44".into()),
            "target" => Some("45".into()),
            "old_kmod" => Some("kmod-nvidia-7.2.8".into()),
            _ => None,
        }
    }

    #[test]
    fn renders() {
        assert_eq!(render("{{ current_version + 1 }}", &vars).unwrap(), "45");
        assert_eq!(
            render("f{{target}}-{{ target - 2 }}", &vars).unwrap(),
            "f45-43"
        );
        assert_eq!(
            render("--uninstall {{ old_kmod }}", &vars).unwrap(),
            "--uninstall kmod-nvidia-7.2.8"
        );
        assert_eq!(
            render(r#"--format '{{ "{{" }}.Names{{ "}}" }}'"#, &vars).unwrap(),
            "--format '{{.Names}}'"
        );
        assert_eq!(render("no templates", &vars).unwrap(), "no templates");
    }

    #[test]
    fn errors() {
        assert!(
            render("{{ nope }}", &vars)
                .unwrap_err()
                .contains("undefined variable `nope`")
        );
        assert!(render("{{ old_kmod + 1 }}", &vars).is_err());
        assert!(render("{{ target", &vars).is_err());
        assert!(render("{{ }}", &vars).is_err());
        assert!(render("{{ target + }}", &vars).is_err());
    }

    #[test]
    fn idents_found() {
        assert_eq!(
            idents(r#"{{ target }} {{ "{{" }} {{ current_version + 1 }} {{ target }}"#).unwrap(),
            vec!["target", "current_version"]
        );
    }
}
