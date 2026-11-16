//! The Processes table, in both programs: top by CPU or memory, the box that asks before a
//! kill, and what Claude is told about one.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Cell, Row};

use super::theme::Theme;
use super::widgets::{TableSpec, table, trunc};
use crate::collectors::procs::{Proc, SortBy};
use crate::fmt;

pub fn hints() -> Vec<(&'static str, &'static str)> {
    vec![
        ("j/k", "select"),
        ("C/M", "sort cpu/mem"),
        ("x", "kill"),
        ("/", "filter"),
    ]
}

/// The table: `rows` already filtered and sorted by `sort` (its column gets the `▼`). A
/// process with no CPU figure yet (NaN: one sample so far) shows `–`.
pub fn draw(f: &mut Frame, area: Rect, t: &Theme, rows: &[Proc], sel: Option<usize>, sort: SortBy) {
    let mark = |s: SortBy| if sort == s { " ▼" } else { "" };
    let cpu_h = format!("CPU%{}", mark(SortBy::Cpu));
    let mem_h = format!("MEM%{}", mark(SortBy::Mem));
    let body: Vec<Row> = rows
        .iter()
        .map(|p| {
            let cpu_c = if p.cpu > 15.0 {
                t.red
            } else if p.cpu > 5.0 {
                t.yellow
            } else {
                t.fg
            };
            let cpu = if p.cpu.is_nan() {
                "–".to_string()
            } else {
                format!("{:.1}", p.cpu)
            };
            Row::new(vec![
                Cell::from(p.pid.to_string()).style(t.dim()),
                Cell::from(p.user.clone()),
                Cell::from(cpu).style(t.s(cpu_c)),
                Cell::from(format!("{:.1}", p.mem_pct)),
                Cell::from(fmt::hms(p.run_time_s)).style(t.dim()),
                Cell::from(p.cmd.clone()),
            ])
        })
        .collect();
    table(
        f,
        area,
        t,
        TableSpec {
            header: vec!["PID", "USER", &cpu_h, &mem_h, "TIME", "COMMAND"],
            widths: vec![
                Constraint::Length(9),
                Constraint::Length(16),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(11),
                Constraint::Fill(1),
            ],
            rows: body,
            selected: sel.filter(|_| !rows.is_empty()),
        },
    );
}

/// What the "Kill process" box says about it.
pub fn kill_lines(t: &Theme, p: &Proc) -> Vec<Line<'static>> {
    vec![
        Line::styled(
            format!("Send SIGTERM to {} {}?", p.pid, trunc(&p.cmd, 60)),
            t.fg(),
        ),
        Line::styled(
            format!(
                "owner {} · cpu {:.1}% · mem {:.1}%",
                p.user, p.cpu, p.mem_pct
            ),
            t.dim(),
        ),
    ]
}

/// What Claude is asked about a process: (the conversation's title, the context). `place` is
/// where it runs ("my Silverblue machine", "the server").
pub fn ask_text(place: &str, p: &Proc) -> (String, String) {
    (
        format!(
            "process {} ({})",
            p.pid,
            p.cmd.split_whitespace().next().unwrap_or("?")
        ),
        format!(
            "Process on {place} (from the Processes screen):\npid {}\nuser {}\ncommand {}\ncpu {:.1}% of one core, memory {:.1}%\nrunning for {}",
            p.pid,
            p.user,
            p.cmd,
            p.cpu,
            p.mem_pct,
            fmt::uptime(p.run_time_s)
        ),
    )
}

/// What Claude is asked about one.
pub const QUESTION: &str = "What is this process, and is this usage normal?";

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn p(pid: u32, cpu: f32) -> Proc {
        Proc {
            pid,
            user: "app".into(),
            uid: Some(999),
            cpu,
            mem_pct: 2.5,
            run_time_s: 3725,
            cmd: "/opt/app/bin/app --config /etc/app/app.toml".into(),
        }
    }

    #[test]
    fn a_process_with_no_cpu_yet_shows_a_dash() {
        let t = Theme::truecolor();
        let rows = [p(901, 75.0), p(1440, f32::NAN)];
        let mut term = Terminal::new(TestBackend::new(100, 6)).unwrap();
        term.draw(|f| draw(f, f.area(), &t, &rows, Some(0), SortBy::Cpu))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let text: Vec<String> = (0..6)
            .map(|y| (0..100).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect();
        assert!(text[0].contains("CPU% ▼") && !text[0].contains("MEM% ▼"));
        assert!(text.iter().any(|l| l.contains("901") && l.contains("75.0")));
        let nan = text.iter().find(|l| l.contains("1440")).unwrap();
        assert!(nan.contains("–") && !nan.contains("NaN"), "{nan}");
        // The box and the question name it.
        assert!(
            kill_lines(&t, &rows[0])[0]
                .to_string()
                .starts_with("Send SIGTERM to 901 /opt")
        );
        let (title, ctx) = ask_text("the server", &rows[0]);
        assert_eq!(title, "process 901 (/opt/app/bin/app)");
        assert!(ctx.starts_with("Process on the server (from the Processes screen):\npid 901\n"));
        assert!(ctx.contains("cpu 75.0% of one core, memory 2.5%\nrunning for "));
    }
}
