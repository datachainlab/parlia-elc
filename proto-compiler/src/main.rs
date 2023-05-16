use argh::FromArgs;
mod cmd;
use cmd::compile::CompileCmd;

#[derive(Debug, FromArgs)]
/// App
struct App {
    #[argh(subcommand)]
    cmd: Command,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand)]
enum Command {
    Compile(CompileCmd),
}

fn main() {
    let app: App = argh::from_env();

    match app.cmd {
        Command::Compile(compile) => compile.run(),
    }
}
