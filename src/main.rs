mod checks;
mod cli;
mod context;
mod diff;
mod finding;
mod fix;
mod journal;
mod render;
mod state;
mod util;

fn main() {
    match cli::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("archdoctor: {error:#}");
            std::process::exit(3);
        }
    }
}
