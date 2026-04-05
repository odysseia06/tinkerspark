mod app;
mod diff_pane;
mod hex_pane;
mod panes;
mod state;

use eframe::NativeOptions;
use tracing_subscriber::EnvFilter;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("starting Tinkerspark");

    // Restore window size from last session.
    let session = tinkerspark_infra_session::load_session();
    let size = [session.window.width, session.window.height];

    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Tinkerspark")
            .with_inner_size(size),
        ..Default::default()
    };

    eframe::run_native(
        "Tinkerspark",
        options,
        Box::new(|cc| Ok(Box::new(app::TinkersparkApp::new(cc)))),
    )
}
