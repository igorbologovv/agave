//! Build a slot-based synthetic sigverify fixture and save it to disk.

extern crate clap4 as clap;

#[path = "support/sigverify_fixture_common.rs"]
mod sigverify_fixture_common;

use {
    clap::Parser,
    sigverify_fixture_common::{
        FixtureBuildConfig, build_stored_workload, init_example_context, save_workload_to_file,
        validate_fixture_build_config,
    },
};

fn main() {
    let config = FixtureBuildConfig::parse();
    validate_fixture_build_config(&config).unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    });

    eprintln!("Preparing fixture data...");

    let ctx = init_example_context(4, config.num_validators, config.seed);

    let workload = build_stored_workload(&ctx, &config);

    save_workload_to_file(&workload, &config.output).unwrap_or_else(|err| {
        eprintln!("error: failed to save fixture: {err}");
        std::process::exit(1);
    });

    eprintln!(
        "Saved fixture to {} (slots={}, packets={}, votes={}, certs={})",
        config.output,
        workload.num_slots,
        workload.total_packets,
        workload.vote_packets,
        workload.cert_packets,
    );
}
