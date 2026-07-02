//! Build a slot-based synthetic sigverify fixture and save it to disk.

extern crate clap4 as clap;

#[path = "support/sigverify_fixture_common.rs"]
mod sigverify_fixture_common;

use {
    clap::Parser,
    sigverify_fixture_common::{
        FixtureBuildConfig, build_stored_workload, fixture_max_slot, init_example_context,
        save_workload_to_file, validate_fixture_build_config,
    },
};

fn main() {
    let config = FixtureBuildConfig::parse();

    validate_fixture_build_config(&config).unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    });

    eprintln!("Preparing fixture data...");

    let max_slot = fixture_max_slot(config.base_slot, config.num_slots);
    let ctx = init_example_context(
        4,
        config.num_validators,
        config.seed,
        config.base_slot,
        max_slot,
    );

    eprintln!("Building stored workload...");

    let workload = build_stored_workload(&ctx, &config);

    eprintln!(
        "Writing fixture: output={}, slots={}, votes_per_slot={}, certs_per_slot={}, \
         total_packets={}",
        config.output,
        workload.num_slots,
        workload.votes_per_slot,
        workload.certs_per_slot,
        workload.total_packets,
    );

    save_workload_to_file(&workload, &config.output).unwrap_or_else(|err| {
        eprintln!("failed to save workload: {err}");
        std::process::exit(1);
    });

    eprintln!("Done.");
}
