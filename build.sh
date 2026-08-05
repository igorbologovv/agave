cargo run --release --example sigverify_fixture_build -- \
	--output ./sigverify_fixture.bin \
	--num-slots 100 \
	--votes-per-slot 2000 \
	--certs-per-slot 500 \
	--num-validators 2000 \
	--seed 42
