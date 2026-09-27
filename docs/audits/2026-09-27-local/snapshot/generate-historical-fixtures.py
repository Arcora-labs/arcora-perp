#!/usr/bin/env python3
"""Rebuild frozen fixtures with actual historical writers (explicit manual tool)."""
from pathlib import Path
import io, json, os, subprocess, sys, tarfile, tempfile
ROOT = Path(__file__).resolve().parents[4]
GEN = Path(__file__).with_name('historical_fixture_generator.rs').read_text()
CREDIT_HELPER = Path(__file__).with_name('historical_credit_helper.rs').read_text()
SOURCES = {
    'v5': 'f9244ca1eee3bb19e91c46648756fe844e12e2a4',
    'v6': '35c519ea2415436ea6c89e200937465f814c939a',
    'v7': 'bddf815f6b20388c9f9710e4fe98fdba736a751c',
    'v8': '098e4952c189f92e4293ed7d49f81222b626e406',
}
for version, sha in SOURCES.items():
    if len(sys.argv) > 1 and version not in sys.argv[1:]:
        continue
    checkout = Path(tempfile.mkdtemp(prefix=f'arcora-fixture-{version}-')).resolve()
    data = subprocess.check_output(['git', 'archive', sha], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        # Only local git-archive entries; reject any path/symlink escape.
        for member in tar.getmembers():
            destination = (checkout / member.name).resolve()
            if checkout not in destination.parents and destination != checkout:
                raise ValueError('unsafe archive path')
            if member.issym() or member.islnk():
                target = (destination.parent / member.linkname).resolve()
                if checkout not in target.parents:
                    raise ValueError('unsafe archive link')
        tar.extractall(checkout)
    # git archive preserves historic mtimes; force workspace sources newer than
    # reused Cargo artifacts so a different SHA cannot borrow stale crate code.
    for source in checkout.rglob('*'):
        if source.is_file(): os.utime(source, None)
    setup = '' 
    if version != 'v5':
        deposit_source = checkout / 'crates/gateway/src/deposit_ingestion.rs'
        deposit_source.write_text(deposit_source.read_text() + CREDIT_HELPER)
        setup += '''
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x44;20]);
        gw.authorize_routed_deposit(&key, [0x44;20], 7_000_000, 1,
            deposit_ingestion::Purpose::Collateral).unwrap();
        deposit_ingestion::frozen_fixture_credit(&mut gw, &key);
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("deposits.bin"), postcard::to_allocvec(&gw.deposits).unwrap()).unwrap();
'''
    if version == 'v8':
        setup += '        gw.accounts.get_mut(&withdraw_key).unwrap().recovery_nonce = 7;\n'
    main = checkout / 'crates/gateway/src/main.rs'
    main.write_text(main.read_text() + GEN.replace('// SOURCE_VERSION_SETUP', setup))
    output = ROOT / 'crates/gateway/testdata/snapshots' / version
    env = os.environ.copy()
    env['ARCORA_FIXTURE_OUTPUT'] = str(output)
    env['CARGO_TARGET_DIR'] = os.environ.get('ARCORA_HISTORICAL_TARGET', '/tmp/arcora-historical-target')
    cmd = ['cargo', 'test', '--locked', '-p', 'gateway', 'generate_historical_snapshot_fixture', '--', '--nocapture']
    log = Path(__file__).with_name(f'historical-{version}.log')
    with log.open('w') as f:
        result = subprocess.run(cmd, cwd=checkout, env=env, stdout=f, stderr=subprocess.STDOUT)
    Path(__file__).with_name(f'historical-{version}-command.json').write_text(json.dumps({
        'source_sha': sha, 'checkout': str(checkout), 'command': cmd,
        'exit_code': result.returncode, 'log': str(log),
        'generator_changes': 'appended test-only module; production source unchanged',
    }, indent=2) + '\n')
    print(version, sha, result.returncode, log, flush=True)
    if result.returncode: raise SystemExit(result.returncode)
