# Lab tools

Operator tools for an isolated two-VM lab (a Windows guest that runs the native
client and a Linux guest that runs the memory backend and a narrow HTTPS egress
proxy). They prepare the VMs, stage the client, run bounded preflights and
canaries, and read back evidence. They are kept as a worked example of how the
lab was built; they are not part of the installed components.

## Configuration

Every value that depends on a particular machine (host paths, VM names and
UUIDs, guest hostnames, addresses, MAC, build pins) is read from `lab.json`
through `lab_config.py`. Copy `lab.example.json` to `lab.json` beside the
tools, or point `INTEGRITY_LAB_CONFIG` at it, and replace every placeholder.
A missing or empty key stops the tool with a message naming the key. The
example uses documentation addresses only (RFC 5737) and must not be used as
it is.

The host-side tools copy `lab.json` and `lab_config.py` to the guests (seed
media, ISO root, guest control directory), so keep the file free of anything
the guests should not see.

`tests/test_lab_tools.py` checks, without starting anything: every source
compiles and has the license header, the example lists every key the tools
read and holds only documentation addresses, the pure helpers of
`lab_config.py`, the egress proxy policy, and the benchmark prompt builder.

## Not verified

- The published form of these tools was not run against a lab. The original
  tools were used on one lab; the configuration was then moved out of the
  code, and those edits were checked only by the static tests above.
- No VM, guest, VirtualBox, SSH, network or model call was made for this
  publication.
- Guest paths under `C:\IntegrityLAB` and `/opt/integrity-lab`, and the
  account names `lab` and `labadmin`, are fixed in the code.
- `sandbox_probe.py` now needs `--working-sentinel` and `--policy-sentinel`;
  the tool that called it is not included.
- The hash pins in `windows_native_canary.py` and
  `windows_native_compat_stage.py` belong to one client build and will not
  match another.
