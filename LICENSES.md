# Licenses and dependency boundaries

Integrity Project source in this repository is licensed under the Business Source
License 1.1 from version 7.0.0-beta.4 on. Earlier releases (6.1.1 and 7.0.0-beta.1
to 7.0.0-beta.3) were published under Apache-2.0 in an earlier repository; copies
obtained under that license keep it.
Each version changes to Apache-2.0 four years after its release; see [LICENSE](LICENSE)
and [COMMERCIAL.md](COMMERCIAL.md).
The root [LICENSE](LICENSE) and [NOTICE](NOTICE), and the corresponding files in
each distribution, must accompany redistributed source and packages.
[COMPONENTS.json](COMPONENTS.json) records each distribution's declared license
and direct Python dependencies; package metadata is authoritative for installation.

Third-party code keeps its original license and attribution:

- [Execution Bridge notices](components/integrity-execution-bridge/THIRD-PARTY-NOTICES.md)
  preserve the MIT notices for incorporated supporting code.
- [Space third-party notices](components/integrity-space/THIRD-PARTY-NOTICES.txt)
  retain the notices for its bundled JavaScript dependencies. Its generated UI
  also includes the required license text.
- Python dependencies are installed separately from their configured package
  index and retain their own licenses. A declared dependency is not relicensed
  by Integrity's license.

No provider executable, subscription, credential or hosted service entitlement
is distributed. Names of supported clients identify interoperability targets;
their vendors' products and terms remain separate from this source license.

An owner-created configuration, imported archive or runtime database is not part
of this source release. This project does not grant rights to third-party user
content or make imported content public.
