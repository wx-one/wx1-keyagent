# wx1-keyagent

The customer's side of confidential VMs (AMD SEV-SNP with COCONUT-SVSM): it runs at the
customer, holds the keys of their VMs' disks in their own OpenBao, and hands a key only to a
VM that proves it is exactly the one the customer approved - by SNP reports signed by AMD,
its vTPM, a quote over its boot chain, a replay stand and a lease. The provider files
requests ("new VM", "another host", ...) and learns only whether they were applied.

Written in meta (metalanguage) and served by nginx.

- Operating it: [doc/betrieb.md](doc/betrieb.md)
- Unlocking data volumes yourself: [doc/daten-volumes.md](doc/daten-volumes.md)
- OpenBao policy: [deploy/openbao-policy.hcl](deploy/openbao-policy.hcl)
- It needs an adapted Trustee KBS (VMPL reported as a claim):
  [doc/betrieb.md, "Angepasster Trustee-KBS"](doc/betrieb.md#angepasster-trustee-kbs).

## Build and test

```
ci/build.sh <version>         # the release tarball, against meta at /opt/meta (the wxone/meta image)
./build.sh                    # the same in the meta image of ci/meta-image, then an image wx/wx1-keyagent
test/local.sh                 # CockroachDB, OpenBao, a KBS stub and the agent in Docker, then test/api.sh
IMAGE=<image> NO_BUILD=1 test/local.sh   # the same against another image, e.g. one from ci/Dockerfile.release
```

CI (`.github/workflows/build.yml`) builds the release on ubuntu-24.04 with meta from the
`wxone/meta` image named by tag and digest in `ci/meta-image` (the local `build.sh` uses
the same one), runs `test/api.sh` against the image, and on a tag `v*` publishes the
release on GitHub and the image on ghcr.io.

`test/tpmtest.c` and `test/snptest.c` check the TPM and SNP code against swtpm and real
guest reports.

## Licence

wx1-keyagent is licensed under the European Union Public Licence, version 1.2
(EUPL-1.2), in `LICENSE`. The EUPL is valid in all official languages of the EU; the
other language versions are published at https://joinup.ec.europa.eu/collection/eupl.
What the release contains from others, and under which licence, is in
`THIRD_PARTY_NOTICES` inside the tarball and in its SBOM.
