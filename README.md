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
./build.sh                    # an image wx/wx1-keyagent from a metalanguage checkout (META=<path>)
test/local.sh                 # CockroachDB, OpenBao, a KBS stub and the agent in Docker, then test/api.sh
IMAGE=<image> NO_BUILD=1 test/local.sh   # the same against another image, e.g. one from ci/Dockerfile.release
```

CI (`.github/workflows/build.yml`) builds the release on ubuntu-24.04 with meta from the
`wxone/meta` image named by tag and digest in `ci/meta-image` (the local `build.sh` uses
the same one), runs `test/api.sh` against
it in a plain ubuntu:24.04, and on a tag `v*` publishes it as a GitHub release.

`test/tpmtest.c` and `test/snptest.c` check the TPM and SNP code against swtpm and real
guest reports.
