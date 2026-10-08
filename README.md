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
- It relies on patched upstream components - the Trustee KBS (VMPL reported as a claim),
  COCONUT-SVSM and its aproxy. What each patch does and what it means for security:
  `PATCHES.md` in the wx-build repository; what the agent needs of them:
  [doc/betrieb.md, "Angepasste Komponenten"](doc/betrieb.md#angepasste-komponenten).

## Build and test

```
./build.sh                    # image wx/wx1-keyagent; META=<path to metalanguage>
test/local.sh                 # CockroachDB, OpenBao, a KBS stub and the agent in Docker, then test/api.sh
```

`test/tpmtest.c` and `test/snptest.c` check the TPM and SNP code against swtpm and real
guest reports.
