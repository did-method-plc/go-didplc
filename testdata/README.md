`log_*.json` files are in the same format as that of the `/<did>/log/audit` endpoint.

`known_bad_cids.json` enumerates known-invalid operations (referenced by CID) stored by `plc.directory` as of 2025-07-08. See https://github.com/did-method-plc/did-method-plc/issues/109 for further details. `known_bad_dids.json` is the same idea, but it's a list of DIDs containing known-invalid operations in their audit logs.

These lists do *not* presently include operations/DIDs containing duplicate rotation keys.

## Nullification Tests

`log_nullification_nontrivial.json` tests the following (valid) scenario:

```

(op0)<-(op1)<-(op2)<-(op3)<-(op4)  (op5)<-(op6)  (op7)
            \             \       /             /
             \             '--<--'             /
              '-------<------------------<----'
```

(all within 72h)

After operation 6, only op 4 would be nullified. After operation 7, all operations 2-6 will be nullified.

## PLC Export Tests

Some test cases (not run by default) expect full data exports from a PLC directory. The aim is to verify consistency with real data (and secondarily to act as a performance benchmark). This dataset is not included in the repo because it's ~64GB, at time of writing.

Those test can be run like so: (expect to wait ~hours depending on how many CPU cores you have)

```
go test -run TestExportLogEntryValidate -timeout 0
go test -run TestExportAuditLogEntryValidate -timeout 0
```

The first test expects "out.jsonlines", which you can gather for example by running `goat plc dump` (or any other tool that paginates through the `/export` endpoint)

The second test expects "plc_audit_log.jsonlines", which can be constructed by processing "out.jsonlines" with the following python script: https://gist.github.com/DavidBuchanan314/39fa9334e3d182454691d5429a7f199c (all it does is group the operations together by DID, in chronological order)
