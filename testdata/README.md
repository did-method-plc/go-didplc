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
