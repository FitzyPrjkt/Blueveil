# blueveil_ioc (Python extension)

Deterministic IOC normalization + offline indicator matching over
contract-shaped telemetry. Standard library only (`json`, `ipaddress`,
`argparse`, `re`, `unittest`). No network. No ML. No fabricated intel.

## Semantics (read before use)

- Normalization makes equivalent spellings byte-identical. Invalid input
  raises `ValueError` — never a silent default.
- Matching is set membership against YOUR local list: a match reports that
  an indicator string was observed in a field. It says nothing about
  malice, reputation, or threat level.
- Enrichment copies the event and adds at most two attributes,
  `blueveil.python.ioc_match[_count]`, and refuses to overwrite existing
  keys. No match → event returned unchanged.
- Synthetic test data is labeled as such in tests, never as findings.

## CLI

```sh
cd extensions/python
python3 -m blueveil_ioc normalize --kind domain --value Example.COM.
python3 -m blueveil_ioc match --indicators indicators.json < event.json
python3 -m blueveil_ioc enrich --indicators indicators.json < event.json
python3 -m unittest discover -s tests
```

`indicators.json` is an array of `{"kind","value","source"}` objects.
Exit 0 on success, 2 on usage/validation errors.
