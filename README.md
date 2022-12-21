# pyorchard
Python bridge for [Orchard](https://github.com/zcash/orchard) Rust crate.

```bash
python3 -m venv env
source env/bin/activate
pip install maturin
maturin build
# exit venv
pip install target/wheels/py_trezor_orchard-0.1.0-cp311-cp311-manylinux_2_34_x86_64.whl  --force-reinstall
```
