reinstall:
	python -m venv env
	source env/bin/activate
	maturin build -i python
	deactivate
	pip install target/wheels/trezor_orchard-0.1.0-cp310-cp310-linux_x86_64.whl  --force-reinstall
