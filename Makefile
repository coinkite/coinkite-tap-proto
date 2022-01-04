

.PHONY: wheel
wheel:
	python3 setup.py sdist bdist_wheel

up: wheel
	cp dist/coinkite*whl /Volumes/work/
