

.PHONY: wheel
wheel:
	python3 setup.py sdist bdist_wheel

win-up: wheel
	cp dist/coinkite*whl /Volumes/work/

up: wheel
	rsync dist/coinkite*whl cktap-burner:.
