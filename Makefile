

.PHONY: wheel
wheel:
	python3 setup.py sdist bdist_wheel

win-up: wheel
	cp dist/coinkite*whl /Volumes/work/

up: wheel
	rsync dist/coinkite*whl cktap-burner:.

CUR_VERSION = $(shell python -c "from cktap.__init__ import __version__; print(__version__)")

TARGETS = dist/coinkite-tap-protocol-$(CUR_VERSION).tar.gz \
	dist/coinkite_tap_protocol-$(CUR_VERSION)-py3-none-any.whl

$(TARGETS) release: Makefile cktap/* setup.py
	python3 setup.py sdist bdist_wheel
	git add $(TARGETS)
	git tag -am v$(CUR_VERSION) v$(CUR_VERSION)
	twine upload $(TARGETS)
