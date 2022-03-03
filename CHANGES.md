# Changes

Please submit a pull request if you make changes that you feel would benefit others.

Keep in mind:

- Breaking changes are a problem, for usual reasons.
- Not everyone has the same needs as you.
- There can be security implications for any change.


## Reference for Maintainers and Contributors

- [Details on setup.py](https://packaging.python.org/tutorials/packaging-projects/)


## Distributing Changes

Building to release for PyPI:

1. `python3 setup.py sdist bdist_wheel`
  - creates files in `./dist`
2. Test: `twine upload --repository-url https://test.pypi.org/legacy/ dist/*`
3. Visit <https://test.pypi.org/project/coinkite-tap-protocol/> to preview.
4. Make a fresh virtual env and activate it.
5. Get latest test version:
  `python3 -m pip install --index-url https://test.pypi.org/simple/ coinkite-tap-protocol --no-cache-dir`
    - Since most dependancies aren't on the TestPyPI repo, install those after each error.
    - You may need to force the version number to get the updated file.
6. Make sure `cktap address` works.
7. Make sure `python -m cktap` works.
8. Final upload: `twine upload dist/*`


## How to Release New Version

1. Update `cktap/__init__.py` with new `__version__` string.
2. `python3 setup.py sdist bdist_wheel`
  - Maybe delete old version from `./dist`?
3. Tag source code with new version (at this point).
4. `twine upload dist/*` when ready.
