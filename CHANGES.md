# Changes

Please submit a pull-request if you make some changes that you feel would be helpful to others.

But please keep in mind:

- breaking changes are a problem, for usual reasons
- not everyone has the same needs as you
- there can be security implications for any change

## Reference for Maintainers and Contributors

- [Details on setup.py](https://packaging.python.org/tutorials/packaging-projects/)

## Distributing Changes

To build to release for Pypi:

- `python3 setup.py sdist bdist_wheel`
- creates files in `./dist`
- then `twine upload --repository-url https://test.pypi.org/legacy/ dist/*` to test
- visit: <https://test.pypi.org/project/coinkite-tap-protocol/> to preview
- make a fresh virtual env, activate it.
- get latest test version: 
  `python3 -m pip install --index-url https://test.pypi.org/simple/ coinkite-tap-protocol --no-cache-dir`
    - but since most dependances aren't on testpypi repo, install those after each error
    - you may need to force the version number to get the updated file
- test `cktap address` works
- test `python -m cktap` works
- final upload: `twine upload dist/*`

## How to Release New Version

- update `cktap/__init__.py` with new `__version__` string
- `python3 setup.py sdist bdist_wheel`
- maybe delete old version from `./dist`
- tag source code with new version (at this point)
- `twine upload dist/*` when ready.
