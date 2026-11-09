# e2e

End-to-end tests that run the real `warden` binary against in-process mock
versions of OSV, deps.dev, and CISA's KEV catalog. No network access and no
containers are needed.

    make e2e

Each scenario builds a `lab`: a temporary project directory, a private
`HOME`, and the three mocks, which warden reaches through the
`WARDEN_OSV_URL`, `WARDEN_DEPSDEV_URL`, and `WARDEN_KEV_URL` overrides.
Fixture projects live in `testdata/projects/`.
