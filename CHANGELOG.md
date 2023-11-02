# Changelog

## [1.3.1](https://github.com/nosduco/nforwardauth/compare/v1.3.0...v1.3.1) (2023-11-02)


### Bug Fixes

* handle error from jwt manipulation ([2267fcc](https://github.com/nosduco/nforwardauth/commit/2267fcc22590da41782a38c4c56e0fd9c79db086))
* handle error from jwt manipulation ([#40](https://github.com/nosduco/nforwardauth/issues/40)) ([150a3c9](https://github.com/nosduco/nforwardauth/commit/150a3c9995935b1d14096bfeb6df2d7a78f743e1))


### CI/CD

* update release workflow to publish to dockerhub on release creation ([947601d](https://github.com/nosduco/nforwardauth/commit/947601dbb4b17207b8bd53a99060f5e6f2a5a150))

## [1.3.0](https://github.com/nosduco/nforwardauth/compare/v1.2.2...v1.3.0) (2023-11-02)


### Features

* rate limiter ([0a4202b](https://github.com/nosduco/nforwardauth/commit/0a4202b0d2dfcc25c7bf7dbec2168b54ef200f79))
* respect x-forwarded-proto for location header redirection ([6e064bc](https://github.com/nosduco/nforwardauth/commit/6e064bc77a5d2aaf6584984ebaf9ad543910d2fc))
* skip/redirect login when cookie is present ([ef322a9](https://github.com/nosduco/nforwardauth/commit/ef322a91b410d4b134c1af94b5efaa9513281aa1))


### Refactor

* clean up ending return statement in login wrapper ([ebd72d5](https://github.com/nosduco/nforwardauth/commit/ebd72d5ece7edf0203313a4498dd4af25dfb2d1b))
* move config to it's own mod ([b8826df](https://github.com/nosduco/nforwardauth/commit/b8826df2b8ca470b3c3bf8bb59997e16c681636f))
* prefer some(..) over is_some/unwrap ([8268a7d](https://github.com/nosduco/nforwardauth/commit/8268a7d22954bb66008ce84f3747249aeab00516))


### Miscellaneous Tasks

* fix formatting ([f627705](https://github.com/nosduco/nforwardauth/commit/f627705c91ce41c3f44b34222494425213c76783))
* fix formatting ([a95afb4](https://github.com/nosduco/nforwardauth/commit/a95afb4a44e44473ddf8bf08bacc2c285769c5fe))
* merge main into dev ([2bf5a91](https://github.com/nosduco/nforwardauth/commit/2bf5a9172445d4a858bb415e6c0c5fff9331b643))
* switch to trunk based releases - catch-up main with dev ([#38](https://github.com/nosduco/nforwardauth/issues/38)) ([e0030ca](https://github.com/nosduco/nforwardauth/commit/e0030ca5c36813b1eba58a2b995b5f5db263f1a8))


### CI/CD

* add prepare release workflow ([78b8381](https://github.com/nosduco/nforwardauth/commit/78b838168d1843e7a0bfcce58fd3c9e03d706497))
* change dependabot target branch ([187ed46](https://github.com/nosduco/nforwardauth/commit/187ed46696694f2764c1661efadc8151ae164041))
* configure dependabot to follow conventional commits ([6f58a4e](https://github.com/nosduco/nforwardauth/commit/6f58a4e6ebdac94666d40441102025d74715f5af))
* reorganize workflows and make names consistent ([19f75cc](https://github.com/nosduco/nforwardauth/commit/19f75cc36f51370a54689118d15cde7b644a112a))
* update release pull request title ([c3ede33](https://github.com/nosduco/nforwardauth/commit/c3ede331e840ba43145b42bbf2db0ac53d63c763))
