# Changelog

## [1.5.1](https://github.com/nosduco/nforwardauth/compare/v1.5.0...v1.5.1) (2025-09-29)


### Bug Fixes

* cippy issues ([d5fc249](https://github.com/nosduco/nforwardauth/commit/d5fc2497a46d806bffd79b3fe97b827ee21a680c))

## [1.5.0](https://github.com/nosduco/nforwardauth/compare/v1.4.2...v1.5.0) (2025-06-13)


### Features

* X-Forwarded-User for downstream identification, rate-limiting for all failed login attempts ([ac52ca5](https://github.com/nosduco/nforwardauth/commit/ac52ca5da86608fa33271bf4d68afded2a257ac3))


### Refactor

* comment styling ([60c4208](https://github.com/nosduco/nforwardauth/commit/60c42087513e4873850a04d066e41d5fd84dca9b))

## [1.4.2](https://github.com/nosduco/nforwardauth/compare/v1.4.1...v1.4.2) (2025-01-23)


### Bug Fixes

* prevent path traversal in file serving ([#56](https://github.com/nosduco/nforwardauth/issues/56)) ([5f8ccf6](https://github.com/nosduco/nforwardauth/commit/5f8ccf60366b79983cab90cdc37b1205f5eddeb4))


### Refactor

* dockerfile syntax ([118ae08](https://github.com/nosduco/nforwardauth/commit/118ae082ee1cd1825bf824157fc854a7fda37442))

## [1.4.1](https://github.com/nosduco/nforwardauth/compare/v1.4.0...v1.4.1) (2024-12-12)


### Bug Fixes

* crash after changing TOKEN_SECRET [#55](https://github.com/nosduco/nforwardauth/issues/55) ([23c17b7](https://github.com/nosduco/nforwardauth/commit/23c17b7856ac7c5c55ea1e0ef5a84f86dbb3b053))
* **deps:** bump actions/cache from 3 to 4 ([67fa4d5](https://github.com/nosduco/nforwardauth/commit/67fa4d597fa91ad816fa02fd81a89c4790b3f743))
* **deps:** bump docker/build-push-action from 5 to 6 ([3f923c0](https://github.com/nosduco/nforwardauth/commit/3f923c046faf7e47f200829198b0f48208cfbfd2))

## [1.4.0](https://github.com/nosduco/nforwardauth/compare/v1.3.4...v1.4.0) (2024-01-03)


### Features

* add nginx forward auth route for nginx support ([0e0a0d8](https://github.com/nosduco/nforwardauth/commit/0e0a0d8813cd1a6483493cb2b48e21eb1d3ffb98))


### Miscellaneous Tasks

* remove unnecessary print statement ([2ddba9a](https://github.com/nosduco/nforwardauth/commit/2ddba9a29f4acba764fb536c1817992d50001362))

## [1.3.4](https://github.com/nosduco/nforwardauth/compare/v1.3.3...v1.3.4) (2023-12-27)


### CI/CD

* use tag version instead of commit sha on binary archive names ([cc8913e](https://github.com/nosduco/nforwardauth/commit/cc8913eceb2042b80bd650080703659065e96212))

## [1.3.3](https://github.com/nosduco/nforwardauth/compare/v1.3.2...v1.3.3) (2023-12-27)


### CI/CD

* fix binary release artifact attachments ([03ebe99](https://github.com/nosduco/nforwardauth/commit/03ebe99c8523c22d75ba673bda519bfbff685426))

## [1.3.2](https://github.com/nosduco/nforwardauth/compare/v1.3.1...v1.3.2) (2023-12-27)


### CI/CD

* add multi-build step for compiling binaries ([fdd52e8](https://github.com/nosduco/nforwardauth/commit/fdd52e8ab2474de22e4b250ee5c097b5af7561d0))
* disable macos build when cross-compiling ([fe6178f](https://github.com/nosduco/nforwardauth/commit/fe6178f333c89adb9c7e2f186a3448346810869d))
* remove windows from cross-compile builds ([6c2bd59](https://github.com/nosduco/nforwardauth/commit/6c2bd594119997e04704e350593cddbeaf4ff922))
* rename build steps and configure build binaries step to trigger on release and add release artifacts ([c03b480](https://github.com/nosduco/nforwardauth/commit/c03b48090f965cc4903d0b17b0dffaac1bf733bc))

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
