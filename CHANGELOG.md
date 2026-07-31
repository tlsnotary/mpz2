# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `SharedRCOTSender` and `SharedRCOTReceiver` no longer report a pending flush for
  allocations which have already been fulfilled, which could deadlock an instance
  on the flush barrier.
