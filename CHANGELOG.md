# Changelog

## [Unreleased]

### Fixed
- Import Gamedata skipped a mid-function signature as "duplicate" when another entry already pointed into the same function (e.g. several patches in one function). Duplicates are now keyed on the signature address.

## [1.0.0] - 2025-03-13

### Added
- Initial release
- Modular crawler system (10 anchor modules)
- Multi-pass parallel pathfinder
- Identity gate + reinforcement scoring
- Gamedata export (CounterStrikeSharp, SwiftlyS2)
- Auto-save/load tracking data
- Mid-function signature support
- VTable offset tracking
- Tree-style logging
- Cross-platform builds (Linux, macOS, Windows)

---

**Repository**: [K4ryuu/IDA-GameDataTracker](https://github.com/K4ryuu/IDA-GameDataTracker)
