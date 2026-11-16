# ChangeLog

## [0.5.2] - 2026-11-16
### Fixed
- Mapa: pakiety nowe dla sesji mapy zawsze pobierają szczegóły obserwacji (jak collectPacket w M² Android) — koniec gubienia tras pakietów z 1 obserwacją bez dopasowań na poziomie pakietu.
- Mapa: usunięty wyścig na starej migawce cache — detale wchłaniane tylko przy zgodności z bieżącym licznikiem obserwacji.
- Mapa: szybszy retry po błędzie pobrania szczegółów (5 s zamiast 30 s).

## [0.5.1] - 2026-11-16
### Fixed
- Mapa: liczniki Routes/Links zgodne z M² Android — jedno zdarzenie na unikalną ścieżkę pakietu (bez mnożenia przez obserwatorów), zdarzenia pakietu podmieniane przy nowych obserwacjach, brak fallbacku bez szczegółów obserwacji.

### Added
- Settings: sekcja ANDROID APP z linkiem do najnowszego wydania M² (APK).

## [0.3.1] - 2026-11-15
### Added
- AES‑GCM decryption with fallback to AES‑ECB for legacy payloads.
- UI toast notifications for MAC validation failures and AES‑GCM decryption errors.
- Architecture diagram (Mermaid) in `ARCHITECTURE.md` (artifact).
- Integration test `test/channels-gcm.test.js`.

### Fixed
- Syntax errors and duplicated implementations in `channels-core.js`.
- Test failures caused by improper async handling.

### Changed
- Updated `README.md` with new section describing encryption, UI feedback, and architecture.
