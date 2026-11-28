# ChangeLog

## [0.5.7] - 2026-11-28
### Added
- Kopia ustawień: eksport i import (klucze, kanały, API, Mapper API) w zakładce Settings; plik M2_DATA_<data-godzina>.json.
- Monit po intro „Wczytać ustawienia z pliku?” — tylko gdy przeglądarka pusta, raz na sesję.
- Przełącznik języka (PL/EN/RU/SK/CZ/DE/FR) w monicie i w Settings; monit w ustawionym języku.
### Changed
- Domyślny język interfejsu to EN.


## [0.5.6] - 2026-11-28
### Changed
- Panel /admin: wykres zmieniony na trzy cienkie linie (wejścia, unikalni, błędy) zamiast słupków.
- Panel /admin: mniejsze kafle podsumowania (bardziej zwarty układ).


## [0.5.5] - 2026-11-28
### Changed
- Panel /admin: wykres „Wejścia dzień po dniu” zmniejszony (mniej dominujący).
- Panel /admin: nowy kafelek „Aktywni teraz” — unikalni odwiedzający (bez botów) z ostatnich 10 minut.
- Panel /admin: usunięta sekcja „Najczęstsze błędy” (tabela „Ostatnie błędy” zostaje).


## [0.5.4] - 2026-11-28
### Fixed
- Statystyki: wejście i klucz liczone raz na sesję karty (sessionStorage), odświeżenie strony nie jest nowym wejściem.
- Statystyki: dzienny identyfikator odwiedzającego zmienia się o północy czasu polskiego (wcześniej UTC).
- Statystyki: kanał Public znowu liczony (porównanie bez względu na wielkość liter).
- Statystyki: boty pomijane w wejściach, odwiedzających, wykresie, krajach i miastach.
- Panel: wykres dzienny skalowany do wszystkich serii (słupki nie wychodzą poza ramkę).
- Panel: kolumna „Zapytania API” przy kluczach liczona z wagą próbkowania, jak reszta sekcji API.
- API: połączenia do źródeł tylko przez IPv4 (jak mapper.php) — mniej błędów „timed out after 5000 ms”.

### Changed
- Panel: kafelki „Odwiedzający dziennie (średnio)” i „Odwiedzający (suma dzienna)” zamiast mylącego „Unikalni odwiedzający”; „Osoby” → „Osobo-dni”; „Baza kluczy → Zapytania” → „Sesje ze śledzeniem”.
- Panel: „Najczęstsze błędy” ze źródłem, liczbą minut oraz czasem pierwszego i ostatniego wystąpienia.
- Panel: usunięte sekcje Zakładki, Skąd przyszli, Urządzenia, Przeglądarki, Zapytania API wg rodzaju.
- Statystyki: źródło wejścia (referrer) nie jest już zapisywane.


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
