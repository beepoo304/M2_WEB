# M2_WEB

## AES‑GCM decryption & UI feedback

Projekt został rozszerzony o nowy mechanizm szyfrowania wiadomości:
- **AES‑GCM** jest używany dla nowych payloadów (16‑bajtowy klucz, zero IV). 
- W przypadku starszych payloadów (32‑bajtowy klucz) zachowano kompatybilność i wykonywana jest de‑krypcja **AES‑ECB**.

### UI toast przy błędach

Dodano prostą funkcję `showToast(message)` w `app.js`, która wyświetla krótkie powiadomienie (toast) w przeglądarce w następujących sytuacjach:
- Niepoprawny **MAC** (integralność wiadomości).
- Błąd dekrypcji **AES‑GCM** (np. `OperationError`).

Dzięki temu użytkownik od razu widzi, że odebrana wiadomość jest niepoprawna.

### Dokumentacja architektury

Pełny diagram architektury znajduje się w artefakcie `ARCHITECTURE.md` w katalogu **brain** tej konwersacji.

---
*Zmiany zostały przetestowane – `npm test` zwraca 0 błędów.*
## Panel administratora — odzyskanie hasła

1. Połącz się przez FTPS z serwerem i wejdź do `httpdoc/stats/data/`.
2. Utwórz tam plik `nowe-haslo.txt`, a w nim wpisz samo nowe hasło (co najmniej 10 znaków).
3. Otwórz `https://sn9pj.pzk.pl/admin/`. Panel zamieni hasło na hash (`admin-hash.php`) i sam usunie `nowe-haslo.txt`.
4. Zaloguj się dotychczasowym loginem i nowym hasłem.

Login jest zapisany w `stats/data/config.php` (`admin_user`). Katalog `stats/data/` jest zablokowany dla przeglądarki (403).
