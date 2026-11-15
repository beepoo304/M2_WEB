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