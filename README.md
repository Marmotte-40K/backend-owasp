# backend-owasp

## Istruzioni per avviare il progetto

1. **Clona il repository**
    ```sh
    git clone <repo-url>
    cd backend-owasp
    ```

2. **Configura le variabili d'ambiente**
    ```sh
    # Copia .env.example in .env e personalizza le variabili se necessario
    cp .env.example .env
    ```

3. **Modifica il docker-compose.yml se necessario**

4. **Avvia i servizi con Docker Compose**
    ```sh
    docker-compose up --build
    ```

## Misure di sicurezza implementate

### Crittografia simmetrica (AES-GCM)
- Tutti i dati sensibili (es. IBAN, codice fiscale, segreti TOTP) sono cifrati a riposo
- Utilizzo di chiavi dedicate e variabili d'ambiente distinte

### Autenticazione JWT
- L'accesso alle API protette richiede un token JWT valido
- Gestione tramite cookie `access_token` e `refresh_token`

### 2FA (TOTP)
- Supporto per autenticazione a due fattori tramite TOTP (Time-based One-Time Password)
- Segreti cifrati nel database

### Protezione brute-force
- Dopo 5 tentativi di login falliti, l'account viene bloccato per 10 minuti

### Gestione sicura delle password
- Le password sono salvate in forma hashata con bcrypt

### Logging sicuro
- Tutte le richieste e risposte sono loggate (file/stdout)
- I tentativi di login falliti sono loggati con dettagli (user/email, IP)
- I dettagli degli errori (stack trace, ID utente, IP) sono presenti nei log
- I dati sensibili (password, token, iban, ecc.) sono mascherati nei log

## Come testare i meccanismi di sicurezza

### 1. Autenticazione e Token
- **Registrazione:**
  ```
  POST /v1/auth/register
  ```
  Con nome, cognome, email e password
  
- **Login:**
  ```
  POST /v1/auth/login
  ```
  Con email e password (se 2FA è abilitato, serve anche `totp_code`)
  
- **Token JWT:**
  - Dopo il login, il token viene salvato nei cookie
  - Prova ad accedere a una rotta protetta (`/v1/users/...`) senza token: riceverai 401

### 2. 2FA (TOTP)
- **Abilita 2FA:**
  ```
  GET /v1/users/{user_id}/totp/qr      # Richiedi il QR code
  POST /v1/users/{user_id}/totp/enable  # Abilita con il codice TOTP
  ```
  Scansiona il QR code con un'app TOTP (es. Google Authenticator)
  
- **Verifica 2FA:**
  - Login con email, password e `totp_code`
  - Prova a inviare un codice errato più volte per vedere il blocco dell'account

### 3. Logging
- **Controlla i log:**
  - Tutte le richieste e risposte sono loggate (stdout/file)
  - I dati sensibili nei log sono mascherati (\***)
  - I tentativi di login falliti e i dettagli degli errori sono presenti nei log

## Note aggiuntive
- **Rotte protette:** Tutte le rotte sotto `/v1/users/` richiedono autenticazione JWT
- **Gestione dati sensibili:** I dati come IBAN e codice fiscale sono cifrati e accessibili solo tramite le API protette
- **Configurazione:** Modifica le variabili d'ambiente in `.env` per personalizzare la sicurezza e la connessione al database