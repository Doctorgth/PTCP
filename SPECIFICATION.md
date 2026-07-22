
```markdown
**Disclaimer:** This document is an English translation of the original Russian specification. While care was taken to maintain consistency, it may contain minor translation inaccuracies or slight terminology differences from the original Russian text. The Russian version remains the primary reference.

---

# Asynchronous Persistent TCP (APTCP) Protocol Specification
**Version:** 1.0  
**Status:** Proposed Standard  
**License:** Apache License 2.0  
**Author:** Doctorgth (https://github.com/Doctorgth) 

---

## 1. Introduction

**Asynchronous Persistent TCP (APTCP)** is a session-layer protocol running on top of the standard TCP transport protocol. The primary goal of APTCP is to ensure the continuity of a logical connection between a client and a server under unstable physical network link conditions (IP address changes, short-term network dropouts, transitions between Wi-Fi and LTE).

The protocol hides network failures from the application programming interface (API) by temporarily buffering data during network "blackouts" and transparently resuming the session when physical contact is restored, without tearing down the logical socket.

### Terminology
In this specification, the key words "MUST", "SHOULD", and "MAY" are to be interpreted as described in RFC standards.

---

## 2. State Machine

Each side of an APTCP logical socket MUST maintain a state machine with the following states:


          +--------------+
          |    CLOSED    | <------------------------+
          +--------------+                          |
                 | (connect)                        |
                 v                                  |
          +--------------+                          |
          |  CONNECTING  |                          |
          +--------------+                          |
                 | (Handshake Success)              | (Graceful Close)
                 v                                  |
          +--------------+                          |
   +----> | ESTABLISHED  | -------------------------+
   |      +--------------+                          |
   |             | (Physical Connection Lost)       |
   |             v                                  |
   |      +----------------------+                  |
   |      | DISCONNECTED_WAITING | -----------------+
   |      +----------------------+                  | (Session Timeout)
   |             | (Reconnected)                    |
   |             v                                  |
   |      +--------------+                          |
   +----  |   RESUMING   | -------------------------+
          +--------------+
```

*   **CLOSED:** The logical connection is closed. Resources are released.
*   **CONNECTING:** The client has initiated a TCP connection and is performing the Diffie-Hellman handshake.
*   **ESTABLISHED:** The logical connection is successfully established. Bi-directional data exchange is active.
*   **DISCONNECTED_WAITING:** The physical TCP channel is lost. The application layer is blocked from sending/receiving; data is being buffered. A session timeout timer (`timeout`) is running.
*   **RESUMING:** The physical TCP channel is restored. The client sends a session resumption request and waits for confirmation from the server.

---

## 3. Wire Format

All data over the physical network is transmitted as frames with the following binary layout. The byte order for all numeric fields MUST be **Big-Endian (network byte order)**.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Length (4 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (1 byte)|                                               |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
|                       Payload (Variable)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```
*   **Length (32-bit unsigned integer, uint32):** The length of the frame, calculated as `1 + Payload length` in bytes.
*   **Type (8-bit integer, uint8):** The frame type identifier.
*   **Payload (variable length):** The frame payload (may be empty).

### Frame Type Identifiers (Frame Types)

| Value (Hex) | Type Name | Direction | Payload |
| :--- | :--- | :--- | :--- |
| `0x01` | `HANDSHAKE_INIT` | Client $\rightarrow$ Server | Client DH public key (256 bytes) |
| `0x02` | `HANDSHAKE_ACK` | Server $\rightarrow$ Client | Session ID (16 bytes) + Server DH public key (256 bytes) |
| `0x03` | `DATA` | Bi-directional | Sequence ID (8 bytes, uint64) + Application data |
| `0x04` | `ACK` | Bi-directional | Acknowledged Sequence ID (8 bytes, uint64) |
| `0x05` | `RESUME_INIT` | Client $\rightarrow$ Server | Session ID (16 bytes) + Client Nonce (8 bytes) + Init Signature (32 bytes) |
| `0x06` | `RESUME_ACK` | Server $\rightarrow$ Client | Server Recv Sequence ID (8 bytes, uint64) |
| `0x07` | `CLOSE` | Bi-directional | Nonce (8 bytes) + Session ID (16 bytes) + Signature (32 bytes) |
| `0x08` | `RESUME_CHALLENGE` | Server $\rightarrow$ Client | Server Nonce (8 bytes) + Challenge Signature (32 bytes) |
| `0x09` | `RESUME_RESPONSE` | Client $\rightarrow$ Server | Response Signature (32 bytes) + Client Recv Sequence ID (8 bytes, uint64) |

---

## 4. Protocol Procedures

### 4.1. Initial Session Establishment (DH Handshake)

To generate a unique shared session key without transmitting it over the network, the Diffie-Hellman algorithm based on the 2048-bit MODP group (RFC 3526) is used.

```
Client                                                    Server
  |                                                         |
  | -- [HANDSHAKE_INIT] (Client Pub Key: 256B) ---------->  |
  |                                                         |
  |                                                [Generate Session ID]
  |                                                [Compute Session Key]
  |                                                         |
  | <-- [HANDSHAKE_ACK] (Session ID: 16B + Server Pub: 256B) |
  |                                                         |
[Compute Session Key]                                       |
[Transition to ESTABLISHED]                               [Transition to ESTABLISHED]
```

1.  **The Client** generates a random private number $a$ (2048 bits) and computes the public key $A = G^a \pmod P$. The key $A$ is sent in the `HANDSHAKE_INIT` frame.
2.  **The Server** receives key $A$, generates a private number $b$ (2048 bits), computes the public key $B = G^b \pmod P$, and generates a random 16-byte `session_id`.
3.  **The Server** computes the shared secret $S = A^b \pmod P$. **Serialization of secret $S$:** Before hashing, the value $S$ MUST be converted into a strict 256-byte Big-Endian binary representation (padded with leading zeros if necessary). The final 32-byte session key `session_key` is calculated as `SHA-256(S)`.
4.  **The Server** sends a `HANDSHAKE_ACK` frame containing the `session_id` and the public key $B$.
5.  **The Client** receives the data and computes the shared secret $S = B^a \pmod P$. The value $S$ MUST similarly be serialized into a 256-byte Big-Endian representation and hashed to obtain the session key: `session_key = SHA-256(S)`.

---

### 4.2. Data Transmission and Delivery Confirmation (Reliability)

Bi-directional data transmission occurs using strictly monotonically increasing frame identifiers (`Sequence ID`).

1.  The sender increments the `send_seq` counter by 1, saves the transmitted data in the `retrans_buffer`, and sends a `DATA` frame.
2.  The receiver verifies that the incoming `seq` is strictly equal to `recv_seq + 1` (the expected next packet). If this condition is met:
    *   `recv_seq` is updated with the value of `seq`.
    *   The data is passed to the application read buffer.
3.  The receiver sends an `ACK` frame in response containing the updated `recv_seq`.
4.  Upon receiving the `ACK`, the sender removes all frames from its `retrans_buffer` whose `Sequence ID` is less than or equal to the acknowledged value.

---

### 4.3. Session Resumption (Mutual Auth Handshake)

Upon detecting a dropped TCP connection, both sides transition to the `DISCONNECTED_WAITING` state. The logical socket remains open. To prevent replay attacks and MitM session hijacking, a mutual challenge-response verification is enforced.

```
Client (New TCP Connection)                               Server
  |                                                         |
  | -- [RESUME_INIT] (SessionID + ClientNonce + InitSig) -> |
  |                                                         |
  |                                                 [Verify InitSig]
  |                                                         |
  | <-- [RESUME_CHALLENGE] (ServerNonce + ChallengeSig) --- |
  |                                                         |
  |                                              [Verify ChallengeSig]
  |                                                         |
  | -- [RESUME_RESPONSE] (ResponseSig + ClientRecvSeq) ---> |
  |                                                         |
  |                                               [Verify ResponseSig]
  |                                            [Rebind Connection Pipes]
  |                                                         |
  | <-- [RESUME_ACK] (ServerRecvSeq) ---------------------- |
  |                                                         |
[Clear buffers by ServerRecvSeq]                  [Clear buffers by ClientRecvSeq]
[Retransmit lost DATA]                            [Retransmit lost DATA]
```

1.  The client establishes a new TCP connection to the server.
2.  The client generates a random 8-byte `client_nonce` and computes `init_signature = HMAC-SHA256(session_key, session_id + client_nonce)`.
3.  The client sends a `RESUME_INIT` frame containing `session_id`, `client_nonce`, and `init_signature`.
4.  The server verifies the request. If the `session_id` exists in active memory and `init_signature` is correct, the server generates a random 8-byte `server_nonce` and computes `challenge_sig = HMAC-SHA256(session_key, session_id + server_nonce + client_nonce)`. The server sends a `RESUME_CHALLENGE` frame containing these values. If validation fails, the server closes the TCP connection silently.
5.  The client verifies `challenge_sig`. If correct, the client computes `client_response_sig = HMAC-SHA256(session_key, session_id + client_nonce + server_nonce)` and sends a `RESUME_RESPONSE` frame containing `client_response_sig` and the current local `recv_seq`.
6.  The server verifies `client_response_sig`. If correct, the old TCP connection is closed, the new I/O channels are bound to the restored session, the server transitions to the `ESTABLISHED` state, and sends a `RESUME_ACK` frame containing its current `recv_seq`.
7.  Both sides, based on the exchanged sequence numbers, clear their retransmission buffers and retransmit any `DATA` frames lost during the dropout.

---

### 4.4. Graceful Close

Either side MAY initiate session closure. To prevent unauthorized termination by MitM packet injection, close commands MUST be authenticated:

1.  The initiator generates a random 8-byte `nonce`, computes `signature = HMAC-SHA256(session_key, session_id + nonce + b'CLOSE')`, and sends a `CLOSE` frame containing `nonce`, `session_id`, and `signature`. The initiator immediately transitions its logical socket to the `CLOSED` state and closes the physical TCP connection.
2.  The receiver verifies the payload size and the validity of the signature. If the signature is correct and `session_id` matches the current active session, the receiver transitions its socket to the `CLOSED` state, closes the physical channel, and wakes up the application software with an EOF signal (`b''` upon reading). If the signature is invalid, the frame is silently dropped to prevent MitM injection.

If one of the sides disconnects abruptly during a network outage (e.g., the device powered off), the session on the server is destroyed automatically after the `session timeout` has expired using a background Garbage Collector.

---

## 5. Flow Control, Backpressure & Concurrency

To prevent uncontrolled memory consumption for buffering during prolonged network outages, APTCP protocol implementations MUST enforce limits on the maximum buffer sizes:

1.  **Write Backpressure:** Each side MUST have a retransmission buffer limit (e.g., 5 MB). When the buffer is full, calling the application-level `send()` method MUST block the execution thread (or return a timeout error), pausing the generation of new data by the application.
2.  **Read Flow Control:** If the application does not read data from the receive buffer, the receiver MUST pause reading from the system TCP socket. This will naturally shrink the TCP window size and force the sender to stop transmitting data over the network.
3.  **Frame Write Atomicity:** Since sending frames can occur concurrently from different execution contexts (application data sent by the user, control ACK frames sent by the background read task, retransmission of buffers upon session resumption), the protocol implementation MUST strictly synchronize writes to the system network buffer (e.g., using a Mutex or asynchronous write locks). Interleaving bytes of different frames within a single TCP connection is strictly prohibited.

---

## 6. Security Considerations

*   **Confidentiality:** The base APTCP v1.0 specification does not encrypt application data inside `DATA` frames. It is assumed that encryption and protection against eavesdropping are handled by higher-layer protocols (such as TLS, SSH, HTTPS, SOCKS5 with encryption) running inside the APTCP pipe.
*   **Session Protection:** The session resumption (`RESUME`) procedure is fully protected against replay attacks and unauthorized session hijacking through the use of a dynamic Diffie-Hellman key, random single-use numbers (`nonce`), and HMAC-SHA256 cryptographic signatures. An attacker who does not know the secret `session_key` cannot enter another active session. Upon receiving an invalid signature, the server immediately terminates the connection, hiding information about the session's existence.

---
---

# Спецификация протокола Asynchronous Persistent TCP (APTCP)
**Версия:** 1.0  
**Статус:** Открытая спецификация (Proposed Standard)  
**Лицензия:** Apache License 2.0  
**Автор:** Doctorgth (https://github.com/Doctorgth) 

---

## 1. Введение (Introduction)

**Asynchronous Persistent TCP (APTCP)** — это протокол сеансового уровня (Session Layer), работающий поверх стандартного транспортного протокола TCP. Главная задача APTCP — обеспечение непрерывности логического соединения между клиентом и сервером в условиях нестабильного физического канала связи (смена IP-адресов, кратковременные обрывы сети, переключение между Wi-Fi и LTE).

Протокол скрывает сетевые сбои от прикладного программного интерфейса (API), временно буферизируя данные во время «блэкаутов» сети и прозрачно восстанавливая сессию при возобновлении физического контакта без разрыва логического сокета.

### Терминология
В данной спецификации ключевые слова «ДОЛЖЕН» (MUST), «СЛЕДУЕТ» (SHOULD) и «МОЖЕТ» (MAY) интерпретируются в соответствии со стандартами RFC.


---

## 2. Модель состояний (State Machine)

Каждая сторона логического сокета APTCP ДОЛЖНА поддерживать конечный автомат со следующими состояниями:

```
          +--------------+
          |    CLOSED    | <------------------------+
          +--------------+                          |
                 | (connect)                        |
                 v                                  |
          +--------------+                          |
          |  CONNECTING  |                          |
          +--------------+                          |
                 | (Handshake Success)              | (Graceful Close)
                 v                                  |
          +--------------+                          |
   +----> | ESTABLISHED  | -------------------------+
   |      +--------------+                          |
   |             | (Physical Connection Lost)       |
   |             v                                  |
   |      +----------------------+                  |
   |      | DISCONNECTED_WAITING | -----------------+
   |      +----------------------+                  | (Session Timeout)
   |             | (Reconnected)                    |
   |             v                                  |
   |      +--------------+                          |
   +----  |   RESUMING   | -------------------------+
          +--------------+
```

*   **CLOSED:** Логическое соединение закрыто. Ресурсы освобождены.
*   **CONNECTING:** Клиент инициировал TCP-соединение и выполняет Diffie-Hellman хэндшейк.
*   **ESTABLISHED:** Логическое соединение успешно установлено. Происходит двунаправленный обмен данными.
*   **DISCONNECTED_WAITING:** Физический TCP-канал потерян. Прикладной уровень заблокирован на отправку/прием, данные буферизируются. Запущен таймер таймаута сессии (`timeout`).
*   **RESUMING:** Физический TCP-канал восстановлен. Клиент отправляет запрос на возобновление сессии и ждет подтверждения от сервера.

---

## 3. Формат кадра (Wire Format)

Все данные по сетевому кабелю передаются в виде кадров (frames) со следующим бинарным макетом. Порядок байт для всех числовых полей — **Big-Endian (сетевой)**.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Length (4 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (1 byte)|                                               |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
|                       Payload (Variable)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

*   **Length (32-битное беззнаковое целое, uint32):** Длина кадра, рассчитываемая как `1 + длина полезной нагрузки (Payload)` в байтах.
*   **Type (8-битное целое, uint8):** Идентификатор типа кадра.
*   **Payload (переменная длина):** Полезная нагрузка кадра (может отсутствовать).

### Идентификаторы типов кадров (Frame Types)

| Значение (Hex) | Имя типа | Направление | Полезная нагрузка |
| :--- | :--- | :--- | :--- |
| `0x01` | `HANDSHAKE_INIT` | Клиент $\rightarrow$ Сервер | Публичный ключ DH клиента (256 байт) |
| `0x02` | `HANDSHAKE_ACK` | Сервер $\rightarrow$ Клиент | ID сессии (16 байт) + Публичный ключ DH сервера (256 байт) |
| `0x03` | `DATA` | Двунаправленный | Sequence ID (8 байт, uint64) + Прикладные данные |
| `0x04` | `ACK` | Двунаправленный | Подтвержденный Sequence ID (8 байт, uint64) |
| `0x05` | `RESUME_INIT` | Клиент $\rightarrow$ Сервер | ID сессии (16 байт) + Client Nonce (8 байт) + Init Signature (32 байта) |
| `0x06` | `RESUME_ACK` | Сервер $\rightarrow$ Клиент | Recv Sequence ID сервера (8 байт, uint64) |
| `0x07` | `CLOSE` | Двунаправленный | Nonce (8 байт) + ID сессии (16 байт) + Signature (32 байта) |
| `0x08` | `RESUME_CHALLENGE` | Сервер $\rightarrow$ Клиент | Server Nonce (8 байт) + Challenge Signature (32 байта) |
| `0x09` | `RESUME_RESPONSE` | Клиент $\rightarrow$ Сервер | Response Signature (32 байта) + Recv Sequence ID клиента (8 байт, uint64) |

---

## 4. Процедуры протокола (Protocol Procedures)

### 4.1. Первичная установка сессии (DH Handshake)

Для генерации уникального общего ключа сессии без передачи его по сети используется алгоритм Диффи-Хеллмана на базе 2048-битной MODP-группы (RFC 3526).

```
Клиент                                                    Сервер
  |                                                         |
  | -- [HANDSHAKE_INIT] (Client Pub Key: 256B) ---------->  |
  |                                                         |
  |                                                [Генерация Session ID]
  |                                                [Вычисление Session Key]
  |                                                         |
  | <-- [HANDSHAKE_ACK] (Session ID: 16B + Server Pub: 256B) |
  |                                                         |
[Вычисление Session Key]                                    |
[Переход в ESTABLISHED]                                   [Переход в ESTABLISHED]
```

1.  **Клиент** генерирует случайное приватное число $a$ (2048 бит) и вычисляет публичный ключ $A = G^a \pmod P$. Ключ $A$ отправляется в кадре `HANDSHAKE_INIT`.
2.  **Сервер** получает ключ $A$, генерирует приватное число $b$ (2048 бит), вычисляет публичный ключ $B = G^b \pmod P$, генерирует случайный 16-байтный `session_id`.
3.  **Сервер** вычисляет общий секрет (Shared Secret) $S = A^b \pmod P$. **Сериализация секрета $S$:** Перед процедурой хэширования число $S$ ДОЛЖНО быть преобразовано в строго 256-байтное бинарное представление в формате Big-Endian (при необходимости дополняется ведущими нулями). Итоговый сессионный ключ `session_key` (32 байта) вычисляется как `SHA-256(S)`.
4.  **Сервер** отправляет кадр `HANDSHAKE_ACK`, содержащий `session_id` и публичный ключ $B$.
5.  **Клиент** принимает данные, вычисляет Shared Secret $S = B^a \pmod P$. Число $S$ аналогичным образом ДОЛЖНО быть сериализовано в 256-байтовое представление Big-Endian и хэшировано для получения сессионного ключа: `session_key = SHA-256(S)`.

---

### 4.2. Передача данных и подтверждение доставки (Reliability)

Двунаправленная передача данных происходит с использованием строго монотонно возрастающих идентификаторов кадров (`Sequence ID`).

1.  Отправитель увеличивает счетчик `send_seq` на 1, сохраняет отправляемые данные в буфере `retrans_buffer` и отправляет кадр `DATA`.
2.  Получатель проверяет, что пришедший `seq` строго равен `recv_seq + 1` (ожидаемый следующий пакет). Если условие верно:
    *   `recv_seq` обновляется значением `seq`.
    *   Данные передаются приложению в буфер чтения.
3.  Получатель в ответ отправляет кадр `ACK`, содержащий актуальный `recv_seq`.
4.  Отправитель при получении `ACK` удаляет из своего `retrans_buffer` все кадры, чей `Sequence ID` меньше или равен подтвержденному значению.

---

### 4.3. Возобновление сессии (Session Resumption)

При обнаружении падения TCP-соединения обе стороны переходят в состояние `DISCONNECTED_WAITING`. Логический сокет остается открытым. Для предотвращения атак воспроизведения и MitM-перехвата сессий применяется процедура обоюдной проверки Challenge-Response.

```
Клиент (Новое TCP-соединение)                             Сервер
  |                                                         |
  | -- [RESUME_INIT] (SessionID + ClientNonce + InitSig) -> |
  |                                                         |
  |                                                 [Проверка InitSig]
  |                                                         |
  | <-- [RESUME_CHALLENGE] (ServerNonce + ChallengeSig) --- |
  |                                                         |
  |                                              [Проверка ChallengeSig]
  |                                                         |
  | -- [RESUME_RESPONSE] (ResponseSig + ClientRecvSeq) ---> |
  |                                                         |
  |                                               [Проверка ResponseSig]
  |                                            [Перепривязка ввода-вывода]
  |                                                         |
  | <-- [RESUME_ACK] (ServerRecvSeq) ---------------------- |
  |                                                         |
[Очистка буферов по ServerRecvSeq]


[Очистка буферов по ServerRecvSeq]                [Очистка буферов по ClientRecvSeq]
[Пересылка утерянных DATA]                        [Пересылка утерянных DATA]

```

1.  Клиент устанавливает новое TCP-подключение к серверу.
2.  Клиент генерирует случайный 8-байтный `client_nonce` и вычисляет `init_signature = HMAC-SHA256(session_key, session_id + client_nonce)`.
3.  Клиент отправляет кадр `RESUME_INIT`, содержащий `session_id`, `client_nonce` и `init_signature`.
4.  Сервер проверяет запрос. Если `session_id` присутствует в активной памяти и `init_signature` верна, сервер генерирует случайный 8-байтный `server_nonce` и вычисляет `challenge_sig = HMAC-SHA256(session_key, session_id + server_nonce + client_nonce)`. Сервер отправляет кадр `RESUME_CHALLENGE`, содержащий эти значения. Если валидация не пройдена, сервер молча закрывает TCP-соединение.
5.  Клиент проверяет `challenge_sig`. Если она верна, клиент вычисляет `client_response_sig = HMAC-SHA256(session_key, session_id + client_nonce + server_nonce)` и отправляет кадр `RESUME_RESPONSE`, содержащий `client_response_sig` и текущий локальный `recv_seq`.
6.  Сервер проверяет `client_response_sig`. Если она верна, старое TCP-соединение закрывается, новые каналы ввода-вывода привязываются к восстановленной сессии, сервер переходит в состояние `ESTABLISHED` и отправляет кадр `RESUME_ACK`, содержащий свой текущий `recv_seq`.
7.  Обе стороны, основываясь на полученных номерах последовательностей, очищают свои буферы переотправки и повторно отправляют кадры `DATA`, утерянные во время обрыва связи.

---

### 4.4. Штатное закрытие сессии (Graceful Close)

Любая сторона МОЖЕТ инициировать закрытие сессии. Для предотвращения несанкционированного закрытия сокета через инъекцию пакетов MitM-атакующим, команды закрытия ДОЛЖНЫ быть подписаны:

1.  Инициатор генерирует случайный 8-байтный `nonce`, вычисляет `signature = HMAC-SHA256(session_key, session_id + nonce + b'CLOSE')` и отправляет кадр `CLOSE`, содержащий `nonce`, `session_id` и `signature`. Инициатор немедленно переводит свой логический сокет в состояние `CLOSED` и закрывает физическое TCP-соединение.
2.  Получатель проверяет размер полезной нагрузки и валидность сигнатуры. Если сигнатура верна и `session_id` совпадает с текущей активной сессией, получатель переводит свой сокет в состояние `CLOSED`, закрывает физический канал и будит прикладное ПО, возвращая сигнал EOF (`b''` при чтении). Если сигнатура невалидна, кадр молча игнорируется для предотвращения инъекций.

Если одна из сторон «исчезает» аварийно во время обрыва сети (например, устройство выключилось), сессия на сервере уничтожается автоматически по истечении тайм-аута (`session timeout`) с помощью фонового сборщика мусора (Garbage Collector).

---

## 5. Контроль переполнения, буферизация и конкуренция (Flow Control, Backpressure & Concurrency)

Для предотвращения бесконтрольного расхода оперативной памяти на буферизацию при длительных обрывах связи реализации протокола APTCP ДОЛЖНЫ накладывать ограничения на максимальный размер буферов:

1.  **Backpressure на отправку:** Каждая сторона должна иметь лимит буфера переотправки (например, 5 МБ). При заполнении буфера вызов прикладного метода `send()` ДОЛЖЕН блокировать поток (или возвращать ошибку ожидания), приостанавливая генерацию новых данных приложением.
2.  **Flow Control на прием:** Если приложение не забирает данные из буфера приема, получатель должен приостанавливать чтение из системного TCP-сокета. Это естественным образом уменьшит окно TCP и заставит отправляющую сторону прекратить передачу данных по сети.
3.  **Атомарность записи кадров:** Поскольку отправка кадров может происходить параллельно из разных контекстов выполнения (отправка прикладных данных пользователем, отправка служебных ACK-кадров фоновой задачей чтения, повторная отправка буфера при возобновлении связи), реализация протокола ДОЛЖНА строго синхронизировать запись в системный сетевой буфер (например, с помощью Mutex или асинхронных замков записи). Чередование байтов разных кадров в рамках одного TCP-соединения категорически запрещено.

---

## 6. Безопасность (Security Considerations)

*   **Конфиденциальность:** Базовая спецификация APTCP v1.0 не шифрует прикладные данные в кадрах `DATA`. Предполагается, что шифрование и защита от прослушивания реализуются протоколами более высокого уровня (TLS, SSH, HTTPS, SOCKS5 с шифрованием), которые работают внутри трубы APTCP.
*   **Защита сессии:** Процедура возобновления сессии (`RESUME`) полностью защищена от атак воспроизведения (Replay Attacks) и несанкционированного перехвата сессии за счет использования динамического ключа Diffie-Hellman, случайных одноразовых чисел (`nonce`) и криптографических подписей HMAC-SHA256. Атакующий, не зная секретный `session_key`, не может войти в чужую активную сессию. При получении невалидной подписи сервер немедленно обрывает соединение, скрывая информацию о существовании сессии.
