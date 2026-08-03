

**Disclaimer:** This document is an English translation of the original Russian README. While care was taken to maintain consistency, it may contain minor translation inaccuracies or slight terminology differences from the original Russian text. The Russian version remains the primary reference.

---

# aioptcp — Python Implementation of the APTCP Protocol

The `aioptcp` library is an asynchronous implementation of the **APTCP** session-layer protocol (running on top of standard transport TCP) designed for the `asyncio` environment.

The **APTCP** protocol is designed to ensure logical connection persistence during short-term network disruptions, interface handovers (Wi-Fi to LTE), or IP address changes.

> **Terminology Note:**
> * The network protocol itself is called **APTCP**.
> * The Python implementation library is called `aioptcp` (the `aio` prefix indicates `asyncio` usage).
> * Within the library code, classes use the `PTCP` prefix (e.g., `PTCPSocket`, `PTCPClient`, `PTCPServer`), since the asynchronous nature is already indicated by the package name.

---

## Architecture and Features

* **Transparency for Application Code:** When a physical TCP connection drops, the logical socket transitions into a waiting state. Outgoing data is buffered, and calls to `send()` and `recv()` block without raising errors. Once the connection is re-established, the APTCP session automatically resumes without any data loss.
* **Built-in Flow Control (Backpressure):** Retransmission buffer limits prevent uncontrolled RAM consumption. The `send()` method automatically pauses the calling coroutine if the buffer limit is exceeded.
* **Secure Session Resumption:** Session resumption is secured via a mutual 3-way Challenge-Response handshake using HMAC-SHA256 signatures derived from a shared secret generated during the initial Diffie-Hellman exchange (2048-bit MODP Group). This protects the protocol against replay and MitM hijacking attacks.
* **Authenticated Graceful Shutdown:** The `CLOSE` frame is crytographically signed with a session-bound HMAC-SHA256 signature, preventing MitM attackers from injecting unauthorized connection teardown commands.

---

## Installation

Place the `aioptcp` package inside your project directory or install it via:

```bash
pip install aioptcp
```

---

## Quick Start Guide

### 1. Running an APTCP Server

The server listens for incoming TCP connections, handles APTCP handshakes, and provides active logical sessions to the application.

```python
import asyncio
from aioptcp import PTCPServer, PTCPSocket

async def handle_client(session: PTCPSocket):
    session_hex = session.session_id.hex()
    print(f"[Server] APTCP session {session_hex} successfully established.")
    
    try:
        while True:
            # Read data from the APTCP logical socket
            data = await session.recv(1024)
            if not data:
                # Empty bytes indicate that the client initiated a graceful close (EOF)
                print(f"[Server] Session {session_hex} closed gracefully by client.")
                break
                
            print(f"[Server] Received from {session_hex}: {data.decode(errors='ignore')}")
            
            # Send echo response back into the session
            await session.send(b"Echo: " + data)
            
    except Exception as e:
        print(f"[Server] Error in session {session_hex}: {e}")
    finally:
        # Gracefully release socket resources
        await session.close()

async def main():
    # Start the APTCP server on port 8888 with a session timeout of 30 seconds
    server = PTCPServer(host='127.0.0.1', port=8888, timeout=30)
    await server.start()
    print("[Server] APTCP server started, waiting for connections...")
    
    while True:
        # Accept a new logical APTCP connection
        session = await server.accept()
        asyncio.create_task(handle_client(session))

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Running an APTCP Client

The client initiates the connection. In case of a network disruption, the library handles reconnection in the background without interrupting the application-level send/receive cycle.

```python
import asyncio
from aioptcp import PTCPClient

async def main():
    # Create an APTCP client with a session keep-alive timeout of 30 seconds
    client = PTCPClient(host='127.0.0.1', port=8888, timeout=30)
    
    try:
        print("[Client] Connecting to APTCP server...")
        await client.connect()
        print(f"[Client] Logical connection established. Session ID: {client.session_id.hex()}")
        
        # Periodically send messages
        for i in range(1, 6):
            message = f"Message {i}".encode()
            print(f"[Client] Sending: {message.decode()}")
            
            # If the network drops, send() will block rather than failing
            await client.send(message)
            
            # Wait for response
            response = await client.recv(1024)
            print(f"[Client] Server response: {response.decode(errors='ignore')}")
            
            await asyncio.sleep(2)
            
    except Exception as e:
        print(f"[Client] Critical error: {e}")
    finally:
        # Graceful logical socket closure (transmits a signed CLOSE frame)
        print("[Client] Closing connection.")
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## API Reference

### `PTCPSocket` Class
The base class representing a logical APTCP socket. Used directly by the client (inherited by `PTCPClient`) and returned by `PTCPServer.accept()`.

*   **`state: PTCPState`**
    The current state of the logical socket. Values (IntEnum):
    *   `PTCPState.CONNECTING` (1) — Performing initial handshake.
    *   `PTCPState.ESTABLISHED` (2) — Connection established, data transfer permitted.
    *   `PTCPState.DISCONNECTED_WAITING` (3) — Physical link lost, waiting to resume.
    *   `PTCPState.RESUMING` (4) — Executing session resumption over a new TCP channel.
    *   `PTCPState.CLOSED` (5) — Connection permanently closed.
*   **`session_id: bytes`**
    A unique 16-byte identifier for the APTCP session. Set after a successful initial handshake.
*   **`buffer_size_limit: int`**
    The maximum size of the retransmission buffer (defaults to `5 * 1024 * 1024` bytes, or 5 MB).
*   **`async send(data: bytes) -> bool`**
    Asynchronously transmits data.
    *   If the retransmission buffer is full (buffered bytes $\ge$ `buffer_size_limit`), the coroutine suspends execution (blocks) until an ACK is received from the peer.
    *   If the socket is in the `DISCONNECTED_WAITING` or `RESUMING` state, data is buffered and the coroutine returns successfully.
    *   Returns `True` if successfully buffered/sent. Returns `False` if the socket is permanently closed (`CLOSED`).
*   **`async recv(size: int) -> bytes`**
    Asynchronously reads data from the application receive buffer.
    *   Blocks until data becomes available in the buffer.
    *   Returns received data up to `size` bytes.
    *   **Note:** Returns empty bytes (`b''`) when the remote peer gracefully closes the connection (EOF signal).
*   **`async close(send_close_frame: bool = True)`**
    Terminates the logical session and releases resources. If `send_close_frame` is `True`, it generates and transmits an authenticated `CLOSE` frame.

### `PTCPClient(PTCPSocket)` Class
The APTCP client class, inheriting the logical core of `PTCPSocket`.

*   **`__init__(host: str, port: int, timeout: int = 30)`**
    Creates a client instance. `timeout` determines how long (in seconds) the client will attempt to restore the logical session after a network disruption.
*   **`async connect()`**
    Initiates physical connection and performs key exchange (Diffie-Hellman handshake). Blocks until the state shifts to `ESTABLISHED`. Raises `TimeoutError` if a connection cannot be established within the timeout limit.

### `PTCPServer` Class
The server class, managing the lifecycle of APTCP sessions.

*   **`__init__(host: str, port: int, timeout: int = 30)`**
    Creates a server instance. `timeout` is the duration the server keeps a disconnected session alive before reclaiming memory.
*   **`async start()`**
    Binds the TCP listener to the specified host and port, and starts the background Garbage Collector to clean up abandoned sessions.
*   **`async accept() -> PTCPSocket`**
    Waits for a client to complete the handshake and returns a configured `PTCPSocket` in the `ESTABLISHED` state.
*   **`sessions: dict`**
    A dictionary containing active sessions, mapping `session_id` (16 bytes) to the respective `PTCPSocket` instance.

---

## AI Integration Guidelines

When writing code that integrates `aioptcp`, follow these guidelines:

1.  **Do not implement application-level reconnect logic.**
    If the network connection drops, **do not** recreate the `PTCPClient` instance or call `connect()` again. The library transitions the socket to `DISCONNECTED_WAITING` and recovers the physical link in the background. Application-level calls to `send()` and `recv()` will block until resumption is complete.
2.  **Detect connection teardown via empty read results.**
    The only reliable way to detect that the remote peer closed the logical socket is checking if `await session.recv()` returns `b''`.
3.  **Run server connections in concurrent tasks.**
    `PTCPServer.accept()` should be called within an infinite loop, and each accepted session must be offloaded to a separate task using `asyncio.create_task()`.
4.  **Manage resource cleanup.**
    Always close sessions using `await session.close()` within a `finally` block to prevent file descriptor leaks.

The library natively supports secure data transmission over TLS. You can pass a configured ssl.SSLContext object to the ssl parameter when initializing PTCPClient or PTCPServer, exactly the same way as in standard asyncio methods (such as asyncio.open_connection and asyncio.start_server). If this parameter is omitted, the connection is established in plaintext.


PyPI Link:
https://pypi.org/project/aioptcp/

---
---

# aioptcp — Python-реализация протокола APTCP

Библиотека `aioptcp` — это асинхронная реализация сеансового протокола **APTCP** (работающего поверх стандартного транспортного протокола TCP) для среды `asyncio`. 

Протокол **APTCP** разработан для обеспечения непрерывности логического соединения при кратковременных обрывах сети, переключениях между интерфейсами (Wi-Fi/LTE) или смене IP-адресов.

> **Важно по терминологии:** 
> * Сам сетевой протокол называется **APTCP**.
> * Реализующая его библиотека для Python называется `aioptcp` (префикс `aio` означает использование `asyncio`).
> * Внутри кода библиотеки классы используют префикс `PTCP` (например, `PTCPSocket`, `PTCPClient`, `PTCPServer`), так как указание на асинхронность уже вынесено в название самого пакета.

---

## Архитектура и особенности

* **Прозрачность для прикладного кода:** При падении физического TCP-соединения логический сокет переходит в режим ожидания. Данные буферизируются на отправку, а вызовы методов `send()` и `recv()` блокируются, но не вызывают ошибок. После восстановления канала сессия APTCP автоматически возобновляется без потерь данных.
* **Встроенный контроль переполнения (Backpressure):** Ограничение буфера переотправки предотвращает бесконтрольное потребление оперативной памяти. Метод `send()` автоматически приостанавливает выполнение корутины, если лимит буфера превышен.
* **Безопасность возобновления сессий:** Возобновление сессии APTCP авторизуется с помощью трехэтапного взаимного Challenge-Response рукопожатия с подписью HMAC-SHA256 на базе ключа, сгенерированного в процессе первичного обмена по алгоритму Диффи-Хеллмана (2048-bit MODP Group). Это полностью исключает возможность replay-атак и MitM-перехвата сессий.
* **Авторизованное закрытие сокета:** Команда `CLOSE` подписывается криптографической HMAC-SHA256 подписью, привязанной к сессии, что исключает возможность закрытия сокета злоумышленником через инъекцию пакетов.

---

## Установка

Поместите пакет `aioptcp` в директорию вашего проекта или установите его:

```bash
pip install aioptcp
```

---

## Руководство по использованию (Quick Start)

### 1. Запуск APTCP-сервера

Сервер слушает входящие TCP-подключения, обрабатывает рукопожатия APTCP и предоставляет приложению готовые логические сессии.

```python
import asyncio
from aioptcp import PTCPServer, PTCPSocket

async def handle_client(session: PTCPSocket):
    session_hex = session.session_id.hex()
    print(f"[Сервер] APTCP-сессия {session_hex} успешно установлена.")
    
    try:
        while True:
            # Чтение данных из логического сокета APTCP
            data = await session.recv(1024)
            if not data:
                # Получен пустой байтовый массив — клиент закрыл соединение штатно (EOF)
                print(f"[Сервер] Сессия {session_hex} закрыта клиентом.")
                break
                
            print(f"[Сервер] Получено от {session_hex}: {data.decode(errors='ignore')}")
            
            # Отправка эхо-ответа обратно в сессию
            await session.send(b"Echo: " + data)
            
    except Exception as e:
        print(f"[Сервер] Ошибка в сессии {session_hex}: {e}")
    finally:
        # Корректно закрываем ресурсы сокета
        await session.close()

async def main():
    # Запуск сервера APTCP на порту 8888 с таймаутом удержания сессии 30 секунд
    server = PTCPServer(host='127.0.0.1', port=8888, timeout=30)
    await server.start()
    print("[Сервер] APTCP-сервер запущен и ожидает подключений...")
    
    while True:
        # Ожидание нового логического подключения APTCP
        session = await server.accept()
        asyncio.create_task(handle_client(session))

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Запуск APTCP-клиента

Клиент инициирует соединение. В случае физического обрыва связи библиотека переподключается в фоновом режиме, при этом прикладной цикл отправки/приема не прерывается.

```python
import asyncio
from aioptcp import PTCPClient

async def main():
    # Создание клиента APTCP с таймаутом удержания сессии 30 секунд
    client = PTCPClient(host='127.0.0.1', port=8888, timeout=30)
    
    try:
        print("[Клиент] Подключение к APTCP-серверу...")
        await client.connect()
        print(f"[Клиент] Логическое соединение установлено. ID сессии: {client.session_id.hex()}")
        
        # Отправка сообщений в цикле
        for i in range(1, 6):
            message = f"Message {i}".encode()
            print(f"[Клиент] Отправка: {message.decode()}")
            
            # Если сеть пропадет, метод send заблокируется, но не упадет с ошибкой
            await client.send(message)
            
            # Ожидание ответа
            response = await client.recv(1024)
            print(f"[Клиент] Ответ от сервера: {response.decode(errors='ignore')}")
            
            await asyncio.sleep(2)
            
    except Exception as e:
        print(f"[Клиент] Критическая ошибка: {e}")
    finally:
        # Штатное закрытие логического сокета и отправка подписанного кадра CLOSE
        print("[Клиент] Закрытие соединения.")
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Справочник по API (API Reference)

### Класс `PTCPSocket`
Базовый класс, реализующий логический сокет протокола APTCP. Используется клиентом напрямую (наследуется в `PTCPClient`) и возвращается методом `PTCPServer.accept()`.

*   **`state: PTCPState`**
    Текущее состояние логического сокета. Значения (IntEnum):
    *   `PTCPState.CONNECTING` (1) — выполняется первичное рукопожатие.
    *   `PTCPState.ESTABLISHED` (2) — соединение установлено, передача разрешена.
    *   `PTCPState.DISCONNECTED_WAITING` (3) — физический канал утерян, ожидание восстановления.
    *   `PTCPState.RESUMING` (4) — выполняется восстановление сессии на новом TCP-канале.
    *   `PTCPState.CLOSED` (5) — соединение закрыто окончательно.
*   **`session_id: bytes`**
    Уникальный 16-байтный идентификатор сессии APTCP. Заполняется после завершения рукопожатия.
*   **`buffer_size_limit: int`**
    Лимит размера буфера переотправки (по умолчанию `5 * 1024 * 1024` байт, или 5 МБ).
*   **`async send(data: bytes) -> bool`**
    Асинхронная отправка данных.
    *   Если буфер переотправки переполнен (размер неотправленных данных $\ge$ `buffer_size_limit`), корутина приостанавливает выполнение (блокируется) до тех пор, пока от противоположной стороны не придет ACK-подтверждение.
    *   Если сокет находится в состоянии `DISCONNECTED_WAITING` или `RESUMING`, данные буферизируются, а корутина завершается успешно.
    *   Возвращает `True` при успешной буферизации/отправке. Возвращает `False`, если сокет окончательно закрыт (`CLOSED`).
*   **`async recv(size: int) -> bytes`**
    Асинхронное чтение данных из прикладного буфера приема.
    *   Блокирует выполнение до появления данных в буфере.
    *   Возвращает полученные данные длиной не более `size` байт.
    *   **Важно:** Возвращает пустую строку байт (`b''`), когда удаленная сторона штатно закрыла соединение (сигнал EOF).
*   **`async close(send_close_frame: bool = True)`**
    Завершает логическую сессию и освобождает системные ресурсы. Если `send_close_frame` равен `True`, отправляет удаленной стороне служебный подписанный кадр `CLOSE`.

### Класс `PTCPClient(PTCPSocket)`
Класс клиента протокола APTCP, наследующий логику `PTCPSocket`.

*   **`__init__(host: str, port: int, timeout: int = 30)`**
    Создает экземпляр клиента. `timeout` определяет, в течение какого времени (в секундах) клиент будет пытаться восстановить логическую сессию после обрыва сети.
*   **`async connect()`**
    Инициирует физическое соединение с сервером и производит обмен ключами (рукопожатие Диффи-Хеллмана). Блокирует выполнение до перехода сокета в состояние `ESTABLISHED`. При невозможности установить первичное соединение в течение `timeout` секунд возбуждает `TimeoutError`.

### Класс `PTCPServer`
Класс сервера, управляющий жизненным циклом сессий APTCP.

*   **`__init__(host: str, port: int, timeout: int = 30)`**
    Создает экземпляр сервера. `timeout` — время ожидания переподключения клиента до уничтожения сессии из памяти сервера.
*   **`async start()`**
    Запускает TCP-слушатель на указанном хосте и порту, а также активирует фоновый сборщик мусора (Garbage Collector) для очистки зависших сессий.
*   **`async accept() -> PTCPSocket`**
    Ожидает завершения рукопожатия с новым клиентом и возвращает готовый объект сокета `PTCPSocket` в состоянии `ESTABLISHED`.
*   **`sessions: dict`**
    Словарь активных сессий сервера, где ключ — `session_id` (16 байт), а значение — экземпляр `PTCPSocket`.

---

## Инструкции для ИИ (AI Integration Guidelines)

При написании программного кода, использующего `aioptcp`, руководствуйтесь следующими правилами:

1.  **Не реализуйте логику повторного подключения (reconnect) на уровне приложения.**
    Если произошел сбой сети, **не нужно** заново создавать экземпляр `PTCPClient` и повторно вызывать `connect()`. Библиотека сама переведет сокет в состояние `DISCONNECTED_WAITING` и восстановит физическое TCP-соединение в фоновом режиме. Прикладные вызовы `send()` и `recv()` просто подождут завершения этого процесса.
2.  **Определяйте закрытие сокета по пустому результату чтения.**
    Единственный верный способ узнать, что удаленная сторона закрыла логический сокет — это получить `b''` в качестве результата вызова `await session.recv()`.
3.  **Используйте конкурентные задачи для работы с сервером.**
    Метод `PTCPServer.accept()` вызывается в бесконечном цикле, и каждую полученную сессию необходимо передавать в отдельную корутину с помощью `asyncio.create_task()`, чтобы сервер мог продолжать принимать новые соединения.
4.  **Следите за закрытием ресурсов.**
    Всегда закрывайте сессию с помощью `await session.close()` в блоке `finally` обработчика соединений для предотвращения утечки дескрипторов файлов ОС.

Библиотека нативно поддерживает безопасную передачу данных по протоколу TLS. Вы можете передать настроенный объект ssl.SSLContext в параметр ssl при создании PTCPClient и PTCPServer точно так же, как это делается в стандартных методах asyncio (например, asyncio.open_connection и asyncio.start_server). Если параметр не задан, соединение устанавливается в открытом виде.


Ссылка на PyPI
https://pypi.org/project/aioptcp/
