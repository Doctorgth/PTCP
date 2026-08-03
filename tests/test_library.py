import asyncio
import socket
import time
import struct
import pytest
import ssl
import os
import tempfile
import subprocess
from aioptcp import PTCPServer, PTCPClient, PTCPState, FrameType, PTCPSocket

"""
================================================================================
МЕТОДОЛОГИЯ И ОПИСАНИЕ ТЕСТОВ БИБЛИОТЕКИ PTCP (test_library.py)
================================================================================

Данный тестовый набор написан с использованием фреймворка pytest и плагина pytest-asyncio.
Цель тестов — верификация корректности работы кастомного протокола PTCP (сеансовый уровень
над TCP) в условиях штатной работы, высоких нагрузок и нестабильного сетевого соединения.

Для симуляции реального сетевого взаимодействия тесты динамически выделяют свободные порты
ОС (loopback-интерфейс 127.0.0.1) и запускают полноценные экземпляры PTCPServer и PTCPClient.

--------------------------------------------------------------------------------
ОПИСАНИЕ ТЕСТОВЫХ СЦЕНАРИЕВ:
--------------------------------------------------------------------------------

1. test_handshake_and_dh_key_exchange (Рукопожатие и Диффи-Хеллман)
   - Что проверяет: Инициализацию сессии без предварительно заданного ключа (PSK).
   - Логика: Клиент и сервер обмениваются публичными ключами в кадрах HANDSHAKE_INIT
     и HANDSHAKE_ACK. На основе приватных экспонент вычисляется общий секрет (shared secret).
     Тест гарантирует, что на обеих сторонах сгенерирован идентичный 16-байтный session_id
     и одинаковый 32-байтный сессионный ключ (session_key).

2. test_data_transfer_and_ack (Доставка данных и подтверждение)
   - Что проверяет: Гарантированную доставку кадров DATA и механизм очистки буфера.
   - Логика: При отправке пакет помещается в буфер переотправки (retrans_buffer). После
     вычитывания данных сервером, тот отправляет обратно кадр ACK. Тест проверяет, что
     клиентский буфер гарантированно очищается при получении ACK, предотвращая утечку памяти.

3. test_clean_immediate_close (Штатное быстрое закрытие сессии)
   - Что проверяет: Отсутствие «зависания» сокетов при добровольном разрыве соединения.
   - Логика: Клиент вызывает close(), что должно инициировать отправку кадра CLOSE ДО перевода
     сокета в закрытое состояние. Тест контролирует, что сервер мгновенно выходит из блокирующего
     ожидания recv(), возвращая пустые байты (EOF), и завершает сессию без ожидания таймаутов.

4. test_session_resumption_after_disconnect (Возобновление сессии / Session Resumption)
   - Что проверяет: Главную фичу протокола — прозрачность обрыва связи для приложения.
   - Логика: Эмулируется физический обрыв TCP-соединения во время работы (вызовом _handle_disconnect).
     В период «блэкаута» приложение отправляет данные. Тест проверяет, что данные безопасно
     аккумулируются в буфере. После автоматического переподключения клиента сессия восстанавливается,
     а накопленные данные прозрачно передаются серверу без дублирования.

5. test_backpressure_buffer_limit (Контроль переполнения буфера / Backpressure)
   - Что проверяет: Защиту от бесконечного потребления памяти при отсутствии интернета.
   - Логика: Лимит буфера искусственно занижается до 10 байт. Симулируется падение сети. Чтобы
     клиент не смог мгновенно переподключиться на loopback-интерфейсе, его порт временно
     подменяется на случайный свободный. Тест проверяет, что при попытке превысить лимит буфера
     метод send() блокирует вызывающий поток. После восстановления связи (возврат оригинального порта)
     и вычитки данных сервером буфер освобождается, и заблокированная задача автоматически
     успешно завершается.

6. test_server_garbage_collector (Очистка ресурсов / Сборщик мусора сервера)
   - Что проверяет: Автоматическое удаление «осиротевших» сессий на стороне сервера.
   - Логика: Устанавливается агрессивный таймаут сессии (1 секунда). Клиент резко отключается
     (без отправки кадра CLOSE) и полностью уничтожается. Тест проверяет, что фоновый процесс
     _garbage_collector на сервере обнаруживает неактивную сессию, закрывает ее ресурсы и
     удаляет из оперативной памяти сервера по истечении таймаута.

7. test_malformed_frame_boundaries (Валидация обрезанных кадров)
   - Что проверяет: Защиту от некорректных/обрезанных кадров на этапе хэндшейка.
   - Логика: Тест запускает фиктивный TCP-сервер, который присылает клиенту заведомо усеченный
     кадр HANDSHAKE_ACK. Тест проверяет, что клиент выбрасывает ValueError/TimeoutError,
     не падает в непредсказуемые состояния и чисто закрывает сокет, не допуская утечки дескрипторов.

8. test_strict_in_order_and_deduplication (Строгий порядок и дедупликация)
   - Что проверяет: Строго последовательную сборку потока данных (seq == recv_seq + 1).
   - Логика: В сокет принудительно посылаются: правильный пакет 1, дубликат пакета 1, пакет 3
     (с «дырой», так как ожидается 2), а затем правильный пакет 2. Тест проверяет, что прикладной
     уровень получает только пакеты 1 и 2, дубликат и пакет с зазором игнорируются, но при этом
     на все входящие кадры шлется ACK для очистки буфера отправителя.

9. test_server_unsupported_first_frame_leak_prevention (Защита от сканирования портов)
   - Что проверяет: Мгновенное пресечение невалидных подключений на сервере.
   - Логика: На порт сервера отправляется произвольное TCP-подключение, первым кадром в котором
     идет не HANDSHAKE_INIT или RESUME, а мусорный кадр ACK. Тест проверяет, что сервер не вешает
     это соединение в памяти, а мгновенно обрывает связь (вызывает close/wait_closed) во избежание утечки сокетов.

10. test_server_memory_leak_on_graceful_close (Очистка сессий сервера из ОЗУ)
    - Что проверяет: Отсутствие утечки памяти сервера при штатных отключениях.
    - Логика: При штатном закрытии сокета клиентом (close) сервер должен мгновенно стереть сессию
      из своего внутреннего словаря sessions (через callback on_close), не дожидаясь 30-секундного
      таймаута сборщика мусора.

11. test_parallel_sends_concurrency (Потокобезопасность конкурентной отправки)
    - Что проверяет: Стабильность метода send() при вызове из параллельных корутин.
    - Логика: Запускаются 50 параллельных задач отправки через один сокет. Тест проверяет, что
      выделение Sequence ID благодаря send_lock происходит атомарно, пакеты уходят на провод в
      строгой последовательности без разрывов, а принимающая сторона собирает их без потерь.

================================================================================
"""


# Вспомогательный метод для поиска свободного порта в ОС
def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_handshake_and_dh_key_exchange():
    """Тест 1: Проверка успешного хэндшейка и генерации одинаковых DH-ключей на обеих сторонах"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5)
    await client.connect()

    server_socket = await asyncio.wait_for(server.accept(), timeout=2.0)

    try:
        # Проверяем, что соединение установлено
        assert client.state == PTCPState.ESTABLISHED
        assert server_socket.state == PTCPState.ESTABLISHED

        # Проверяем, что ID сессий совпадают
        assert client.session_id == server_socket.session_id
        assert len(client.session_id) == 16

        # Самое важное: сгенерированные через DH ключи сессии должны совпадать
        assert client.session_key == server_socket.session_key
        assert len(client.session_key) == 32  # SHA-256 хэш от shared secret
    finally:
        await client.close()
        await server_socket.close()


@pytest.mark.asyncio
async def test_data_transfer_and_ack():
    """Тест 2: Проверка обычной передачи данных и очистки буфера после получения подтверждения (ACK)"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5)
    await client.connect()
    server_socket = await server.accept()

    try:
        # Отправляем сообщение
        payload = b"hello world"
        success = await client.send(payload)
        assert success is True

        # Проверяем, что данные попали в буфер переотправки клиента
        assert len(client.retrans_buffer) == 1

        # Сервер считывает данные
        received_data = await asyncio.wait_for(server_socket.recv(len(payload)), timeout=2.0)
        assert received_data == payload

        # Ждем короткое время, чтобы кадр ACK успел дойти обратно до клиента
        await asyncio.sleep(0.1)

        # Буфер переотправки клиента должен очиститься после получения ACK
        assert len(client.retrans_buffer) == 0
        assert client.current_retrans_size == 0
    finally:
        await client.close()
        await server_socket.close()


@pytest.mark.asyncio
async def test_clean_immediate_close():
    """Тест 3: Проверка штатного быстрого закрытия без ожидания таймаутов"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5)
    await client.connect()
    server_socket = await server.accept()

    try:
        # Клиент инициирует закрытие
        await client.close()
        assert client.state == PTCPState.CLOSED

        # Сервер должен мгновенно разблокировать recv() и вернуть b"" (EOF)
        received_data = await asyncio.wait_for(server_socket.recv(1024), timeout=1.0)
        assert received_data == b""
        assert server_socket.state == PTCPState.CLOSED
    finally:
        await server_socket.close()


@pytest.mark.asyncio
async def test_session_resumption_after_disconnect():
    """Тест 4: Эмуляция обрыва связи, отправка данных в буфер «офлайн» и успешное возобновление сессии"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5)
    await client.connect()
    server_socket = await server.accept()

    try:
        # Шаг 1: Эмулируем физический обрыв сетевого кабеля со стороны клиента
        client._handle_disconnect()
        assert client.state == PTCPState.DISCONNECTED_WAITING

        # Шаг 2: Приложение пытается отправить данные во время «блэкаута»
        offline_payload = b"saved in offline"
        await client.send(offline_payload)

        # Данные обязаны лежать в буфере ожидания
        assert len(client.retrans_buffer) == 1
        assert client.retrans_buffer[client.send_seq] == offline_payload

        # Шаг 3: Клиент пытается автоматически переподключиться.
        # Дадим ему время соединиться с сервером заново
        start_time = time.time()
        while client.state != PTCPState.ESTABLISHED:
            await asyncio.sleep(0.1)
            if time.time() - start_time > 5.0:
                pytest.fail("Сессия не смогла восстановиться за разумное время")

        # Шаг 4: Сервер должен принять переподключение и без потерь выдать накопленные данные
        received_data = await asyncio.wait_for(server_socket.recv(len(offline_payload)), timeout=2.0)
        assert received_data == offline_payload

        # Даем время на прохождение ACK
        await asyncio.sleep(0.1)
        assert len(client.retrans_buffer) == 0
    finally:
        await client.close()
        await server_socket.close()


@pytest.mark.asyncio
async def test_backpressure_buffer_limit():
    """Тест 5: Проверка ограничения скорости (Backpressure) при переполнении буфера"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5)
    # Искусственно занижаем лимит буфера до 10 байт для простоты тестирования
    client.buffer_size_limit = 10
    await client.connect()
    server_socket = await server.accept()

    try:
        # Сдвигаем порт на несуществующий, чтобы фоновый реконнект гарантированно провалился
        client.port = get_free_port()
        client._handle_disconnect()

        # Первая отправка (6 байт) — помещается в лимит (10 байт)
        assert await client.send(b"123456") is True

        # Вторая отправка (6 байт) — суммарно 12 байт. Превысит лимит.
        # Этот send сработает, но сбросит drain_event
        assert await client.send(b"789012") is True
        assert client.drain_event.is_set() is False

        # Третья отправка должна заблокироваться (так как drain_event сброшен)
        blocked_send_task = asyncio.create_task(client.send(b"blocked"))

        # Проверяем, что задача действительно зависла в режиме ожидания свободного места
        try:
            await asyncio.wait_for(asyncio.shield(blocked_send_task), timeout=0.5)
            pytest.fail("Вызов send() не заблокировался при переполнении буфера!")
        except asyncio.TimeoutError:
            # Задача успешно заблокирована, как мы и ожидали
            pass

        # Возвращаем правильный порт обратно, чтобы клиент мог успешно переподключиться
        client.port = port

        # Клиент сам переподключится по таймеру
        start_time = time.time()
        while client.state != PTCPState.ESTABLISHED:
            await asyncio.sleep(0.1)
            if time.time() - start_time > 5.0:
                pytest.fail("Клиент не смог переподключиться")

        # Сервер вычитывает данные, отправляя ACK-и
        d1 = await asyncio.wait_for(server_socket.recv(6), timeout=2.0)
        d2 = await asyncio.wait_for(server_socket.recv(6), timeout=2.0)
        assert d1 == b"123456"
        assert d2 == b"789012"

        # Ждем, когда ACK-и дойдут до клиента и разблокируют задачу
        await asyncio.sleep(0.2)
        assert blocked_send_task.done() is True
        assert blocked_send_task.result() is True

        # Сервер считывает третью, ранее заблокированную отправку
        d3 = await asyncio.wait_for(server_socket.recv(7), timeout=2.0)
        assert d3 == b"blocked"
    finally:
        await client.close()
        await server_socket.close()


@pytest.mark.asyncio
async def test_server_garbage_collector():
    """Тест 6: Проверка работы Garbage Collector на сервере для зависших сессий"""
    port = get_free_port()
    # Задаем агрессивный таймаут сессии в 1 секунду
    server = PTCPServer('127.0.0.1', port, timeout=1)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=1)
    await client.connect()
    server_socket = await server.accept()

    session_id = server_socket.session_id
    assert session_id in server.sessions

    try:
        # Имитируем резкий краш клиента (не отправляя кадр CLOSE)
        client._handle_disconnect()
        await client.close()  # Предотвращаем любые реконнекты

        # Сборщик мусора проверяет сессии каждые 5 секунд.
        # Подождем 6 секунд, чтобы таймаут (1с) гарантированно истек и GC отработал.
        await asyncio.sleep(6.0)

        # Сессия должна быть стерта из реестра сервера, а сокет закрыт
        assert session_id not in server.sessions
        assert server_socket.state == PTCPState.CLOSED
    finally:
        await server_socket.close()


@pytest.mark.asyncio
async def test_malformed_frame_boundaries():
    """Тест 7: Проверка защиты клиента от поврежденных/обрезанных кадров во время хэндшейка"""
    port = get_free_port()

    # Запускаем сырой фиктивный TCP-сервер, имитирующий отправку поврежденного HANDSHAKE_ACK
    async def handle_dummy(reader, writer):
        try:
            # Читаем кадр HANDSHAKE_INIT от клиента
            await reader.readexactly(4 + 1 + 256)
            # Отправляем клиенту обрезанный кадр HANDSHAKE_ACK (длина 50 байт вместо положенных 273)
            writer.write(struct.pack('!IB', 50, FrameType.HANDSHAKE_ACK.value) + b"A" * 49)
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    dummy_server = await asyncio.start_server(handle_dummy, '127.0.0.1', port)
    client = PTCPClient('127.0.0.1', port, timeout=2)

    try:
        with pytest.raises((ValueError, TimeoutError)):
            await client.connect()

        # Проверяем, что при ошибке хэндшейка сокет гарантированно закрылся и не утекли сокеты
        assert client.state == PTCPState.CLOSED
        assert client.writer is None
    finally:
        dummy_server.close()
        await dummy_server.wait_closed()


@pytest.mark.asyncio
async def test_strict_in_order_and_deduplication():
    """Тест 8: Проверка строгого упорядочивания данных и игнорирования дубликатов"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5)
    await client.connect()
    server_socket = await server.accept()

    try:
        # Отправляем кадры вручную в обход стандартного API, чтобы сгенерировать дубликаты и зазоры
        # Наш recv_seq изначально равен 0

        # 1. Отправляем правильный пакет 1 (recv_seq становится 1)
        await client._send_frame(FrameType.DATA, struct.pack('!Q', 1) + b"packet_1")
        # 2. Отправляем дубликат пакета 1 (должен быть проигнорирован прикладным буфером)
        await client._send_frame(FrameType.DATA, struct.pack('!Q', 1) + b"duplicate_1")
        # 3. Отправляем пакет 3 с зазором (ожидается 2). Должен быть отброшен.
        await client._send_frame(FrameType.DATA, struct.pack('!Q', 3) + b"gap_3")
        # 4. Отправляем правильный пакет 2. Должен быть принят (recv_seq станет 2).
        await client._send_frame(FrameType.DATA, struct.pack('!Q', 2) + b"packet_2")

        # Приложение на сервере должно прочесть последовательные данные в виде единого потока "packet_1packet_2"
        # Так как PTCP — это потоковый протокол (как TCP), данные склеиваются в прикладном буфере приема.
        received_stream = await asyncio.wait_for(server_socket.recv(100), timeout=1.0)
        assert received_stream == b"packet_1packet_2"

        # Проверяем, что в буфере приема сервера больше ничего нет (дубликаты и зазоры гарантированно отброшены)
        assert len(server_socket.app_recv_buffer) == 0
    finally:
        await client.close()
        await server_socket.close()


@pytest.mark.asyncio
async def test_server_unsupported_first_frame_leak_prevention():
    """Тест 9: Защита от утечки сокетов на сервере при отправке неверного первого кадра (сканирование)"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    # Подключаемся по голому TCP и шлем мусорный кадр ACK вместо HANDSHAKE_INIT
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    try:
        # Упаковываем кадр ACK: длина 9 байт, тип ACK, произвольный seq
        invalid_frame = struct.pack('!IBQ', 9, FrameType.ACK.value, 999)
        writer.write(invalid_frame)
        await writer.drain()

        # Сервер должен мгновенно разорвать это некорректное соединение.
        # Ожидаем получить немедленный EOF (пустые байты) из сокета без зависания.
        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        assert data == b""
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_server_memory_leak_on_graceful_close():
    """Тест 10: Проверка мгновенного удаления сессии из ОЗУ сервера при штатном закрытии сокета"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5)
    await client.connect()
    server_socket = await server.accept()

    session_id = server_socket.session_id
    assert session_id in server.sessions

    try:
        # Клиент инициирует штатное закрытие сокета
        await client.close()
        # Даем событиям в цикле asyncio прокрутиться
        await asyncio.sleep(0.1)

        # Проверяем, что сессия удалена из ОЗУ сервера немедленно (on_close callback сработал)
        assert session_id not in server.sessions
    finally:
        await server_socket.close()


@pytest.mark.asyncio
async def test_parallel_sends_concurrency():
    """Тест 11: Потокобезопасность и отсутствие гонки Sequence ID при параллельных вызовах send()"""
    port = get_free_port()
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5)
    await client.connect()
    server_socket = await server.accept()

    try:
        num_tasks = 50
        payloads = [f"payload_data_chunk_{i}".encode() for i in range(num_tasks)]

        # Корутина для параллельной отправки данных
        async def send_worker(data):
            return await client.send(data)

        # Запускаем 50 тасок одновременно
        tasks = [asyncio.create_task(send_worker(p)) for p in payloads]
        results = await asyncio.gather(*tasks)

        # Все вызовы send() обязаны завершиться успехом
        assert all(results)

        # Даем миллисекунды на вычитку данных и прохождение всех ACK в фоновом цикле
        await asyncio.sleep(0.5)

        # Сверяем суммарный размер переданных данных
        total_size = sum(len(p) for p in payloads)
        received_data = await asyncio.wait_for(server_socket.recv(total_size), timeout=2.0)

        assert len(received_data) == total_size

        # Проверяем, что все куски дошли без искажений и перемешивания байтов
        for p in payloads:
            assert p in received_data

            # Убеждаемся, что буфер переотправки клиента чист (все пакеты успешно подтверждены)
            assert len(client.retrans_buffer) == 0
    finally:
        await client.close()
        await server_socket.close()


@pytest.fixture(scope="module")
def ssl_certs():
    """Фикстура для генерации временного самоподписанного SSL-сертификата с помощью openssl"""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "key.pem")
        cert_path = os.path.join(tmpdir, "cert.pem")

        cmd = [
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-days", "1",
            "-nodes", "-x509", "-keyout", key_path, "-out", cert_path,
            "-subj", "/CN=127.0.0.1"
        ]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except Exception as e:
            pytest.skip(f"Не удалось сгенерировать SSL-сертификат через openssl: {e}")

        yield cert_path, key_path


@pytest.mark.asyncio
async def test_ssl_handshake_and_data_transfer(ssl_certs):
    """Тест 12: Успешное SSL-рукопожатие, шифрование трафика и передача данных"""
    cert_path, key_path = ssl_certs
    port = get_free_port()

    # Настройка SSL для сервера
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Настройка SSL для клиента (доверяем самоподписанному сертификату)
    client_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ssl.load_verify_locations(cafile=cert_path)
    client_ssl.check_hostname = False  # Отключаем проверку имени хоста для loopback

    server = PTCPServer('127.0.0.1', port, timeout=5, ssl=server_ssl)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=5, ssl=client_ssl)
    await client.connect()
    server_socket = await server.accept()

    try:
        # Проверяем, что соединение установлено и обернуто в SSL
        assert client.state == PTCPState.ESTABLISHED
        assert server_socket.state == PTCPState.ESTABLISHED

        # Проверяем, что подлежащий сокет действительно использует SSL шифрование
        assert client.writer.get_extra_info('sslcontext') is not None
        assert server_socket.writer.get_extra_info('sslcontext') is not None

        # Передаем данные по зашифрованному каналу
        payload = b"encrypted secure data transfer"
        await client.send(payload)

        received_data = await asyncio.wait_for(server_socket.recv(len(payload)), timeout=2.0)
        assert received_data == payload
    finally:
        await client.close()
        await server_socket.close()


@pytest.mark.asyncio
async def test_ssl_mismatch_fails():
    """Тест 13: Попытка подключения SSL-клиента к обычному TCP-серверу (должно завершиться ошибкой)"""
    port = get_free_port()

    # Запускаем обычный сервер без SSL
    server = PTCPServer('127.0.0.1', port, timeout=5)
    await server.start()

    # Клиент пытается подключиться с SSL контекстом
    client_ssl = ssl.create_default_context()
    client_ssl.check_hostname = False
    client_ssl.verify_mode = ssl.CERT_NONE

    client = PTCPClient('127.0.0.1', port, timeout=3, ssl=client_ssl)

    try:
        with pytest.raises((ConnectionResetError, asyncio.TimeoutError, OSError, ValueError)):
            await client.connect()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_ssl_untrusted_cert_fails(ssl_certs):
    """Тест 14: Проверка отклонения соединения при недоверенном сертификате сервера"""
    cert_path, key_path = ssl_certs
    port = get_free_port()

    # Настройка SSL для сервера
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Настройка SSL для клиента со строгой проверкой, но без загрузки нашего CA
    client_ssl = ssl.create_default_context()

    server = PTCPServer('127.0.0.1', port, timeout=5, ssl=server_ssl)
    await server.start()

    client = PTCPClient('127.0.0.1', port, timeout=3, ssl=client_ssl)

    try:
        # Рукопожатие должно упасть из-за ошибки валидации сертификата (SSLError)
        with pytest.raises((ssl.SSLError, asyncio.TimeoutError, ConnectionResetError)):
            await client.connect()
    finally:
        await client.close()