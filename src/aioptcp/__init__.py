import asyncio
import struct
import hashlib
import hmac
import secrets
import logging
import time
from enum import IntEnum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - PTCP: %(message)s')

# Константы для Diffie-Hellman (RFC 3526 2048-bit MODP Group)
DH_P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
           '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
           '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
           'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
           '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
           '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
           'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
           '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
DH_G = 2


class PTCPState(IntEnum):
    CONNECTING = 1
    ESTABLISHED = 2
    DISCONNECTED_WAITING = 3
    RESUMING = 4
    CLOSED = 5


class FrameType(IntEnum):
    HANDSHAKE_INIT = 1
    HANDSHAKE_ACK = 2
    DATA = 3
    ACK = 4
    RESUME = 5
    RESUME_ACK = 6
    CLOSE = 7


class PTCPSocket:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.state = PTCPState.CLOSED

        self.session_id = b''
        self.session_key = b''

        self.reader = None
        self.writer = None

        self.send_seq = 0
        self.recv_seq = 0

        # Лимиты для защиты от бесконечного потребления памяти
        self.buffer_size_limit = 5 * 1024 * 1024  # 5 MB лимит буферов
        self.current_retrans_size = 0
        self.retrans_buffer = {}
        self.app_recv_buffer = bytearray()

        self.recv_event = asyncio.Event()
        self.drain_event = asyncio.Event()  # Событие для Backpressure на отправку
        self.drain_event.set()

        # Событие для событийного (не polling) Flow Control на чтение
        self.recv_drain_event = asyncio.Event()
        self.recv_drain_event.set()

        # Замок блокировки для предотвращения интерливинга (порчи) кадров при конкурентной отправке
        self.write_lock = asyncio.Lock()

        # Замок сериализации вызовов send для предотвращения гонки номеров Sequence ID
        self.send_lock = asyncio.Lock()

        # Событие окончания фазы подключения (заменяет медленный polling)
        self.connect_event = asyncio.Event()

        # Коллбек для уведомления сервера об удалении сессии при закрытии
        self.on_close = None

        self.bg_task = None
        self.reconnect_event = asyncio.Event()
        self.disconnect_time = time.time()

    def _cancel_bg_task(self):
        """Останавливает старую задачу чтения для предотвращения дублирования"""
        if self.bg_task and not self.bg_task.done():
            self.bg_task.cancel()

    def _pack_frame(self, ftype: FrameType, payload: bytes = b'') -> bytes:
        length = 1 + len(payload)
        return struct.pack('!IB', length, ftype.value) + payload

    async def _send_frame(self, ftype: FrameType, payload: bytes = b''):
        if self.writer is None or self.state in (PTCPState.DISCONNECTED_WAITING, PTCPState.CLOSED):
            return False
        async with self.write_lock:
            try:
                frame = self._pack_frame(ftype, payload)
                self.writer.write(frame)
                await self.writer.drain()
                return True
            except Exception:
                # Вызываем отключение вне блокировки, чтобы избежать дедлоков при реконнекте
                loop = asyncio.get_running_loop()
                loop.call_soon(self._handle_disconnect)
                return False

    async def send(self, data: bytes) -> bool:
        """Неблокирующая отправка данных (API приложения)"""
        if self.state == PTCPState.CLOSED:
            return False

        # Если интернета нет или канал забит, ждем пока буфер разгрузится (Backpressure)
        await self.drain_event.wait()

        # Сериализуем выделение Sequence ID и буферизацию
        async with self.send_lock:
            self.send_seq += 1
            self.retrans_buffer[self.send_seq] = data
            self.current_retrans_size += len(data)

            # Если превысили лимит - блокируем будущие вызовы send до прихода ACK
            if self.current_retrans_size >= self.buffer_size_limit:
                self.drain_event.clear()

            payload = struct.pack('!Q', self.send_seq) + data

            if self.state == PTCPState.ESTABLISHED:
                await self._send_frame(FrameType.DATA, payload)

        return True

    async def recv(self, size: int) -> bytes:
        """Чтение данных (API приложения)"""
        while not self.app_recv_buffer and self.state != PTCPState.CLOSED:
            self.recv_event.clear()
            await self.recv_event.wait()

        if not self.app_recv_buffer and self.state == PTCPState.CLOSED:
            return b''

        ret = bytes(self.app_recv_buffer[:size])
        self.app_recv_buffer = self.app_recv_buffer[size:]

        # Если буфер приема разгрузился ниже лимита — возобновляем чтение из сокета
        if len(self.app_recv_buffer) < self.buffer_size_limit and not self.recv_drain_event.is_set():
            self.recv_drain_event.set()

        return ret

    async def close(self, send_close_frame: bool = True):
        if self.state != PTCPState.CLOSED:
            # Отправляем CLOSE по сети только если мы сами являемся инициатором закрытия
            if send_close_frame:
                await self._send_frame(FrameType.CLOSE)
            self.state = PTCPState.CLOSED
            # Уведомляем сервер об окончательном закрытии сессии для очистки памяти
            if self.on_close:
                self.on_close()
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
        # Разблокируем все ожидающие события во избежание зависания задач
        self.recv_drain_event.set()
        self.recv_event.set()
        self.connect_event.set()

    def _handle_disconnect(self):
        # Переводим в ожидание реконнекта только реально установленные сессии
        if self.state in (PTCPState.ESTABLISHED, PTCPState.RESUMING):
            logging.warning(f"Physical connection lost. Waiting {self.timeout}s for reconnect...")
            self.state = PTCPState.DISCONNECTED_WAITING
            self.disconnect_time = time.time()  # Фиксируем время обрыва
            self.reconnect_event.set()
            self.recv_drain_event.set()  # Будим фоновое чтение, если оно заблокировано Flow Control

        # Для CONNECTING состояние не меняем, чтобы цикл реконнекта сделал чистую попытку заново

        # Гарантированно закрываем сокеты во избежание утечек
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.writer = None
        self.reader = None

    async def _read_loop(self):
        """Фоновое чтение. Умирает корректно при обрыве."""
        try:
            while self.state not in (PTCPState.CLOSED, PTCPState.DISCONNECTED_WAITING):
                # Избавляемся от polling: ждем события, что буфер приема имеет свободное место
                await self.recv_drain_event.wait()
                if self.state in (PTCPState.CLOSED, PTCPState.DISCONNECTED_WAITING):
                    break

                length_bytes = await self.reader.readexactly(4)
                length = struct.unpack('!I', length_bytes)[0]
                frame_data = await self.reader.readexactly(length)

                ftype = frame_data[0]
                payload = frame_data[1:]
                await self._process_frame(ftype, payload)

        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionAbortedError):
            self._handle_disconnect()
        except asyncio.CancelledError:
            pass  # Задача была отменена при реконнекте
        except Exception as e:
            self._handle_disconnect()

    async def _process_frame(self, ftype: int, payload: bytes):
        if ftype == FrameType.DATA:
            seq = struct.unpack('!Q', payload[:8])[0]
            data = payload[8:]

            # Обеспечиваем гарантированную непрерывность и строгий порядок пакетов
            if seq == self.recv_seq + 1:
                self.recv_seq = seq
                self.app_recv_buffer.extend(data)

                # Если буфер приема переполнен — останавливаем чтение
                if len(self.app_recv_buffer) >= self.buffer_size_limit:
                    self.recv_drain_event.clear()

                self.recv_event.set()

            # Отвечаем ACK-ом в любом случае (даже на дубликаты, чтобы удаленная сторона очистила буфер)
            await self._send_frame(FrameType.ACK, struct.pack('!Q', self.recv_seq))

        elif ftype == FrameType.ACK:
            ack_seq = struct.unpack('!Q', payload[:8])[0]
            keys_to_delete = [k for k in self.retrans_buffer.keys() if k <= ack_seq]
            for k in keys_to_delete:
                self.current_retrans_size -= len(self.retrans_buffer[k])
                del self.retrans_buffer[k]

            # Разблокируем отправку, так как место в буфере освободилось
            if self.current_retrans_size < self.buffer_size_limit and not self.drain_event.is_set():
                self.drain_event.set()


        elif ftype == FrameType.CLOSE:

            logging.info("Received CLOSE from peer.")

            # Мы получатели CLOSE: закрываем ресурсы, но не шлем эхо-кадр обратно

            await self.close(send_close_frame=False)

class PTCPClient(PTCPSocket):
    def __init__(self, host, port, timeout=30):
        super().__init__(timeout)
        self.host = host
        self.port = port
        self.dh_private = secrets.randbits(2048)

    async def connect(self):
        self.state = PTCPState.CONNECTING
        self.connection_start_time = time.time()  # Чистый старт первичного подключения
        self.connect_event.clear()
        asyncio.create_task(self._maintain_connection())
        # Ждем асинхронного события вместо периодического сна (polling)
        await self.connect_event.wait()
        if self.state == PTCPState.CLOSED:
            raise TimeoutError("Handshake timed out / Server unavailable")

    async def _maintain_connection(self):
        self.disconnect_time = time.time()

        while self.state != PTCPState.CLOSED:
            if self.state in (PTCPState.CONNECTING, PTCPState.DISCONNECTED_WAITING, PTCPState.RESUMING):

                # Контроль таймаута для первичного подключения (CONNECTING)
                if self.state == PTCPState.CONNECTING:
                    if time.time() - self.connection_start_time > self.timeout:
                        logging.error("Initial connection timeout. Closing socket.")
                        await self.close()
                        break

                # Контроль таймаута для восстановления сессии (DISCONNECTED_WAITING, RESUMING)
                elif self.state in (PTCPState.DISCONNECTED_WAITING, PTCPState.RESUMING):
                    if time.time() - self.disconnect_time > self.timeout:
                        logging.error("Session timeout. Closing socket.")
                        await self.close()
                        break

                try:
                    self.reader, self.writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, self.port), timeout=3.0
                    )

                    if self.state == PTCPState.CONNECTING:
                        client_pub = pow(DH_G, self.dh_private, DH_P)
                        client_pub_bytes = client_pub.to_bytes(256, 'big')
                        await self._send_frame(FrameType.HANDSHAKE_INIT, client_pub_bytes)

                        # Защищаем чтение хэндшейка таймаутом во избежание вечной блокировки
                        length_bytes = await asyncio.wait_for(self.reader.readexactly(4), timeout=5.0)
                        length = struct.unpack('!I', length_bytes)[0]
                        frame_data = await asyncio.wait_for(self.reader.readexactly(length), timeout=5.0)

                        if frame_data[0] == FrameType.HANDSHAKE_ACK:
                            # Защита от поврежденных/обрезанных пакетов
                            if len(frame_data) < 273:
                                raise ValueError(f"Malformed HANDSHAKE_ACK, too short: {len(frame_data)}")

                            self.session_id = frame_data[1:17]
                            server_pub_bytes = frame_data[17:273]

                            server_pub = int.from_bytes(server_pub_bytes, 'big')
                            shared_secret = pow(server_pub, self.dh_private, DH_P)
                            self.session_key = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()

                            self.state = PTCPState.ESTABLISHED
                            logging.info(f"Connected. Session: {self.session_id.hex()}")
                            self.connect_event.set()  # Будим блокировку метода connect()
                            self._cancel_bg_task()
                            self.bg_task = asyncio.create_task(self._read_loop())
                        else:
                            raise ValueError(f"Unexpected frame type during handshake: {frame_data[0]}")

                    elif self.state in (PTCPState.DISCONNECTED_WAITING, PTCPState.RESUMING):
                        self.state = PTCPState.RESUMING

                        nonce = secrets.token_bytes(8)
                        signature = hmac.new(self.session_key, self.session_id + nonce, hashlib.sha256).digest()
                        resume_payload = self.session_id + nonce + signature + struct.pack('!Q', self.recv_seq)

                        await self._send_frame(FrameType.RESUME, resume_payload)

                        length_bytes = await asyncio.wait_for(self.reader.readexactly(4), timeout=2.0)
                        length = struct.unpack('!I', length_bytes)[0]
                        frame_data = await asyncio.wait_for(self.reader.readexactly(length), timeout=2.0)

                        if frame_data[0] == FrameType.RESUME_ACK:
                            # Защита от обрезанных пакетов resume_ack
                            if len(frame_data) < 9:
                                raise ValueError(f"Malformed RESUME_ACK, too short: {len(frame_data)}")

                            server_recv_seq = struct.unpack('!Q', frame_data[1:9])[0]

                            # Очищаем буфер от пакетов, которые сервер успел получить до обрыва
                            keys_to_delete = [k for k in self.retrans_buffer.keys() if k <= server_recv_seq]
                            for k in keys_to_delete:
                                self.current_retrans_size -= len(self.retrans_buffer[k])
                                del self.retrans_buffer[k]

                            if self.current_retrans_size < self.buffer_size_limit and not self.drain_event.is_set():
                                self.drain_event.set()

                            self.state = PTCPState.ESTABLISHED
                            logging.info("Session Resumed Successfully!")
                            self._cancel_bg_task()
                            self.bg_task = asyncio.create_task(self._read_loop())

                            # Отправляем только то, что сервер реально не получил
                            for seq, data in sorted(self.retrans_buffer.items()):
                                payload = struct.pack('!Q', seq) + data
                                await self._send_frame(FrameType.DATA, payload)
                        else:
                            raise ValueError(f"Unexpected frame type during resume: {frame_data[0]}")


                except Exception as e:
                    # При любом сбое ХЭНДШЕЙКА закрываем сокет, предотвращая утечку файловых дескрипторов ОС
                    if self.writer:
                        try:
                            self.writer.close()
                            await self.writer.wait_closed()
                        except Exception:
                            pass
                    self.writer = None

                    self.reader = None

                    # Если сорвалось при возобновлении — возвращаемся в режим ожидания
                    if self.state == PTCPState.RESUMING:
                        self.state = PTCPState.DISCONNECTED_WAITING

                    # Логируем процесс, чтобы видеть, что клиент делает
                    time_left = int(self.timeout - (time.time() - self.disconnect_time))
                    logging.info(f"Network down / Reconnect failed. Retrying... ({time_left}s left)")
                    await asyncio.sleep(1)
            else:
                await self.reconnect_event.wait()
                self.reconnect_event.clear()


class PTCPServer:
    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sessions = {}
        self.app_connections = asyncio.Queue()

    async def start(self):
        server = await asyncio.start_server(self._handle_client, self.host, self.port)
        logging.info(f"PTCP Server listening on {self.host}:{self.port}")
        asyncio.create_task(server.serve_forever())
        # Запуск сборщика мусора для зависших сессий
        asyncio.create_task(self._garbage_collector())

    async def accept(self) -> PTCPSocket:
        return await self.app_connections.get()

    async def _garbage_collector(self):
        """Очищает сервер от сессий, которые не смогли восстановиться за timeout секунд"""
        while True:
            await asyncio.sleep(5)
            now = time.time()
            dead_sessions = []
            for sid, conn in self.sessions.items():
                if conn.state == PTCPState.DISCONNECTED_WAITING:
                    if now - conn.disconnect_time > conn.timeout:
                        dead_sessions.append(sid)

            for sid in dead_sessions:
                conn = self.sessions.get(sid)
                if conn and conn.state == PTCPState.DISCONNECTED_WAITING:
                    if now - conn.disconnect_time > conn.timeout:
                        logging.info(f"Session {sid.hex()} timed out. Cleaning up.")
                        # Исключаем Race Condition: удаляем из реестра ДО того, как отдадим управление через await
                        self.sessions.pop(sid, None)
                        await conn.close()

    async def _handle_client(self, reader, writer):
        try:
            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            length = struct.unpack('!I', length_bytes)[0]
            # Защищаем чтение тела хэндшейка таймаутом во избежание вечного зависания
            frame_data = await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
            ftype = frame_data[0]
            payload = frame_data[1:]

            if ftype == FrameType.HANDSHAKE_INIT:
                # Защита от кривых пакетов рукопожатия
                if len(payload) < 256:
                    raise ValueError(f"HANDSHAKE_INIT payload too short: {len(payload)}")

                client_pub_bytes = payload[:256]
                client_pub = int.from_bytes(client_pub_bytes, 'big')

                dh_private = secrets.randbits(2048)
                server_pub = pow(DH_G, dh_private, DH_P)
                server_pub_bytes = server_pub.to_bytes(256, 'big')

                shared_secret = pow(client_pub, dh_private, DH_P)
                session_key = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()
                session_id = secrets.token_bytes(16)

                conn = PTCPSocket(self.timeout)
                conn.session_id = session_id
                conn.session_key = session_key
                conn.reader = reader
                conn.writer = writer
                conn.state = PTCPState.ESTABLISHED

                # Удаляем сессию из реестра ОЗУ сервера при штатном закрытии (решает проблему утечки памяти)
                conn.on_close = lambda: self.sessions.pop(session_id, None)

                self.sessions[session_id] = conn
                # Проверяем, ушел ли HANDSHAKE_ACK клиенту
                success = await conn._send_frame(FrameType.HANDSHAKE_ACK, session_id + server_pub_bytes)
                if not success:
                    # Клиент отвалился, удаляем сессию и закрываем сокет во избежание утечки
                    self.sessions.pop(session_id, None)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return

                conn._cancel_bg_task()
                conn.bg_task = asyncio.create_task(conn._read_loop())
                await self.app_connections.put(conn)
                logging.info(f"New session generated: {session_id.hex()}")

            elif ftype == FrameType.RESUME:
                # Проверяем корректность границ полезной нагрузки для RESUME
                if len(payload) < 64:
                    raise ValueError(f"RESUME payload too short: {len(payload)}")

                session_id = payload[:16]
                nonce = payload[16:24]
                signature = payload[24:56]
                client_recv_seq = struct.unpack('!Q', payload[56:64])[0]
                if session_id in self.sessions:
                    conn = self.sessions[session_id]
                    expected_sig = hmac.new(conn.session_key, session_id + nonce, hashlib.sha256).digest()

                    if hmac.compare_digest(expected_sig, signature):

                        if conn.writer:
                            conn.writer.close()
                            try:
                                # Ждем полного системного закрытия старого канала перед биндингом нового
                                await conn.writer.wait_closed()
                            except Exception:
                                pass
                        conn.reader = reader
                        conn.writer = writer
                        conn.state = PTCPState.ESTABLISHED

                        # Сервер отправляет клиенту номер последнего принятого пакета
                        keys_to_delete = [k for k in conn.retrans_buffer.keys() if k <= client_recv_seq]
                        for k in keys_to_delete:
                            conn.current_retrans_size -= len(conn.retrans_buffer[k])
                            del conn.retrans_buffer[k]

                        # Восстанавливаем Backpressure-событие отправки сервера, если буфер разгрузился
                        if conn.current_retrans_size < conn.buffer_size_limit and not conn.drain_event.is_set():
                            conn.drain_event.set()

                        # Сервер отправляет клиенту номер последнего принятого пакета
                        await conn._send_frame(FrameType.RESUME_ACK, struct.pack('!Q', conn.recv_seq))

                        conn._cancel_bg_task()
                        conn.bg_task = asyncio.create_task(conn._read_loop())

                        # Пересылаем только те данные из буфера, которые клиент еще не успел получить
                        for seq, data in sorted(conn.retrans_buffer.items()):
                            if seq > client_recv_seq:
                                out_payload = struct.pack('!Q', seq) + data
                                await conn._send_frame(FrameType.DATA, out_payload)
                        logging.info(f"Session {session_id.hex()} resumed.")
                    else:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                else:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            else:
                # Защита от утечки сокетов: закрываем соединение, если пришел неверный тип первого кадра
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception as e:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass