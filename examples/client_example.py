import asyncio
import logging
from aioptcp import PTCPClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - CLIENT: %(message)s')


async def send_loop(client: PTCPClient):
    """Цикл периодической генерации и отправки сообщений."""
    counter = 0
    try:
        # Проверяем, что логический сокет не закрыт принудительно
        while client.state != client.state.CLOSED:
            counter += 1
            payload = f"Message #{counter}"
            logging.info(f"Попытка отправки: '{payload}'")
            
            # Отправка буферизуется. При падении сети вызов завершится успешно (данные уйдут в буфер),
            # но если буфер переполняется (больше лимита), вызов заблокируется до очистки.
            success = await client.send(payload.encode())
            if not success:
                logging.warning("Отправка не удалась: логический сокет закрыт.")
                break
                
            await asyncio.sleep(3)
    except asyncio.CancelledError:
        pass


async def recv_loop(client: PTCPClient):
    """Цикл непрерывного чтения ответов от сервера."""
    try:
        while client.state != client.state.CLOSED:
            # Вызов блокируется до прихода пакета. При обрыве физической связи
            # метод не генерирует ошибок типа ConnectionResetError, а просто ждет реконнекта.
            data = await client.recv(1024)
            if not data:
                logging.info("Получен сигнал EOF. Сервер закрыл логическую сессию.")
                break
                
            logging.info(f"Получен ответ: '{data.decode(errors='ignore')}'")
    except asyncio.CancelledError:
        pass


async def main():
    host = '127.0.0.1'
    port = 8888
    
    # Инициализация клиента. В случае обрыва сети клиент будет фоном пытаться
    # восстановить связь в течение 30 секунд.
    client = PTCPClient(host, port, timeout=30)
    
    logging.info(f"Попытка первичного подключения к APTCP-серверу {host}:{port}...")
    try:
        await client.connect()
        logging.info(f"Логическое соединение установлено. Session ID: {client.session_id.hex()}")
    except Exception as e:
        logging.error(f"Не удалось установить первичное подключение: {e}")
        return

    # Запускаем конкурентные задачи на чтение и запись
    send_task = asyncio.create_task(send_loop(client))
    recv_task = asyncio.create_task(recv_loop(client))

    try:
        # Ожидаем завершения хотя бы одного цикла (например, при получении EOF от сервера)
        done, pending = await asyncio.wait(
            {send_task, recv_task},
            return_when=asyncio.FIRST_COMPLETED
        )
    except asyncio.CancelledError:
        pass
    finally:
        # Корректно завершаем фоновые циклы и закрываем сокет
        send_task.cancel()
        recv_task.cancel()
        await asyncio.gather(send_task, recv_task, return_exceptions=True)
        
        logging.info("Инициирование закрытия APTCP-сессии...")
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Клиент завершил работу.")