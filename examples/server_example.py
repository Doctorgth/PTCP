import asyncio
import logging
from aioptcp import PTCPServer, PTCPSocket

# Настройка логирования для наглядности процессов под капотом
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - SERVER: %(message)s')


async def handle_client(session: PTCPSocket):
    """
    Обработчик отдельной APTCP-сессии.
    Работает в бесконечном цикле, пока логический сокет активен.
    """
    session_id_hex = session.session_id.hex()
    logging.info(f"Логическая сессия установлена: {session_id_hex}")
    
    try:
        while True:
            # Чтение данных из APTCP сокета.
            # Если сеть пропадет, вызов заблокируется и будет ждать переподключения.
            data = await session.recv(1024)
            if not data:
                logging.info(f"Сессия {session_id_hex} штатно закрыта удаленной стороной (получен EOF).")
                break

            message = data.decode(errors='ignore')
            logging.info(f"Получено от [{session_id_hex[:8]}...]: {message}")

            # Отправка эхо-ответа обратно в логический канал
            response = f"Echo: {message}"
            success = await session.send(response.encode())
            if not success:
                logging.warning(f"Не удалось отправить данные в сессию {session_id_hex} (соединение CLOSED).")
                break

    except asyncio.CancelledError:
        logging.info(f"Задача обслуживания сессии {session_id_hex} была принудительно отменена.")
    except Exception as e:
        logging.error(f"Ошибка при работе с сессией {session_id_hex}: {e}")
    finally:
        logging.info(f"Закрытие ресурсов сессии {session_id_hex}...")
        await session.close()


async def main():
    host = '0.0.0.0'
    port = 8888
    
    # Таймаут сессии — 30 секунд. Если физическое TCP-соединение оборвется,
    # сервер будет удерживать сессию в ОЗУ еще 30 секунд, ожидая кадра RESUME.
    server = PTCPServer(host, port, timeout=30)
    await server.start()
    logging.info(f"APTCP-сервер запущен на {host}:{port}")

    try:
        while True:
            # Ожидаем успешного хэндшейка с новым (или переподключившимся) клиентом
            session = await server.accept()
            # Передаем обслуживание сессии в фоновую задачу
            asyncio.create_task(handle_client(session))
    except asyncio.CancelledError:
        logging.info("Слушающий цикл сервера остановлен.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Сервер завершил работу по сигналу прерывания.")