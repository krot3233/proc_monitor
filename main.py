import logging
from logging.handlers import RotatingFileHandler

from config import LOG_NAME
from gui import AntivirusApp


if __name__ == "__main__":
    # Ограничиваем размер лога и оставляем несколько старых файлов.
    log_handler = RotatingFileHandler(
        LOG_NAME,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[log_handler],
    )
    app = AntivirusApp()
    app.mainloop()
