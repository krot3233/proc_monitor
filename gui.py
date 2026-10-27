import queue
import sqlite3
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import customtkinter
import psutil

from config import DB_NAME
from db import add_to_whitelist, init_db, remove_from_whitelist
from monitor import build_info, monitor_loop
from scoring import score_process


customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")


class AntivirusApp(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title("Система мониторинга процессов")
        self.geometry("1100x700")
        self.minsize(900, 600)

        init_db()
        self.stop_event = None
        self.monitor_thread = None
        self.process_scan_running = False
        self.process_queue = queue.Queue()

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.update_ui()

    def create_widgets(self):
        # Тут сверху показываем состояние мониторинга и кнопку запуска.
        top_frame = customtkinter.CTkFrame(self)
        top_frame.pack(fill="x", padx=16, pady=(16, 8))

        title = customtkinter.CTkLabel(
            top_frame,
            text="Система мониторинга процессов",
            font=customtkinter.CTkFont(size=22, weight="bold"),
        )
        title.pack(side="left", padx=16, pady=14)

        self.status_label = customtkinter.CTkLabel(
            top_frame,
            text="Статус: Остановлен",
            text_color="#ff5c5c",
        )
        self.status_label.pack(side="left", padx=12)

        self.monitor_button = customtkinter.CTkButton(
            top_frame,
            text="Запустить мониторинг",
            command=self.toggle_monitoring,
        )
        self.monitor_button.pack(side="right", padx=16, pady=10)

        self.tabs = customtkinter.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.events_tab = self.tabs.add("События")
        self.processes_tab = self.tabs.add("Активные процессы")
        self.whitelist_tab = self.tabs.add("Белый список")

        self.events_text = customtkinter.CTkTextbox(self.events_tab)
        self.events_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.events_text.configure(state="disabled")

        self.create_process_table()
        self.create_whitelist_table()

    def create_process_table(self):
        # Тут таблица показывает процессы и их текущую оценку.
        table_frame = customtkinter.CTkFrame(self.processes_tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.process_tree = self.create_tree(
            table_frame,
            ("pid", "name", "exe", "score"),
            ("PID", "Имя", "Путь", "Оценка"),
            (80, 180, 640, 90),
        )

        buttons = customtkinter.CTkFrame(self.processes_tab, fg_color="transparent")
        buttons.pack(fill="x", padx=10, pady=(0, 10))
        customtkinter.CTkButton(
            buttons,
            text="Обновить список",
            command=self.request_process_scan,
        ).pack(side="left", padx=(0, 8))
        customtkinter.CTkButton(
            buttons,
            text="Добавить в белый список",
            command=self.add_selected_to_whitelist,
        ).pack(side="left")

    def create_whitelist_table(self):
        # Тут показываем программы, которые пользователь исключил из проверки.
        table_frame = customtkinter.CTkFrame(self.whitelist_tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.whitelist_tree = self.create_tree(
            table_frame,
            ("name", "exe"),
            ("Имя", "Путь"),
            (240, 750),
        )

        customtkinter.CTkButton(
            self.whitelist_tab,
            text="Удалить из белого списка",
            command=self.remove_selected_from_whitelist,
        ).pack(anchor="w", padx=10, pady=(0, 10))

    def create_tree(self, parent, columns, headings, widths):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#242424",
            foreground="white",
            fieldbackground="#242424",
            rowheight=26,
        )
        style.configure(
            "Treeview.Heading",
            background="#343638",
            foreground="white",
        )
        style.map("Treeview", background=[("selected", "#1f6aa5")])

        tree_frame = tk.Frame(parent, bg="#242424")
        tree_frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=60, anchor="w")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return tree

    def toggle_monitoring(self):
        if self.stop_event is None or self.stop_event.is_set():
            self.stop_event = threading.Event()
            self.monitor_thread = threading.Thread(
                target=monitor_loop,
                args=(self.stop_event,),
                daemon=True,
            )
            self.monitor_thread.start()
            self.status_label.configure(
                text="Статус: Работает",
                text_color="#4caf50",
            )
            self.monitor_button.configure(
                text="Остановить мониторинг",
                fg_color="#b33a3a",
                hover_color="#8f2d2d",
            )
        else:
            self.stop_event.set()
            self.status_label.configure(
                text="Статус: Остановлен",
                text_color="#ff5c5c",
            )
            self.monitor_button.configure(
                text="Запустить мониторинг",
                fg_color="#1f6aa5",
                hover_color="#144870",
            )

    def request_process_scan(self):
        if self.process_scan_running:
            return

        self.process_scan_running = True
        thread = threading.Thread(target=self.scan_processes, daemon=True)
        thread.start()

    def scan_processes(self):
        # Тут отдельно от окна собираем процессы, чтобы таблица не подвисала.
        rows = []
        for proc in psutil.process_iter():
            info = build_info(proc)
            if info is None:
                continue
            score, _reasons = score_process(info)
            rows.append((info.pid, info.name, info.exe, score))

        self.process_queue.put(rows)

    def update_process_table(self, rows):
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)

        for pid, name, exe, score in rows:
            self.process_tree.insert(
                "",
                "end",
                iid=str(pid),
                values=(pid, name, exe, score),
            )

    def add_selected_to_whitelist(self):
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showwarning("Белый список", "Сначала выберите процесс.")
            return

        values = self.process_tree.item(selected[0], "values")
        try:
            add_to_whitelist(values[1], values[2])
        except sqlite3.Error:
            pass
        self.load_whitelist()

    def remove_selected_from_whitelist(self):
        selected = self.whitelist_tree.selection()
        if not selected:
            messagebox.showwarning("Белый список", "Сначала выберите программу.")
            return

        values = self.whitelist_tree.item(selected[0], "values")
        try:
            remove_from_whitelist(values[0], values[1])
        except sqlite3.Error:
            pass
        self.load_whitelist()

    def load_events(self):
        events = []
        conn = None
        try:
            conn = sqlite3.connect(DB_NAME)
            events = conn.execute(
                "SELECT ts, pid, name, rule, score FROM events "
                "ORDER BY id DESC LIMIT 200"
            ).fetchall()
        except sqlite3.Error:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass

        self.events_text.configure(state="normal")
        self.events_text.delete("1.0", "end")
        for timestamp, pid, name, rule, score in reversed(events):
            self.events_text.insert(
                "end",
                f"[{timestamp}] {name} ({pid}) | Оценка: {score} | Причина: {rule}\n",
            )
        self.events_text.see("end")
        self.events_text.configure(state="disabled")

    def load_whitelist(self):
        entries = []
        conn = None
        try:
            conn = sqlite3.connect(DB_NAME)
            entries = conn.execute(
                "SELECT name, exe FROM whitelist ORDER BY name"
            ).fetchall()
        except sqlite3.Error:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass

        for item in self.whitelist_tree.get_children():
            self.whitelist_tree.delete(item)
        for index, (name, exe) in enumerate(entries):
            self.whitelist_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(name, exe),
            )

    def update_ui(self):
        self.load_events()
        self.load_whitelist()

        try:
            rows = self.process_queue.get_nowait()
        except queue.Empty:
            rows = None
        if rows is not None:
            self.update_process_table(rows)
            self.process_scan_running = False

        self.request_process_scan()
        self.after(2000, self.update_ui)

    def close_app(self):
        if self.stop_event is not None:
            self.stop_event.set()
        self.destroy()


if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()
