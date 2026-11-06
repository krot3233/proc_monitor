import queue
import logging
import os
import sqlite3
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import customtkinter
import psutil

from config import DB_NAME, WARNING_SCALE
from db import add_to_whitelist, get_file_hash, init_db, remove_from_whitelist
from monitor import build_info, monitor_loop
from scoring import clear_score_cache, score_process


customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")
logger = logging.getLogger(__name__)


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
        self.process_scan_requested = False
        self.process_scan_visible = set()
        self.process_scan_current = set()
        self.monitor_restart_requested = False
        self.process_group_ids = {}
        self.process_group_members = {}
        # Эти словари отражают уже показанные данные и помогают обновлять только разницу.
        self.tree_item_state = {}
        self.tree_children_order = {}
        self.next_process_group_id = 1
        self.process_table_update_pending = False
        self.process_queue = queue.Queue()
        self.last_events = None
        self.process_scan_interval = 10.0
        self.last_process_scan = 0
        self.last_scroll = 0
        self.database_scan_running = False
        self.database_scan_requested = None
        self.whitelist_add_running = False
        self.row_state = {}
        self.protected_processes = {
            "system",
            "system idle process",
            "csrss.exe",
            "lsass.exe",
            "services.exe",
            "smss.exe",
            "wininit.exe",
            "winlogon.exe",
            "registry",
            "memory compression",
            "dwm.exe",
        }

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.update_ui()
        self.after(100, self.request_database_refresh)

    def create_widgets(self):
        # Статус и кнопка управления монитором остаются видны над вкладками.
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
        self.scan_error_label = customtkinter.CTkLabel(
            top_frame,
            text="",
            text_color="#ff8c42",
        )
        self.scan_error_label.pack(side="left", padx=8)

        self.monitor_button = customtkinter.CTkButton(
            top_frame,
            text="Запустить мониторинг",
            command=self.toggle_monitoring,
        )
        self.monitor_button.pack(side="right", padx=16, pady=10)

        self.tabs = customtkinter.CTkTabview(self, command=self.on_tab_changed)
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
        # В этой таблице одинаковые процессы собираются в группы.
        table_frame = customtkinter.CTkFrame(self.processes_tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.process_tree = self.create_tree(
            table_frame,
            ("pid", "name", "exe", "score"),
            ("PID", "Имя", "Путь", "Оценка"),
            (80, 150, 700, 90),
        )
        self.process_tree.bind("<MouseWheel>", self.on_process_scroll, add="+")
        self.process_tree.bind("<Button-4>", self.on_process_scroll, add="+")
        self.process_tree.bind("<Button-5>", self.on_process_scroll, add="+")

        buttons = customtkinter.CTkFrame(self.processes_tab, fg_color="transparent")
        buttons.pack(fill="x", padx=10, pady=(0, 10))
        customtkinter.CTkButton(
            buttons,
            text="Обновить список",
            command=lambda: self.request_process_scan(force=True),
        ).pack(side="left", padx=(0, 8))
        customtkinter.CTkButton(
            buttons,
            text="Добавить в белый список",
            command=self.add_selected_to_whitelist,
        ).pack(side="left")
        customtkinter.CTkButton(
            buttons,
            text="Завершить процесс",
            command=self.kill_selected_process,
            fg_color="#b33a3a",
            hover_color="#8f2d2d",
        ).pack(side="left", padx=(8, 0))

    def create_whitelist_table(self):
        # Для записей whitelist отдельно показываем, совпадает ли хеш файла.
        table_frame = customtkinter.CTkFrame(self.whitelist_tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.whitelist_tree = self.create_tree(
            table_frame,
            ("name", "exe", "status"),
            ("Имя", "Путь", "Состояние файла"),
            (180, 650, 170),
        )

        customtkinter.CTkButton(
            self.whitelist_tab,
            text="Удалить из белого списка",
            command=self.remove_selected_from_whitelist,
        ).pack(anchor="w", padx=10, pady=(0, 10))

    def create_tree(self, parent, columns, headings, widths):
        # Стиль общий для обеих таблиц, поэтому задаем его только при первом вызове.
        if not getattr(self, "tree_style_ready", False):
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
            self.tree_style_ready = True

        tree_frame = tk.Frame(parent, bg="#242424")
        tree_frame.pack(fill="both", expand=True)
        if columns[0] == "pid":
            tree = ttk.Treeview(
                tree_frame,
                columns=columns,
                show=("tree", "headings"),
            )
            tree.heading("#0", text="")
            tree.column("#0", width=24, minwidth=24, stretch=False)
        else:
            tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=60, anchor="w")

        tree.tag_configure("danger", foreground="#ff4a4a")
        tree.tag_configure("safe", foreground="#4aff4a")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        if columns[0] == "pid":
            self.process_tree_scrollbar = scrollbar
            scrollbar.configure(command=self.scroll_process_tree)
        return tree

    def on_process_scroll(self, _event=None):
        # Пока пользователь листает список, не запускаем новое тяжелое сканирование.
        self.last_scroll = time.monotonic()

    def on_tab_changed(self):
        tab_name = self.tabs.get()
        if tab_name in ("События", "Белый список"):
            self.start_database_read(tab_name)
        elif tab_name == "Активные процессы":
            self.request_process_scan()

    def scroll_process_tree(self, *args):
        self.on_process_scroll()
        self.process_tree.yview(*args)

    def toggle_monitoring(self):
        if self.monitor_thread is not None and self.monitor_thread.is_alive():
            if self.stop_event is not None and self.stop_event.is_set():
                self.monitor_restart_requested = True
                self.status_label.configure(
                    text="Статус: Перезапуск после остановки",
                    text_color="#ff8c42",
                )
                return

            if self.stop_event is not None:
                self.stop_event.set()
            self.status_label.configure(
                text="Статус: Останавливается",
                text_color="#ff8c42",
            )
            self.monitor_button.configure(
                text="Запустить мониторинг",
                fg_color="#1f6aa5",
                hover_color="#144870",
            )
            return

        self.start_monitoring()

    def start_monitoring(self):
        self.monitor_restart_requested = False
        self.stop_event = threading.Event()
        self.monitor_thread = threading.Thread(
            target=monitor_loop,
            args=(self.stop_event, 2.0),
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

    def request_process_scan(self, force=False):
        if self.process_scan_running:
            if force:
                self.process_scan_requested = True
            return

        if not force and time.monotonic() - self.last_process_scan < self.process_scan_interval:
            return
        if not force and time.monotonic() - self.last_scroll < 1.0:
            return

        self.process_scan_running = True
        self.last_process_scan = time.monotonic()
        # Сбор процессов и оценка идут отдельно от Tkinter-потока.
        thread = threading.Thread(target=self.scan_processes, daemon=True)
        thread.start()

    def scan_processes(self):
        # Сначала показываем процессы, а оценки отправляем в очередь по мере расчета.
        completed = False
        self.process_queue.put(("process_scan_started", None))
        infos = []
        try:
            for proc in psutil.process_iter():
                info = build_info(proc)
                if info is None:
                    continue
                infos.append(info)
            completed = True
        except Exception as error:
            self.process_queue.put(("scan_error", str(error)))

        rows = []
        for info in infos:
            rows.append((info.pid, info.create_time, info.name, info.exe, "..."))
        self.process_queue.put(("process_rows", rows))

        try:
            for info in infos:
                try:
                    score, _reasons = score_process(info)
                except Exception:
                    logger.exception(
                        "Не удалось оценить процесс %s (%s)",
                        info.name,
                        info.pid,
                    )
                    score = "Ошибка"

                self.process_queue.put(
                    ("process_score", (info.pid, info.create_time, score))
                )
        except Exception as error:
            self.process_queue.put(("scan_error", str(error)))
        finally:
            self.process_queue.put(("process_scan_done", completed))

    def update_process_row(self, pid, create_time, name, exe, score, update_tree=True):
        item_id = str(pid)
        self.process_scan_current.add(item_id)
        if score == "...":
            tag = ""
        elif isinstance(score, int) and score >= WARNING_SCALE:
            tag = "danger"
        elif score == 0:
            tag = "safe"
        else:
            tag = ""

        values = (str(pid), str(name), str(exe), str(score))
        state = (values, tag, create_time)
        self.row_state[item_id] = state
        if update_tree and self.process_tree.exists(item_id):
            self.process_tree.item(item_id, values=values, tags=(tag,))

    def request_process_table_update(self):
        # Не меняем структуру таблицы, пока пользователь активно прокручивает её.
        if time.monotonic() - self.last_scroll < 1.0:
            if not self.process_table_update_pending:
                self.process_table_update_pending = True
                self.after(250, self.finish_delayed_process_table_update)
            return
        self.render_grouped_process_table()

    def finish_delayed_process_table_update(self):
        self.process_table_update_pending = False
        self.request_process_table_update()

    def render_grouped_process_table(self):
        # Данные прежней отрисовки лежат в Python, поэтому не приходится опрашивать Treeview.
        scroll_position = self.process_tree.yview()[0]
        grouped = {}
        desired_items = set(self.row_state)
        desired_groups = {}
        desired_parents = {}

        for item_id, state in self.row_state.items():
            values = state[0]
            key = (values[1].lower(), values[2].lower())
            grouped.setdefault(key, []).append((item_id, state))

        for key in sorted(grouped):
            items = grouped[key]
            items.sort(key=lambda item: int(item[0]))
            if len(items) > 1:
                group_id = self.process_group_ids.get(key)
                if group_id is None:
                    group_id = "group-" + str(self.next_process_group_id)
                    self.next_process_group_id += 1
                    self.process_group_ids[key] = group_id
                desired_groups[group_id] = (key, items)
                for item_id, _state in items:
                    desired_parents[item_id] = group_id
            else:
                desired_parents[items[0][0]] = ""

        # Сортируем группы и PID; порядок в Treeview меняем только при реальном изменении.
        desired_children = {"": []}
        for key in sorted(grouped):
            items = grouped[key]
            if len(items) > 1:
                group_id = self.process_group_ids[key]
                desired_children[""].append(group_id)
                desired_children[group_id] = [
                    item_id for item_id, _state in items
                ]
            else:
                desired_children[""].append(items[0][0])

        for group_id, (key, items) in desired_groups.items():
            values = [state[0] for _item_id, state in items]
            scores = []
            for row in values:
                try:
                    scores.append(int(row[3]))
                except (TypeError, ValueError):
                    continue
            max_score = max(scores) if scores else None
            tag = "danger" if max_score is not None and max_score >= WARNING_SCALE else ""
            if max_score is None:
                score_text = "Оценка: ..."
            else:
                score_text = f"Макс. оценка: {max_score}"
            group_values = (
                f"Группа ({len(items)})",
                values[0][1],
                values[0][2],
                score_text,
            )
            group_state = (group_values, tag, "")
            old_entry = self.tree_item_state.get(group_id)
            old_state = old_entry[0] if old_entry else None
            was_dangerous = old_state is not None and old_state[1] == "danger"
            if old_state is None:
                self.process_tree.insert(
                    "",
                    "end",
                    iid=group_id,
                    values=group_values,
                    tags=(tag,),
                    open=bool(max_score is not None and max_score >= WARNING_SCALE),
                    text="Группа",
                )
            elif old_state != group_state:
                self.process_tree.item(group_id, values=group_values, tags=(tag,))
            # Не раскрываем группу повторно: пользователь может свернуть ее вручную.
            if (
                old_state is not None
                and max_score is not None
                and max_score >= WARNING_SCALE
                and not was_dangerous
            ):
                self.process_tree.item(group_id, open=True)
            self.tree_item_state[group_id] = (group_state, "")

        for item_id in desired_items:
            state = self.row_state[item_id]
            parent_id = desired_parents[item_id]
            old_entry = self.tree_item_state.get(item_id)
            if old_entry is None:
                self.process_tree.insert(
                    parent_id,
                    "end",
                    iid=item_id,
                    values=state[0],
                    tags=(state[1],),
                    text="",
                )
            elif old_entry[1] != parent_id:
                self.process_tree.move(item_id, parent_id, "end")
                if old_entry[0] != state:
                    self.process_tree.item(
                        item_id,
                        values=state[0],
                        tags=(state[1],),
                    )
            elif old_entry[0] != state:
                self.process_tree.item(item_id, values=state[0], tags=(state[1],))
            self.tree_item_state[item_id] = (state, parent_id)

        desired_tree_items = desired_items | set(desired_groups)
        stale_items = [
            item_id
            for item_id in self.tree_item_state
            if item_id not in desired_tree_items
        ]
        stale_items.sort(key=lambda item_id: item_id.startswith("group-"))
        for item_id in stale_items:
            # Строка могла исчезнуть, пока фоновое сканирование собирало результат.
            if self.process_tree.exists(item_id):
                self.process_tree.delete(item_id)
            self.tree_item_state.pop(item_id, None)

        active_parents = set(desired_children)
        for parent_id in active_parents:
            child_ids = desired_children[parent_id]
            if self.tree_children_order.get(parent_id) != child_ids:
                self.process_tree.set_children(parent_id, *child_ids)
                self.tree_children_order[parent_id] = list(child_ids)
        for parent_id in list(self.tree_children_order):
            if parent_id not in active_parents:
                del self.tree_children_order[parent_id]

        active_group_keys = set(key for key, _items in desired_groups.values())
        self.process_group_ids = {
            key: group_id
            for key, group_id in self.process_group_ids.items()
            if key in active_group_keys
        }
        self.process_group_members = {}
        for group_id, (_key, items) in desired_groups.items():
            self.process_group_members[group_id] = [
                int(item_id) for item_id, _state in items
            ]
        self.process_tree.yview_moveto(scroll_position)

    def selected_process_values(self):
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showwarning("Процесс", "Сначала выберите процесс.")
            return None
        if selected[0] in self.process_group_members:
            messagebox.showwarning(
                "Процесс",
                "Раскройте группу и выберите конкретный процесс (PID).",
            )
            return None
        return self.process_tree.item(selected[0], "values")

    def update_process_score(self, pid, create_time, score):
        item_id = str(pid)
        old_state = self.row_state.get(item_id)
        if old_state is None or old_state[2] != create_time:
            return
        old_values = old_state[0]
        self.update_process_row(
            pid,
            create_time,
            old_values[1],
            old_values[2],
            score,
            update_tree=False,
        )
        tree_entry = self.tree_item_state.get(item_id)
        if tree_entry is not None:
            # Сразу обновляем саму строку, а потом пересчитываем заголовок группы.
            state = self.row_state[item_id]
            self.process_tree.item(item_id, values=state[0], tags=(state[1],))
            parent_id = tree_entry[1]
            self.tree_item_state[item_id] = (state, parent_id)
            if parent_id:
                self.refresh_process_group(parent_id)

    def refresh_process_group(self, group_id):
        members = self.process_group_members.get(group_id, [])
        states = []
        for pid in members:
            state = self.row_state.get(str(pid))
            if state is not None:
                states.append(state)
        if not states or not self.process_tree.exists(group_id):
            return

        scores = []
        for state in states:
            try:
                scores.append(int(state[0][3]))
            except (TypeError, ValueError):
                continue
        max_score = max(scores) if scores else None
        tag = "danger" if max_score is not None and max_score >= WARNING_SCALE else ""
        if max_score is None:
            score_text = "Оценка: ..."
        else:
            score_text = f"Макс. оценка: {max_score}"
        values = (
            f"Группа ({len(states)})",
            states[0][0][1],
            states[0][0][2],
            score_text,
        )
        state = (values, tag, "")
        old_entry = self.tree_item_state.get(group_id)
        old_state = old_entry[0] if old_entry else None
        was_dangerous = old_state is not None and old_state[1] == "danger"
        if old_state != state:
            self.process_tree.item(group_id, values=values, tags=(tag,))
            self.tree_item_state[group_id] = (state, "")
        if (
            max_score is not None
            and max_score >= WARNING_SCALE
            and not was_dangerous
        ):
            self.process_tree.item(group_id, open=True)

    def finish_process_scan(self, completed):
        try:
            if completed:
                for item_id in self.process_scan_visible - self.process_scan_current:
                    if self.process_tree.exists(item_id):
                        self.process_tree.delete(item_id)
                    self.row_state.pop(item_id, None)
                self.request_process_table_update()
                self.scan_error_label.configure(text="")
        finally:
            self.process_scan_running = False
            if self.process_scan_requested:
                self.process_scan_requested = False
                self.after(1, lambda: self.request_process_scan(force=True))

    def add_selected_to_whitelist(self):
        if self.whitelist_add_running:
            return

        values = self.selected_process_values()
        if values is None:
            return

        if not values[2]:
            messagebox.showwarning(
                "Белый список",
                "У процесса не удалось получить путь, поэтому добавить его нельзя.",
            )
            return
        self.whitelist_add_running = True
        thread = threading.Thread(
            target=self.add_to_whitelist_in_background,
            args=(values[1], values[2]),
            daemon=True,
        )
        thread.start()

    def add_to_whitelist_in_background(self, name, exe):
        # Хеширование большого файла не должно задерживать интерфейс.
        try:
            added = add_to_whitelist(name, exe)
        except sqlite3.Error as error:
            self.process_queue.put(
                ("whitelist_result", (False, f"Не удалось сохранить запись: {error}"))
            )
            return

        if not added:
            self.process_queue.put(
                (
                    "whitelist_result",
                    (False, "Не удалось прочитать файл процесса для сохранения подписи."),
                )
            )
            return
        self.process_queue.put(("whitelist_result", (True, "")))

    def clear_score_cache(self):
        clear_score_cache()

    def kill_selected_process(self):
        # Завершение запускается только после подтверждения и проверок защиты.
        values = self.selected_process_values()
        if values is None:
            return

        pid = int(values[0])
        name = str(values[1]).lower()
        exe = str(values[2])
        system32 = os.path.join(
            os.environ.get("WINDIR") or os.environ.get("SystemRoot", ""),
            "System32",
        )
        is_system_process = False
        if name in self.protected_processes:
            if not exe:
                is_system_process = True
            else:
                process_dir = os.path.normcase(os.path.dirname(os.path.abspath(exe)))
                system_dir = os.path.normcase(os.path.abspath(system32))
                process_file = os.path.basename(exe).lower()
                is_system_process = (
                    process_dir == system_dir and process_file == name
                )
        if pid == os.getpid() or is_system_process:
            messagebox.showerror(
                "Завершение процесса",
                "Этот системный процесс защищен от завершения.",
            )
            return
        if not messagebox.askyesno(
            "Завершение процесса",
            f"Завершить процесс {values[1]} (PID {pid})?",
        ):
            return

        state = self.row_state.get(str(pid))
        if state is None:
            messagebox.showerror("Завершение процесса", "Данные процесса устарели.")
            return

        thread = threading.Thread(
            target=self.terminate_process,
            args=(pid, state[2]),
            daemon=True,
        )
        thread.start()

    def terminate_process(self, pid, expected_create_time):
        # Сначала даем процессу закрыться штатно и прибегаем к kill только по таймауту.
        try:
            proc = psutil.Process(pid)
            # PID может успеть перейти другому процессу, поэтому сверяем время запуска.
            if proc.create_time() != expected_create_time:
                self.process_queue.put(
                    ("kill_result", (False, "PID уже принадлежит другому процессу.", pid))
                )
                return
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            self.process_queue.put(
                ("kill_result", (True, "Процесс завершен.", pid))
            )
        except psutil.NoSuchProcess:
            self.process_queue.put(
                ("kill_result", (False, "Процесс уже завершился.", pid))
            )
        except psutil.AccessDenied:
            self.process_queue.put(
                ("kill_result", (False, "Нет прав для завершения процесса.", pid))
            )
        except psutil.Error as error:
            self.process_queue.put(("kill_result", (False, str(error), pid)))

    def remove_selected_from_whitelist(self):
        selected = self.whitelist_tree.selection()
        if not selected:
            messagebox.showwarning("Белый список", "Сначала выберите программу.")
            return

        values = self.whitelist_tree.item(selected[0], "values")
        try:
            remove_from_whitelist(values[0], values[1])
        except sqlite3.Error as error:
            messagebox.showerror("Белый список", f"Не удалось удалить запись: {error}")
            return
        self.clear_score_cache()
        self.start_database_read("Белый список")
        self.request_process_scan(force=True)

    def request_database_refresh(self):
        # Запрашиваем БД только для открытой вкладки и не читаем ее в GUI-потоке.
        if not self.database_scan_running:
            current_tab = self.tabs.get()
            if current_tab in ("События", "Белый список"):
                self.start_database_read(current_tab)

        self.after(2000, self.request_database_refresh)

    def start_database_read(self, tab_name):
        if self.database_scan_running:
            self.database_scan_requested = tab_name
            return
        self.database_scan_running = True
        thread = threading.Thread(
            target=self.read_tab_data,
            args=(tab_name,),
            daemon=True,
        )
        thread.start()

    def read_tab_data(self, tab_name):
        # Фоновый поток возвращает готовые данные через очередь, не меняя виджеты.
        data = []
        conn = None
        try:
            conn = sqlite3.connect(DB_NAME, timeout=1.0)
            if tab_name == "События":
                data = conn.execute(
                    "SELECT ts, pid, name, rule, score FROM ("
                    "SELECT id, ts, pid, name, rule, score FROM events "
                    "ORDER BY id DESC LIMIT 200) ORDER BY id"
                ).fetchall()
            else:
                data = conn.execute(
                    "SELECT name, exe, sha256 FROM whitelist ORDER BY name"
                ).fetchall()
                entries = []
                for name, exe, expected_hash in data:
                    current_hash = get_file_hash(exe)
                    if not current_hash:
                        status = "Файл недоступен"
                    elif current_hash == expected_hash:
                        status = "Хеш совпадает"
                    else:
                        status = "Файл изменен"
                    entries.append((name, exe, status))
                data = entries
        except sqlite3.OperationalError:
            data = None
        except sqlite3.Error:
            data = None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass

        self.process_queue.put(("tab_data", (tab_name, data)))

    def show_events(self, events):
        # При обычном пополнении журнала добавляем только новые строки.
        if events == self.last_events:
            return

        view = self.events_text.yview()
        was_at_bottom = view[1] >= 0.99
        previous = self.last_events or []
        if events[:len(previous)] == previous:
            new_events = events[len(previous):]
        else:
            new_events = events
            self.events_text.configure(state="normal")
            self.events_text.delete("1.0", "end")
            if not was_at_bottom:
                self.events_text.yview_moveto(view[0])

        if new_events:
            self.events_text.configure(state="normal")
            for timestamp, pid, name, rule, score in new_events:
                self.events_text.insert(
                    "end",
                    f"[{timestamp}] {name} ({pid}) | Оценка: {score} | Причина: {rule}\n",
                )
            if was_at_bottom:
                self.events_text.see("end")

        self.events_text.configure(state="disabled")
        self.last_events = events

    def show_whitelist(self, entries):
        # Сохраняем существующие строки, если их значения не менялись.
        visible_items = set(self.whitelist_tree.get_children())
        current_items = set()
        for index, (name, exe, status) in enumerate(entries):
            item_id = str(index)
            current_items.add(item_id)
            values = (str(name), str(exe), str(status))
            if item_id in visible_items:
                old_values = tuple(
                    str(value)
                    for value in self.whitelist_tree.item(item_id, "values")
                )
                if old_values != values:
                    self.whitelist_tree.item(item_id, values=values)
            else:
                self.whitelist_tree.insert(
                    "",
                    "end",
                    iid=item_id,
                    values=values,
                )

        for item_id in visible_items:
            if item_id not in current_items:
                self.whitelist_tree.delete(item_id)

    def update_ui(self):
        try:
            self.update_ui_tasks()
        except Exception:
            logger.exception("Ошибка обновления интерфейса.")
        finally:
            try:
                self.after(100, self.update_ui)
            except tk.TclError:
                pass

    def update_ui_tasks(self):
        # Tkinter-поток забирает результаты из очереди и обновляет виджеты.
        for _ in range(60):
            try:
                result_type, result = self.process_queue.get_nowait()
            except queue.Empty:
                break

            if result_type == "tab_data":
                # Пока один запрос выполняется, запоминаем только последнюю нужную вкладку.
                tab_name, data = result
                self.database_scan_running = False
                if data is not None and self.tabs.get() == tab_name:
                    if tab_name == "События":
                        self.show_events(data)
                    else:
                        self.show_whitelist(data)
                requested_tab = self.database_scan_requested
                self.database_scan_requested = None
                if requested_tab:
                    self.start_database_read(requested_tab)
                elif self.tabs.get() in ("События", "Белый список"):
                    if self.tabs.get() != tab_name:
                        self.start_database_read(self.tabs.get())
            elif result_type == "process_scan_started":
                self.process_scan_visible = set(self.row_state)
                self.process_scan_current = set()
            elif result_type == "process_rows":
                # Для знакомых процессов оставляем прежнюю оценку, пока не придет новая.
                for row in result:
                    pid, create_time, name, exe, score = row
                    item_id = str(pid)
                    old_state = self.row_state.get(item_id)
                    if (
                        old_state is not None
                        and old_state[2] == create_time
                        and old_state[0][1:3] == (str(name), str(exe))
                    ):
                        self.process_scan_current.add(item_id)
                        continue
                    self.update_process_row(
                        pid,
                        create_time,
                        name,
                        exe,
                        score,
                        update_tree=False,
                    )
                self.request_process_table_update()
            elif result_type == "process_score":
                pid, create_time, score = result
                self.update_process_score(pid, create_time, score)
            elif result_type == "process_scan_done":
                self.finish_process_scan(result)
            elif result_type == "whitelist_result":
                self.whitelist_add_running = False
                success, text = result
                if success:
                    self.clear_score_cache()
                    self.start_database_read("Белый список")
                    self.request_process_scan(force=True)
                    messagebox.showinfo("Белый список", "Программа добавлена.")
                else:
                    messagebox.showerror("Белый список", text)
            elif result_type == "scan_error":
                self.scan_error_label.configure(text="Ошибка обновления: " + result)
            elif result_type == "kill_result":
                success, text, pid = result
                if success:
                    item_id = str(pid)
                    if self.process_tree.exists(item_id):
                        self.process_tree.delete(item_id)
                    self.row_state.pop(item_id, None)
                    self.tree_item_state.pop(item_id, None)
                    self.request_process_scan(force=True)
                    messagebox.showinfo("Завершение процесса", text)
                else:
                    messagebox.showerror("Завершение процесса", text)

        if self.tabs.get() == "Активные процессы":
            self.request_process_scan()

        if self.monitor_thread is not None and not self.monitor_thread.is_alive():
            if self.monitor_restart_requested:
                self.start_monitoring()
            elif self.stop_event is not None and self.stop_event.is_set():
                self.status_label.configure(
                    text="Статус: Остановлен",
                    text_color="#ff5c5c",
                )
                self.monitor_button.configure(
                    text="Запустить мониторинг",
                    fg_color="#1f6aa5",
                    hover_color="#144870",
                )
            elif self.stop_event is not None:
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
                self.scan_error_label.configure(
                    text="Монитор завершился. Проверьте antivirus.log."
                )

    def close_app(self):
        if self.stop_event is not None:
            self.stop_event.set()
        self.destroy()