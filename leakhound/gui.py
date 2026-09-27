"""La ventana de leakhound: elegir una carpeta y ver qué secretos hay, también en git.

Tkinter viene con Python, así que no hace falta instalar nada más. La búsqueda va en un
hilo aparte para que la ventana no se congele con un repositorio grande; Tkinter no se
puede tocar desde otro hilo, así que el resultado llega por una cola que la ventana mira
cada 100 ms.
"""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from . import __version__, demo
from .git import GitError, repo_root, scan_history
from .report import to_json, to_sarif, to_text
from .rules import Severity
from .scanner import Finding, scan_path

ICON = Path(__file__).with_name("icon.png")
ROW_COLORS = {
    Severity.CRITICAL: "#fecaca",
    Severity.HIGH: "#fed7aa",
    Severity.MEDIUM: "#fef08a",
    Severity.LOW: "#dbeafe",
}


@dataclass
class Result:
    findings: list[Finding]
    base: Path  # las rutas de los hallazgos son relativas a esta carpeta
    history: bool


def search(folder: Path, history: bool) -> Result:
    """Lo que hay ahora en la carpeta y, si se pide, lo que ha pasado por git. Un secreto
    que todavía no se ha llegado a hacer commit solo sale en lo primero, así que se juntan."""
    if not history:
        return Result(scan_path(folder), folder, False)
    root = repo_root(folder)
    found = scan_history(root)
    seen = {(f.rule.id, f.secret, f.path) for f in found}
    found += [f for f in scan_path(root) if (f.rule.id, f.secret, f.path) not in seen]
    return Result(found, root, True)


def status_of(finding: Finding, history: bool) -> str:
    if not history:
        return "en el código"
    if finding.commit is None:
        return "sin commit todavía"
    return "sigue en el código" if finding.still_present else "solo en el historial"


def open_file(path: Path) -> None:
    if sys.platform == "win32":
        os.startfile(path)  # solo existe en Windows
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class App:
    def __init__(self, root: tk.Tk, folder: Path | None):
        self.root = root
        self.folder: Path | None = None
        self.result: Result | None = None
        self.rows: dict[str, Finding] = {}
        self.jobs: queue.Queue = queue.Queue()
        self.busy = False
        self.history = tk.BooleanVar(value=True)
        # Los informes de texto llevan colores si la salida es una terminal (y la ventana se
        # puede abrir desde una): al guardarlos en un archivo no tienen que ir.
        os.environ["NO_COLOR"] = "1"

        root.title("leakhound")
        root.geometry("1000x640")
        root.minsize(720, 460)
        if ICON.exists():
            root.iconphoto(True, tk.PhotoImage(file=str(ICON)))
        self.build()
        root.after(100, self.poll)
        if folder:
            self.open(folder)
        else:
            self.summary.config(text="Elige una carpeta (un proyecto, un repositorio de git...) y pulsa Buscar.")

    # La ventana

    def build(self) -> None:
        root = self.root
        style = ttk.Style(root)
        if style.theme_use() == "default" and "clam" in style.theme_names():
            style.theme_use("clam")  # en Linux el de por defecto es de los noventa
        bold = tkfont.nametofont("TkDefaultFont").copy()
        bold.configure(weight="bold")
        line = tkfont.nametofont("TkDefaultFont").metrics("linespace")
        style.configure("Treeview", rowheight=line + 8)
        style.configure("Accent.TButton", font=bold)

        menu = tk.Menu(root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Elegir carpeta…", command=self.choose, accelerator="Ctrl+O")
        file_menu.add_command(label="Probar con un repositorio de ejemplo", command=self.open_demo)
        file_menu.add_command(label="Guardar informe…", command=self.save, accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=root.destroy)
        menu.add_cascade(label="Archivo", menu=file_menu)
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Acerca de leakhound", command=self.about)
        menu.add_cascade(label="Ayuda", menu=help_menu)
        root.config(menu=menu)
        root.bind_all("<Control-o>", lambda _: self.choose())
        root.bind_all("<Control-s>", lambda _: self.save())

        top = ttk.Frame(root, padding=(14, 12, 14, 6))
        top.pack(fill="x")
        ttk.Label(top, text="Carpeta:").pack(side="left")
        self.folder_label = ttk.Label(top, text="(ninguna)", font=bold)
        self.folder_label.pack(side="left", padx=(6, 10), fill="x", expand=True)
        ttk.Button(top, text="Elegir…", command=self.choose).pack(side="right")

        options = ttk.Frame(root, padding=(14, 0, 14, 6))
        options.pack(fill="x")
        self.history_check = ttk.Checkbutton(
            options, text="Buscar también en el historial de git", variable=self.history, command=self.run
        )
        self.history_check.pack(side="left")
        self.git_note = ttk.Label(options, foreground="#6b7280")
        self.git_note.pack(side="left", padx=10)
        self.search_button = ttk.Button(options, text="Buscar", command=self.run, style="Accent.TButton")
        self.search_button.pack(side="right")

        self.summary = ttk.Label(root, padding=(14, 4, 14, 8), wraplength=960, justify="left")
        self.summary.pack(fill="x")
        root.bind("<Configure>", lambda e: e.widget is root and self.summary.config(wraplength=max(300, e.width - 40)))

        panes = ttk.PanedWindow(root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=14)
        table = ttk.Frame(panes)
        columns = ("severity", "title", "where", "secret", "status")
        self.tree = ttk.Treeview(table, columns=columns, show="headings", selectmode="browse")
        for column, text, width, stretch in (
            ("severity", "Gravedad", 90, False),
            ("title", "Qué es", 250, True),
            ("where", "Dónde", 230, True),
            ("secret", "Secreto (tapado)", 220, True),
            ("status", "Estado", 150, False),
        ):
            self.tree.heading(column, text=text, anchor="w")
            self.tree.column(column, width=width, stretch=stretch)
        for severity, color in ROW_COLORS.items():
            self.tree.tag_configure(severity.label, background=color, foreground="#111827")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _: self.show_detail())
        self.tree.bind("<Double-1>", lambda _: self.open_selected())
        panes.add(table, weight=3)

        self.detail = tk.Text(panes, height=8, wrap="word", relief="flat", padx=10, pady=8, font="TkDefaultFont")
        self.detail.tag_configure("title", font=bold)
        self.detail.configure(state="disabled")
        panes.add(self.detail, weight=1)

        bottom = ttk.Frame(root, padding=(14, 8, 14, 12))
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=100)
        self.status = ttk.Label(bottom, foreground="#4b5563")
        self.status.pack(side="left")
        self.save_button = ttk.Button(bottom, text="Guardar informe…", command=self.save)
        self.save_button.pack(side="right")
        self.copy_button = ttk.Button(bottom, text="Copiar huella", command=self.copy_fingerprint)
        self.copy_button.pack(side="right", padx=(0, 8))
        self.open_button = ttk.Button(bottom, text="Abrir el archivo", command=self.open_selected)
        self.open_button.pack(side="right", padx=(0, 8))
        self.update_buttons()

    def update_buttons(self) -> None:
        idle = not self.busy
        selected = self.selected()
        exists = bool(selected and self.result and (self.result.base / selected.path).is_file())
        self.search_button.state(["!disabled"] if idle and self.folder else ["disabled"])
        self.save_button.state(["!disabled"] if idle and self.result else ["disabled"])
        self.copy_button.state(["!disabled"] if selected else ["disabled"])
        self.open_button.state(["!disabled"] if exists else ["disabled"])

    def show_result(self, result: Result) -> None:
        self.result = result
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        for f in sorted(result.findings, key=lambda f: (-f.severity, f.path, f.line)):
            values = (f.severity.label, f.rule.title, f"{f.path}:{f.line}", f.masked, status_of(f, result.history))
            self.rows[self.tree.insert("", "end", values=values, tags=(f.severity.label,))] = f
        where = "el código y el historial de git" if result.history else "el código"
        count = len(result.findings)
        if count:
            worst = max(f.severity for f in result.findings)
            self.summary.config(
                text=f"{count} secreto{'s' if count != 1 else ''} en {where}; el más grave, {worst.label.lower()}. "
                "Un secreto que ha llegado a git hay que darlo por filtrado: revócalo y genera otro."
            )
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)
        else:
            self.summary.config(text=f"Sin secretos en {where}.")
            self.show_detail()
        self.status.config(text="")
        self.update_buttons()

    def selected(self) -> Finding | None:
        chosen = self.tree.selection()
        return self.rows.get(chosen[0]) if chosen else None

    def show_detail(self) -> None:
        f = self.selected()
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if f:
            self.detail.insert("end", f"{f.rule.title}\n", "title")
            self.detail.insert("end", f"{f.path}, línea {f.line}. Gravedad: {f.severity.label.lower()}.\n")
            self.detail.insert("end", f"Secreto: {f.masked}. No se enseña entero, ni aquí ni en los informes.\n")
            if f.commit:
                state = "sigue en el código" if f.still_present else "ya no está en el código, pero sí en el historial"
                self.detail.insert("end", f"Añadido en el commit {f.commit[:8]} por {f.author} el {f.date}; {state}.\n")
            self.detail.insert(
                "end",
                "\nQué hacer: revócalo en el servicio y genera uno nuevo. Quitarlo del código no basta si ya "
                "llegó a git, porque cualquiera que clone el repositorio puede verlo.\n"
                f"Si es un falso positivo, copia su huella ({f.fingerprint}) en un archivo .leakhound-ignore "
                "en la carpeta y no volverá a salir.",
            )
        self.detail.configure(state="disabled")
        self.update_buttons()

    # Lo que hacen los botones

    def choose(self) -> None:
        if self.busy:
            return
        chosen = filedialog.askdirectory(
            parent=self.root, title="¿Dónde busco?", initialdir=str(self.folder or Path.home())
        )
        if chosen:
            self.open(Path(chosen))

    def open(self, folder: Path) -> None:
        folder = folder.expanduser().resolve()
        if not folder.is_dir():
            messagebox.showerror("leakhound", f"No existe la carpeta {folder}.", parent=self.root)
            return
        self.folder = folder
        self.folder_label.config(text=str(folder))
        if not shutil.which("git"):
            can_history, note = False, "(hace falta tener git instalado)"
        else:
            try:
                repo_root(folder)
                can_history, note = True, ""
            except GitError:
                can_history, note = False, "(esta carpeta no es un repositorio de git)"
        self.history.set(can_history)
        self.history_check.state(["!disabled"] if can_history else ["disabled"])
        self.git_note.config(text=note)
        self.run()

    def open_demo(self) -> None:
        if self.busy:
            return
        if not shutil.which("git"):
            messagebox.showinfo("leakhound", "El ejemplo es un repositorio de git: hace falta tener git instalado.")
            return
        repo = demo.build_repo(Path(tempfile.mkdtemp(prefix="leakhound-ejemplo-")))
        messagebox.showinfo(
            "Repositorio de ejemplo",
            "He creado un repositorio de prueba en el que Ana sube unas claves de AWS, Luis las quita "
            "en el siguiente commit y luego alguien añade un script con un token.\n\n"
            "En el código ya solo quedan dos secretos. Mira lo que sigue en el historial.",
            parent=self.root,
        )
        self.open(repo)

    def run(self) -> None:
        if self.folder is None or self.busy:
            return
        folder, history = self.folder, self.history.get() and "disabled" not in self.history_check.state()
        self.in_background(lambda: search(folder, history), self.show_result, "Buscando…")

    def open_selected(self) -> None:
        f = self.selected()
        if f and self.result and (self.result.base / f.path).is_file():
            open_file(self.result.base / f.path)

    def copy_fingerprint(self) -> None:
        f = self.selected()
        if f:
            self.root.clipboard_clear()
            self.root.clipboard_append(f"{f.fingerprint}  # {f.rule.title} en {f.path}")
            self.status.config(text="Huella copiada: pégala en .leakhound-ignore para ignorar este hallazgo.")

    def save(self) -> None:
        if not self.result or self.busy:
            return
        target = filedialog.asksaveasfilename(
            parent=self.root,
            title="Guardar informe",
            defaultextension=".txt",
            initialfile="leakhound-informe.txt",
            filetypes=[("Texto", "*.txt"), ("JSON", "*.json"), ("SARIF (GitHub Code Scanning)", "*.sarif")],
        )
        if not target:
            return
        findings = self.result.findings
        if target.lower().endswith(".json"):
            text = to_json(findings)
        elif target.lower().endswith(".sarif"):
            text = to_sarif(findings)
        else:
            text = to_text(findings, str(self.folder))
        Path(target).write_text(text + "\n", encoding="utf-8")
        self.status.config(text=f"Informe guardado en {target}")

    def about(self) -> None:
        messagebox.showinfo(
            "Acerca de leakhound",
            f"leakhound {__version__}\n\nBusca contraseñas, claves de API y tokens en el código y en el historial "
            "de git, sin enseñarlos nunca enteros.\n\nhttps://github.com/espi0207/leakhound",
            parent=self.root,
        )

    # Trabajo en segundo plano

    def in_background(self, work, done, message: str) -> None:
        self.busy = True
        self.status.config(text=message)
        self.progress.pack(side="left", padx=(0, 10), before=self.status)
        self.progress.start(12)
        self.update_buttons()

        def worker():
            try:
                self.jobs.put((done, work(), None))
            except Exception as exc:  # que un error no deje la ventana esperando para siempre
                self.jobs.put((done, None, exc))

        threading.Thread(target=worker, daemon=True).start()

    def poll(self) -> None:
        try:
            while True:
                done, result, error = self.jobs.get_nowait()
                self.busy = False
                self.progress.stop()
                self.progress.pack_forget()
                if error:
                    self.status.config(text="")
                    messagebox.showerror("leakhound", f"No se ha podido buscar: {error}", parent=self.root)
                    self.update_buttons()
                else:
                    done(result)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)


def self_check() -> int:
    """Para la CI: crea el repositorio de ejemplo, lo abre en la ventana y comprueba que
    salen los cinco secretos (tres solo en el historial), sin que nadie toque nada. Así se
    sabe que el programa instalado funciona de verdad (con Tkinter y git), no solo que se
    ha creado."""
    # ignore_cleanup_errors: en Windows git deja archivos de solo lectura que no se dejan borrar.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        repo = demo.build_repo(Path(tmp))
        root = tk.Tk()
        app = App(root, repo)
        outcome = {"code": 1}

        def check():
            if app.busy or app.result is None:
                root.after(100, check)
                return
            statuses = [app.tree.item(item, "values")[4] for item in app.tree.get_children()]
            ok = len(statuses) == 5 and statuses.count("solo en el historial") == 3
            outcome["code"] = 0 if ok else 1
            root.destroy()

        root.after(200, check)
        root.after(60_000, root.destroy)  # por si algo se queda colgado
        root.mainloop()
        return outcome["code"]


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if sys.platform == "win32":
        try:  # sin esto, en pantallas con zoom Windows estira la ventana y se ve borrosa
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    if "--comprobar" in args:
        sys.exit(self_check())
    # Una carpeta como argumento: la que llega desde "Buscar secretos con leakhound" en el Explorador.
    folder = Path(args[0]) if args else None
    root = tk.Tk()
    App(root, folder if folder and folder.is_dir() else None)
    root.mainloop()


if __name__ == "__main__":
    main()
