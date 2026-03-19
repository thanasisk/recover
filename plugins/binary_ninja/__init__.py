# -*- coding: utf-8 -*-
# pylint: disable=invalid-name,unused-argument
"""REcover Binary Ninja plug-in."""

__author__ = "Chariton Karamitas <huku@census-labs.com>"
__credits__ = ["Chariton Karamitas <huku@census-labs.com>", "Athanasios Kostopoulos <athanasios@akostopoulos.com>"]
__maintainer__ = "Athanasios Kostopoulos <athanasios@akostopoulos.com>"

from pathlib import Path
import collections
import contextlib
import errno
import functools
import importlib
import importlib.resources
import json
import logging.config
import os

try:
    import binaryninja as bn
    from binaryninja import BinaryView
    from binaryninja.plugin import PluginCommand
    from binaryninja.interaction import (
        get_directory_name_input,
        get_open_filename_input,
        show_message_box,
        MessageBoxButtonSet,
        MessageBoxIcon,
    )
    import binaryninjaui
    from binaryninjaui import (
        UIContext,
        DockHandler,
        ViewFrame,
        UIActionHandler,
    )
    from PySide6.QtWidgets import (
        QWidget,
        QDialog,
        QVBoxLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QRadioButton,
        QButtonGroup,
        QGroupBox,
        QTableWidget,
        QTableWidgetItem,
        QHeaderView,
        QFileDialog,
        QDialogButtonBox,
        QSplitter,
        QAbstractItemView,
    )
    from PySide6.QtCore import Qt
except ImportError as e:
    raise RuntimeError("Not running in Binary Ninja") from e


ESTIMATORS = ["agglnse", "agglpse", "apsnse", "apspse", "file"]
OPTIMIZERS = ["none", "brute_fast", "brute", "genetic"]
FITNESS_FUNCTIONS = ["modularity"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def check_dir(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(path))
    if not path.is_dir():
        raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(path))


def _default_path(bv: BinaryView) -> Path:
    """Return the directory containing the currently open binary."""
    if bv and bv.file and bv.file.filename:
        return Path(bv.file.filename).parent
    return Path.cwd()


# ---------------------------------------------------------------------------
# Core logic (replaces IDA-specific wiring)
# ---------------------------------------------------------------------------

def analyze(
    bv: BinaryView,
    path: str | Path | None = None,
    estimator: str | None = None,
    load_estimation: str | None = None,
    optimizer: str | None = None,
    fitness_function: str | None = None,
    segment: str | None = None,
    venv_path: str | Path | None = None,
) -> None:
    """Run REcover analysis."""
    if path:
        path = Path(path) if isinstance(path, str) else path
        check_dir(path)
    else:
        path = _default_path(bv)

    context: Any
    if venv_path:
        venv_path = Path(venv_path) if isinstance(venv_path, str) else venv_path
        check_dir(venv_path)
        # Binary Ninja has no ida_venv; activate the venv manually by
        # prepending its site-packages to sys.path.
        import sys
        sp = venv_path / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        if not sp.exists():
            # Windows layout
            sp = venv_path / "Lib" / "site-packages"
        context = _venv_sys_path_context(sp)
    else:
        context = contextlib.nullcontext()

    with context:
        recover = importlib.import_module("recover")
        config_path = importlib.resources.files("recover.data") / "logging.ini"
        logging.config.fileConfig(str(config_path))
        recover.analyze(
            path,
            estimator=estimator or "apsnse",
            load_estimation=load_estimation,
            optimizer=optimizer or "brute_fast",
            fitness_function=fitness_function or "modularity",
            segment=segment or ".text",
            pickle_path=path / "cu_map.pcl",
            json_path=path / "cu_map.json",
            debug=True,
        )


def export(
    bv: BinaryView,
    path: str | Path | None = None,
    venv_path: str | Path | None = None,
) -> None:
    """Run REcover export logic."""
    if path:
        path = Path(path) if isinstance(path, str) else path
        check_dir(path)
    else:
        path = _default_path(bv)

    if venv_path:
        venv_path = Path(venv_path) if isinstance(venv_path, str) else venv_path
        check_dir(venv_path)
        import sys
        sp = venv_path / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        if not sp.exists():
            sp = venv_path / "Lib" / "site-packages"
        context = _venv_sys_path_context(sp)
    else:
        context = contextlib.nullcontext()

    with context:
        recover = importlib.import_module("recover")
        binja_exporter = importlib.import_module("recover.exporters.binja")
        config_path = importlib.resources.files("recover.data") / "logging.ini"
        logging.config.fileConfig(str(config_path))
        recover.export(binja_exporter.BinjaExporter(bv), path)


@contextlib.contextmanager
def _venv_sys_path_context(site_packages: Path):
    """Temporarily prepend a venv's site-packages to sys.path."""
    import sys
    sp = str(site_packages)
    sys.path.insert(0, sp)
    try:
        yield
    finally:
        sys.path.remove(sp)


# ---------------------------------------------------------------------------
# Headless mode
# ---------------------------------------------------------------------------

def run_headless(bv: BinaryView, actions: str) -> None:
    r = os.EX_OK
    actions_list = [a.strip() for a in actions.split(",")]
    try:
        if "export" in actions_list:
            export(
                bv,
                path=os.getenv("RECOVER_PATH"),
                venv_path=os.getenv("RECOVER_VENV_PATH"),
            )
        if "analyze" in actions_list:
            analyze(
                bv,
                path=os.getenv("RECOVER_PATH"),
                estimator=os.getenv("RECOVER_ESTIMATOR"),
                load_estimation=os.getenv("RECOVER_LOAD_ESTIMATION"),
                fitness_function=os.getenv("RECOVER_FITNESS_FUNCTION"),
                optimizer=os.getenv("RECOVER_OPTIMIZER"),
                segment=os.getenv("RECOVER_SEGMENT"),
            )
    except Exception:
        logging.exception("REcover raised exception")
        r = -1

    if os.getenv("RECOVER_EXIT"):
        # BinaryInja has no qexit; ask the host process to quit.
        bn.shutdown()
        raise SystemExit(r)


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def _browse_dir(line_edit: QLineEdit, title: str = "Select directory") -> None:
    d = QFileDialog.getExistingDirectory(None, title, line_edit.text())
    if d:
        line_edit.setText(d)


def _browse_file(line_edit: QLineEdit, title: str = "Select file") -> None:
    f, _ = QFileDialog.getOpenFileName(None, title, line_edit.text())
    if f:
        line_edit.setText(f)


def _row(label: str, widget: QWidget, browse_cb=None) -> QHBoxLayout:
    hbox = QHBoxLayout()
    hbox.addWidget(QLabel(label))
    hbox.addWidget(widget)
    if browse_cb:
        btn = QPushButton("…")
        btn.setFixedWidth(28)
        btn.clicked.connect(browse_cb)
        hbox.addWidget(btn)
    return hbox


# ---------------------------------------------------------------------------
# Export dialog
# ---------------------------------------------------------------------------

class ExportDialog(QDialog):
    def __init__(self, bv: BinaryView, parent=None):
        super().__init__(parent)
        self._bv = bv
        self.setWindowTitle("REcover — Export")
        self.setMinimumWidth(500)

        layout = QVBoxLayout(self)

        self._venv = QLineEdit()
        self._venv.setPlaceholderText("(optional)")
        layout.addLayout(_row("Virtual environment:", self._venv,
                              lambda: _browse_dir(self._venv, "Select venv directory")))

        self._output = QLineEdit(str(_default_path(bv)))
        layout.addLayout(_row("Output directory:", self._output,
                               lambda: _browse_dir(self._output)))

        buttons = QDialogButtonBox(Qt.Horizontal)
        export_btn = buttons.addButton("Export", QDialogButtonBox.AcceptRole)
        close_btn  = buttons.addButton("Close",  QDialogButtonBox.RejectRole)
        export_btn.clicked.connect(self._on_export)
        close_btn.clicked.connect(self.reject)
        layout.addWidget(buttons)

    def _on_export(self) -> None:
        try:
            export(
                self._bv,
                path=self._output.text() or None,
                venv_path=self._venv.text() or None,
            )
            show_message_box("REcover", "Export completed successfully.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
        except Exception as exc:
            show_message_box("REcover — Error", str(exc),
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


# ---------------------------------------------------------------------------
# Analysis dialog
# ---------------------------------------------------------------------------

class AnalysisDialog(QDialog):
    def __init__(self, bv: BinaryView, parent=None):
        super().__init__(parent)
        self._bv = bv
        self.setWindowTitle("REcover — Analyze")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)

        # Venv
        self._venv = QLineEdit()
        self._venv.setPlaceholderText("(optional)")
        layout.addLayout(_row("Virtual environment:", self._venv,
                              lambda: _browse_dir(self._venv, "Select venv directory")))

        # Estimator
        est_box = QGroupBox("Initial estimation method")
        est_layout = QVBoxLayout(est_box)
        self._est_group = QButtonGroup(self)
        est_labels = [
            "agglnse  (Agglomerative – No Sequence Edges)",
            "agglpse  (Agglomerative – Partial Sequence Edges)",
            "apsnse   (Articulation Points – No Sequence Edges)",
            "apspse   (Articulation Points – Partial Sequence Edges)",
            "Load from file",
        ]
        for i, label in enumerate(est_labels):
            rb = QRadioButton(label)
            self._est_group.addButton(rb, i)
            est_layout.addWidget(rb)
        self._est_group.button(2).setChecked(True)  # apsnse default
        layout.addWidget(est_box)

        self._input_file = QLineEdit()
        self._input_file.setPlaceholderText("(required when 'Load from file' selected)")
        layout.addLayout(_row("Input file:", self._input_file,
                              lambda: _browse_file(self._input_file)))
        self._est_group.idToggled.connect(self._on_est_changed)
        self._on_est_changed(self._est_group.checkedId(), True)

        # Optimizer
        opt_box = QGroupBox("Optimization method")
        opt_layout = QVBoxLayout(opt_box)
        self._opt_group = QButtonGroup(self)
        for i, label in enumerate(["None", "Fast brute-force", "Brute-force", "Genetic"]):
            rb = QRadioButton(label)
            self._opt_group.addButton(rb, i)
            opt_layout.addWidget(rb)
        self._opt_group.button(1).setChecked(True)  # brute_fast default
        layout.addWidget(opt_box)

        # Fitness function
        ff_box = QGroupBox("Fitness function")
        ff_layout = QVBoxLayout(ff_box)
        self._ff_group = QButtonGroup(self)
        rb = QRadioButton("Modularity")
        self._ff_group.addButton(rb, 0)
        ff_layout.addWidget(rb)
        rb.setChecked(True)
        layout.addWidget(ff_box)

        # Segment + output
        self._segment = QLineEdit(".text")
        layout.addLayout(_row("Segment name:", self._segment))

        self._output = QLineEdit(str(_default_path(bv)))
        layout.addLayout(_row("Output directory:", self._output,
                               lambda: _browse_dir(self._output)))

        buttons = QDialogButtonBox(Qt.Horizontal)
        analyze_btn = buttons.addButton("Analyze", QDialogButtonBox.AcceptRole)
        close_btn   = buttons.addButton("Close",   QDialogButtonBox.RejectRole)
        analyze_btn.clicked.connect(self._on_analyze)
        close_btn.clicked.connect(self.reject)
        layout.addWidget(buttons)

    def _on_est_changed(self, btn_id: int, checked: bool) -> None:
        self._input_file.setEnabled(ESTIMATORS[btn_id] == "file")

    def _on_analyze(self) -> None:
        estimator = ESTIMATORS[self._est_group.checkedId()]
        load_estimation = self._input_file.text() or None
        optimizer = OPTIMIZERS[self._opt_group.checkedId()]
        fitness_function = FITNESS_FUNCTIONS[self._ff_group.checkedId()]
        try:
            analyze(
                self._bv,
                path=self._output.text() or None,
                estimator=estimator,
                load_estimation=load_estimation,
                optimizer=optimizer,
                fitness_function=fitness_function,
                segment=self._segment.text() or ".text",
                venv_path=self._venv.text() or None,
            )
            show_message_box("REcover", "Analysis completed successfully.",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
        except Exception as exc:
            show_message_box("REcover — Error", str(exc),
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


# ---------------------------------------------------------------------------
# Exploration dialog
# ---------------------------------------------------------------------------

class ExplorationDialog(QDialog):
    def __init__(self, bv: BinaryView, parent=None):
        super().__init__(parent)
        self._bv = bv
        self._cu_funcs: dict | None = None
        self._cus: list | None = None
        self.setWindowTitle("REcover — Explorer")
        self.setMinimumSize(700, 450)

        layout = QVBoxLayout(self)

        # File picker row
        file_row = QHBoxLayout()
        self._cumap_path = QLineEdit(str(_default_path(bv) / "cu_map.json"))
        file_row.addWidget(QLabel("CUMap JSON file:"))
        file_row.addWidget(self._cumap_path)
        browse_btn = QPushButton("…")
        browse_btn.setFixedWidth(28)
        browse_btn.clicked.connect(lambda: _browse_file(self._cumap_path, "Open cu_map.json"))
        file_row.addWidget(browse_btn)
        load_btn = QPushButton("Load")
        load_btn.clicked.connect(self._on_load)
        file_row.addWidget(load_btn)
        layout.addLayout(file_row)

        # Two-pane splitter: compile-units | functions
        splitter = QSplitter(Qt.Horizontal)

        self._cu_table = QTableWidget(0, 2)
        self._cu_table.setHorizontalHeaderLabels(["CU", "Size"])
        self._cu_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._cu_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._cu_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._cu_table.itemSelectionChanged.connect(self._on_cu_select)
        splitter.addWidget(self._cu_table)

        self._fn_table = QTableWidget(0, 2)
        self._fn_table.setHorizontalHeaderLabels(["Address", "Name"])
        self._fn_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._fn_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._fn_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._fn_table.itemDoubleClicked.connect(self._on_fn_jump)
        splitter.addWidget(self._fn_table)

        layout.addWidget(splitter)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)

    def _on_load(self) -> None:
        try:
            cumap_path = Path(self._cumap_path.text())
            with open(cumap_path, "rb") as fp:
                data = json.load(fp)
            cu_funcs: dict[int, list[int]] = collections.defaultdict(list)
            for i, cu in enumerate(data["func_to_cu"]):
                cu_funcs[cu].append(data["funcs"][i])
            self._cu_funcs = cu_funcs
            self._cus = list(sorted(cu_funcs))

            self._cu_table.setRowCount(0)
            for cu in self._cus:
                row = self._cu_table.rowCount()
                self._cu_table.insertRow(row)
                self._cu_table.setItem(row, 0, QTableWidgetItem(f"CU #{cu}"))
                self._cu_table.setItem(row, 1, QTableWidgetItem(str(len(cu_funcs[cu]))))
        except Exception as exc:
            show_message_box("REcover — Error", str(exc),
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def _on_cu_select(self) -> None:
        if self._cu_funcs is None:
            return
        rows = self._cu_table.selectedItems()
        if not rows:
            return
        row_idx = self._cu_table.currentRow()
        cu = self._cus[row_idx]
        funcs = self._cu_funcs[cu]

        self._fn_table.setRowCount(0)
        for ea in funcs:
            row = self._fn_table.rowCount()
            self._fn_table.insertRow(row)
            self._fn_table.setItem(row, 0, QTableWidgetItem(f"{ea:#x}"))
            # Resolve name via Binary Ninja
            binja_fn = self._bv.get_function_at(ea)
            name = binja_fn.name if binja_fn else f"sub_{ea:#x}"
            self._fn_table.setItem(row, 1, QTableWidgetItem(name))

    def _on_fn_jump(self, item: QTableWidgetItem) -> None:
        row = item.row()
        ea_str = self._fn_table.item(row, 0).text()
        ea = int(ea_str, 16)
        # Navigate the current view to the address
        ctx = UIContext.activeContext()
        if ctx:
            ctx.navigateForBinaryView(self._bv, ea)


# ---------------------------------------------------------------------------
# Main dialog
# ---------------------------------------------------------------------------

class MainDialog(QDialog):
    def __init__(self, bv: BinaryView, parent=None):
        super().__init__(parent)
        self._bv = bv
        self.setWindowTitle("REcover")
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<b>REcover Binary Ninja plug-in</b>"))

        export_btn = QPushButton("Export IDB information")
        export_btn.clicked.connect(self._on_export)
        layout.addWidget(export_btn)

        analyze_btn = QPushButton("Recover compile-unit segmentation")
        analyze_btn.clicked.connect(self._on_analyze)
        layout.addWidget(analyze_btn)

        explore_btn = QPushButton("Explore analysis results")
        explore_btn.clicked.connect(self._on_explore)
        layout.addWidget(explore_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

    def _on_export(self) -> None:
        dlg = ExportDialog(self._bv, self)
        dlg.exec()

    def _on_analyze(self) -> None:
        dlg = AnalysisDialog(self._bv, self)
        dlg.exec()

    def _on_explore(self) -> None:
        dlg = ExplorationDialog(self._bv, self)
        dlg.exec()


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------

def _show_main(bv: BinaryView) -> None:
    # Headless mode: if env var set, skip UI entirely
    if actions := os.getenv("RECOVER_HEADLESS"):
        run_headless(bv, actions)
        return
    dlg = MainDialog(bv)
    dlg.exec()


PluginCommand.register(
    "REcover\\Open REcover",
    "Open REcover compile-unit recovery tool (Ctrl+Alt+R)",
    _show_main,
)

