import json
import shutil
from datetime import datetime
from pathlib import Path

import webview

from engine import (
    load_config, save_config,
    parse_message, parse_excel, compare, export_to_excel,
)


class API:
    def __init__(self):
        self.cfg         = load_config()
        self.excel_path  = None
        self.output_path = None
        self.window      = None  # set after window creation

    # ── Config ────────────────────────────────────────────────────────────────

    def get_config(self):
        return json.dumps(self.cfg, ensure_ascii=False)

    def save_settings_full(self, data):
        updates = json.loads(data)
        self.cfg['excel_columns']    = updates['excel_columns']
        self.cfg['excel_has_header'] = updates['excel_has_header']
        self.cfg['rules']            = updates['rules']
        save_config(self.cfg)
        return 'ok'

    def save_aliases(self, data):
        self.cfg['aliases'] = json.loads(data)
        save_config(self.cfg)
        return 'ok'

    # ── File dialogs ──────────────────────────────────────────────────────────

    def pick_excel(self):
        result = self.window.create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=('Excel Files (*.xlsx;*.xls)', 'All files (*.*)')
        )
        if result:
            self.excel_path = result[0]
            return Path(self.excel_path).name
        return None

    def save_output(self):
        if not self.output_path or not Path(self.output_path).exists():
            return 'no_output'
        result = self.window.create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename='השוואת_משמרות.xlsx',
            file_types=('Excel Files (*.xlsx)',)
        )
        if result:
            dest = result[0] if isinstance(result, (list, tuple)) else result
            shutil.copy(self.output_path, dest)
            return 'saved'
        return 'cancelled'

    # ── Comparison ────────────────────────────────────────────────────────────

    def run_comparison(self, message):
        if not message.strip():
            return json.dumps({'error': 'אנא הדבק הודעה מוואטסאפ'})
        if not self.excel_path:
            return json.dumps({'error': 'אנא בחר קובץ אקסל'})
        try:
            msg_entries   = parse_message(message)
            excel_entries = parse_excel(self.excel_path, self.cfg)

            if not msg_entries:
                return json.dumps({'error': 'לא נמצאו עובדים בהודעה — בדוק את הפורמט'})
            if not excel_entries:
                return json.dumps({'error': 'לא נמצאו שורות תקינות באקסל — בדוק הגדרות עמודות'})

            results  = compare(msg_entries, excel_entries, self.cfg)
            out_name = f"השוואה_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            self.output_path = str(Path(__file__).parent / out_name)
            export_to_excel(results, self.output_path)

            return json.dumps({'success': True, 'count': len(results)})
        except Exception as e:
            return json.dumps({'error': str(e)})


if __name__ == '__main__':
    api = API()
    window = webview.create_window(
        title='השוואת משמרות',
        url=str(Path(__file__).parent / 'ui' / 'index.html'),
        js_api=api,
        width=1050,
        height=730,
        min_size=(820, 580),
        text_select=True,
    )
    api.window = window
    webview.start(debug=False)
