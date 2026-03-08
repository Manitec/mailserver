
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, DataTable, Static, Input, Button, TextArea, Label, ListView, ListItem
from textual.screen import Screen
from dotenv import load_dotenv
import os
import httpx
import asyncio

# Load credentials
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")

# Account config
ACCOUNT_KEY = "I7k71md8l03w9"
FROM_ADDRESS = "justin.lavey@manitec.pw"
BASE_URL = "https://mail360.zoho.com"


def get_access_token() -> str:
    url = f"{BASE_URL}/api/access-token"
    payload = {
        "refresh_token": REFRESH_TOKEN,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    resp = httpx.post(url, json=payload)
    resp.raise_for_status()
    return resp.json()["data"]["access_token"]


class ComposeScreen(Screen):
    """Screen for composing new emails."""

    def __init__(self, reply_to=None, forward_msg=None):
        super().__init__()
        self.reply_to = reply_to
        self.forward_msg = forward_msg

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        if self.forward_msg:
            title = "Forward Email"
        elif self.reply_to:
            title = "Reply to Email"
        else:
            title = "Compose New Email"

        yield Label(title, classes="title")

        with Container(classes="compose-form"):
            yield Label("To:")
            self.to_input = Input(placeholder="recipient@example.com")
            if self.reply_to:
                self.to_input.value = self.reply_to.get("fromAddress", "")
            yield self.to_input

            yield Label("Subject:")
            self.subject_input = Input(placeholder="Email subject")
            if self.reply_to:
                self.subject_input.value = f"Re: {self.reply_to.get('subject', '')}"
            elif self.forward_msg:
                self.subject_input.value = f"Fwd: {self.forward_msg.get('subject', '')}"
            yield self.subject_input

            yield Label("Message:")
            self.body_text = TextArea()

            if self.forward_msg:
                orig = f"\n--- Forwarded Message ---\nFrom: {self.forward_msg.get('fromAddress', '')}\nSubject: {self.forward_msg.get('subject', '')}\n\n{self.forward_msg.get('content', '')[:500]}"
                self.body_text.text = orig
            elif self.reply_to:
                orig = f"\n\n--- Original Message ---\n{self.reply_to.get('content', '')[:500]}"
                self.body_text.text = orig

            yield self.body_text

            with Horizontal(classes="button-row"):
                yield Button("📤 Send", id="send", variant="success")
                yield Button("❌ Cancel", id="cancel", variant="error")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.app.pop_screen()
        elif event.button.id == "send":
            asyncio.create_task(self.send_email())

    async def send_email(self):
        to = self.to_input.value
        subject = self.subject_input.value
        content = self.body_text.text

        if not to or not subject:
            self.app.notify("To and Subject are required!", severity="error")
            return

        try:
            token = get_access_token()
            url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages"
            headers = {"Authorization": f"Zoho-oauthtoken {token}"}
            payload = {
                "fromAddress": FROM_ADDRESS,
                "toAddress": to,
                "subject": subject,
                "content": content,
                "mailFormat": "plaintext",
            }
            resp = httpx.post(url, headers=headers, json=payload)
            if resp.status_code in (200, 201, 202):
                self.app.notify("✅ Email sent successfully!")
                self.app.pop_screen()
            else:
                self.app.notify(f"❌ Error: {resp.text}", severity="error")
        except Exception as e:
            self.app.notify(f"❌ Error: {str(e)}", severity="error")


class EmailClient(App):
    """Main TUI Email Client Application."""

    CSS = """
    Screen {
        background: $surface;
    }
    
    .title {
        text-align: center;
        text-style: bold;
        padding: 1;
        background: $primary;
        color: $text;
        border-bottom: tall $accent;
    }
    
    .email-list {
        width: 50%;
        height: 100%;
        border-right: solid $accent;
        background: $surface-darken-1;
    }
    
    .reader-pane {
        width: 50%;
        height: 100%;
        padding: 1;
        background: $surface;
    }
    
    .email-meta {
        background: $boost;
        color: $text;
        padding: 1;
        border: solid $primary;
        margin-bottom: 1;
    }
    
    .email-body {
        padding: 1;
        height: 100%;
        border: solid $accent;
        background: $surface-lighten-1;
    }
    
    .compose-form {
        padding: 2;
        background: $surface;
    }
    
    .compose-form Label {
        color: $accent;
        text-style: bold;
        margin-top: 1;
    }
    
    .compose-form Input {
        margin-bottom: 1;
        border: solid $primary;
    }
    
    .compose-form TextArea {
        height: 15;
        margin-bottom: 1;
        border: solid $primary;
    }
    
    .button-row {
        height: auto;
        padding: 1;
        background: $surface-darken-1;
    }
    
    .button-row Button {
        margin-right: 2;
    }
    
    DataTable {
        height: 100%;
    }
    
    DataTable > .datatable--cursor {
        background: $primary 40%;
        color: $text;
    }
    
    Static {
        height: auto;
    }
    
    Button {
        margin: 0 1;
    }
    """


    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh Inbox"),
        ("c", "compose", "Compose"),
        ("d", "delete", "Delete"),
    ]

    def __init__(self):
        super().__init__()
        self.emails = []
        self.selected_email = None
        self.current_folder = "inbox"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal():
            # Left side: Email list
            with Vertical(classes="email-list"):
                yield Label(f"📧 {FROM_ADDRESS}", classes="title")
                self.table = DataTable()
                self.table.add_columns("From", "Subject", "Date")
                self.table.cursor_type = "row"
                yield self.table

            # Right side: Reading pane
            with Vertical(classes="reader-pane"):
                yield Label("📖 Reading Pane", classes="title")
                self.reader = Static("Select an email to read it.", classes="email-body")
                yield self.reader

                with Horizontal(classes="button-row"):
                    yield Button("↩️ Reply", id="reply", variant="primary")
                    yield Button("➡️ Forward", id="forward", variant="warning")
                    yield Button("🗑️ Delete", id="delete", variant="error")

        with Horizontal(classes="button-row"):
            yield Button("✉️ Compose New", id="compose", variant="success")
            yield Button("🔄 Refresh", id="refresh")
            yield Label(" | Keys: (R)efresh, (C)ompose, (D)elete, (Q)uit")

        yield Footer()

    async def on_mount(self) -> None:
        await self.load_inbox()

    async def load_inbox(self):
        self.table.clear()
        self.reader.update("Loading inbox...")

        try:
            token = get_access_token()
            url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages"
            headers = {"Authorization": f"Zoho-oauthtoken {token}"}
            params = {"searchKey": f"in:{self.current_folder}", "limit": 20}
            resp = httpx.get(url, headers=headers, params=params)
            resp.raise_for_status()

            self.emails = resp.json().get("data", [])

            for email in self.emails:
                from_addr = email.get("fromAddress", "Unknown")[:25]
                subject = email.get("subject", "(No subject)")[:40]
                date = email.get("receivedTime", "")
                if date:
                    import datetime
                    date = datetime.datetime.fromtimestamp(int(date)/1000).strftime("%m/%d %H:%M")
                else:
                    date = ""
                self.table.add_row(from_addr, subject, date, key=email.get("messageId"))

            self.reader.update(f"Loaded {len(self.emails)} emails. Select one to read.")

        except Exception as e:
            self.reader.update(f"❌ Error loading inbox: {str(e)}")

    async def load_email_content(self, message_id: str):
        try:
            token = get_access_token()
            url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages/{message_id}/content"
            headers = {"Authorization": f"Zoho-oauthtoken {token}"}
            params = {"includeBlockContent": "true"}
            resp = httpx.get(url, headers=headers, params=params)
            resp.raise_for_status()

            data = resp.json().get("data", {})
            self.selected_email = data

            from_addr = data.get("fromAddress", "Unknown")
            to_addr = data.get("toAddress", "")
            subject = data.get("subject", "(No subject)")
            content = data.get("content", "(No content)")
            date = data.get("receivedTime", "")
            if date:
                import datetime
                date = datetime.datetime.fromtimestamp(int(date)/1000).strftime("%Y-%m-%d %H:%M:%S")

            display = f"""
[b]From:[/b] {from_addr}
[b]To:[/b] {to_addr}
[b]Subject:[/b] {subject}
[b]Date:[/b] {date}
{'─' * 60}

{content}
"""
            self.reader.update(display)

        except Exception as e:
            self.reader.update(f"❌ Error loading email: {str(e)}")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        message_id = event.row_key.value
        if message_id:
            asyncio.create_task(self.load_email_content(message_id))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "refresh":
            asyncio.create_task(self.load_inbox())
        elif button_id == "compose":
            self.push_screen(ComposeScreen())
        elif button_id == "reply":
            if self.selected_email:
                self.push_screen(ComposeScreen(reply_to=self.selected_email))
            else:
                self.notify("Select an email first!", severity="warning")
        elif button_id == "forward":
            if self.selected_email:
                self.push_screen(ComposeScreen(forward_msg=self.selected_email))
            else:
                self.notify("Select an email first!", severity="warning")
        elif button_id == "delete":
            if self.selected_email:
                asyncio.create_task(self.delete_email())
            else:
                self.notify("Select an email first!", severity="warning")

    async def delete_email(self):
        if not self.selected_email:
            return

        try:
            message_id = self.selected_email.get("messageId")
            token = get_access_token()
            url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages/{message_id}"
            headers = {"Authorization": f"Zoho-oauthtoken {token}"}
            params = {"expunge": "false"}  # Move to trash

            resp = httpx.delete(url, headers=headers, params=params)
            if resp.status_code == 200:
                self.notify("🗑️ Email moved to trash")
                self.selected_email = None
                self.reader.update("Email deleted. Select another.")
                await self.load_inbox()
            else:
                self.notify(f"❌ Error: {resp.text}", severity="error")
        except Exception as e:
            self.notify(f"❌ Error: {str(e)}", severity="error")

    def action_refresh(self):
        asyncio.create_task(self.load_inbox())

    def action_compose(self):
        self.push_screen(ComposeScreen())

    def action_delete(self):
        if self.selected_email:
            asyncio.create_task(self.delete_email())


if __name__ == "__main__":
    app = EmailClient()
    app.run()
