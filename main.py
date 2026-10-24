#!/usr/bin/env python3
"""
SessionKiller - Telegram Login Session Monitor Bot
Monitors login sessions and automatically logs out untrusted devices.
Controlled via a separate Telegram Bot token.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Set, Dict, Any

import socks
from telethon import TelegramClient, events
from telethon.tl.functions.account import GetAuthorizationsRequest, ResetAuthorizationRequest
from telethon.tl.types import Authorization

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SessionMonitorBot:
    def __init__(self, api_id: int, api_hash: str, phone: str, bot_token: str, admin_id: int, proxy: tuple = None):
        self.api_id = api_id
        self.api_hash = api_hash
        self.phone = phone
        self.bot_token = bot_token
        self.admin_id = admin_id
        
        self.client = TelegramClient('session_monitor', api_id, api_hash, proxy=proxy)
        self.bot = TelegramClient('bot_session', api_id, api_hash, proxy=proxy)
        
        self.trusted_devices_file = 'trusted_devices.json'
        self.trusted_devices: Set[int] = self.load_trusted_devices()
        
        self.known_sessions: Dict[int, Authorization] = {}
        
        self.monitoring = False
        self.scan_interval = 0.5
        
    def load_trusted_devices(self) -> Set[int]:
        """Load trusted device hashes from file."""
        try:
            if os.path.exists(self.trusted_devices_file):
                with open(self.trusted_devices_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('trusted_devices', []))
        except Exception as e:
            logger.error(f"Error loading trusted devices: {e}")
        return set()
    
    def save_trusted_devices(self):
        """Save trusted device hashes to file."""
        try:
            with open(self.trusted_devices_file, 'w') as f:
                json.dump({'trusted_devices': list(self.trusted_devices)}, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving trusted devices: {e}")
    
    async def get_current_sessions(self) -> Dict[int, Authorization]:
        """Get all current active sessions."""
        try:
            result = await self.client(GetAuthorizationsRequest())
            sessions = {}
            auths = getattr(result, 'authorizations', [])
            for auth in auths:
                sessions[auth.hash] = auth
            return sessions
        except Exception as e:
            logger.error(f"Error getting sessions: {e}")
            return {}
    
    async def logout_session(self, session_hash: int) -> bool:
        """Log out a specific session."""
        try:
            await self.client(ResetAuthorizationRequest(hash=session_hash))
            logger.info(f"Successfully logged out session: {session_hash}")
            return True
        except Exception as e:
            logger.error(f"Error logging out session {session_hash}: {e}")
            return False
    
    def format_session_info(self, auth: Authorization) -> str:
        """Format session information for display."""
        if auth.date_created:
            date_created = auth.date_created if isinstance(auth.date_created, datetime) else datetime.fromtimestamp(auth.date_created)
        else:
            date_created = "Unknown"
            
        if auth.date_active:
            date_active = auth.date_active if isinstance(auth.date_active, datetime) else datetime.fromtimestamp(auth.date_active)
        else:
            date_active = "Unknown"
        
        return (
            f"🔐 Session Info:\n"
            f"📱 Device: {auth.device_model or 'Unknown'}\n"
            f"🏢 App: {auth.app_name or 'Unknown'} {auth.app_version or ''}\n"
            f"🌍 Platform: {auth.platform or 'Unknown'}\n"
            f"📍 Location: {auth.country or 'Unknown'}, {auth.region or 'Unknown'}\n"
            f"🌐 IP: {auth.ip or 'Unknown'}\n"
            f"📅 Created: {date_created}\n"
            f"🕐 Active: {date_active}\n"
            f"🆔 Hash: {auth.hash}"
        )
    
    async def monitor_sessions(self):
        """Main monitoring loop."""
        logger.info("Starting session monitoring...")
        
        self.known_sessions = await self.get_current_sessions()
        logger.info(f"Initialized with {len(self.known_sessions)} known sessions")
        
        while self.monitoring:
            try:
                current_sessions = await self.get_current_sessions()
                
                for session_hash, auth in current_sessions.items():
                    if session_hash not in self.known_sessions:
                        logger.info(f"New session detected: {session_hash}")
                        
                        if session_hash in self.trusted_devices:
                            logger.info(f"Session {session_hash} is trusted, allowing...")
                            await self.send_notification(
                                f"✅ Trusted device logged in:\n{self.format_session_info(auth)}"
                            )
                        else:
                            logger.warning(f"Untrusted session detected, logging out: {session_hash}")
                            
                            await self.send_notification(
                                f"🚨 SECURITY ALERT: Untrusted device detected and logged out!\n"
                                f"{self.format_session_info(auth)}\n\n"
                                f"If this was you, use /trust {session_hash} to trust this device in the future."
                            )
                            
                            success = await self.logout_session(session_hash)
                            if success:
                                logger.info(f"Successfully logged out untrusted session: {session_hash}")
                            else:
                                logger.error(f"Failed to log out untrusted session: {session_hash}")
                
                self.known_sessions = current_sessions
                await asyncio.sleep(self.scan_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(1)
    
    async def send_notification(self, message: str):
        """Send notification to the admin via bot."""
        try:
            await self.bot.send_message(self.admin_id, message)
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
    
    async def start(self):
        """Start the bot and user client."""
        await self.client.connect()
        if not await self.client.is_user_authorized():
            await self.client.send_code_request(self.phone)
            code = input('Enter the code you received: ')
            await self.client.sign_in(self.phone, code)
        
        await self.bot.start(bot_token=self.bot_token)
        logger.info("Bot client started successfully via token (with SOCKS5 proxy)!")
        
        self.setup_handlers()
        
        self.monitoring = True
        await self.monitor_sessions()
    
    def setup_handlers(self):
        """Set up command handlers on the bot client (restricted to admin_id)."""
        
        @self.bot.on(events.NewMessage(pattern='/start', from_users=self.admin_id))
        async def start_handler(event):
            await event.respond(
                "🔥 **SessionKiller Bot**\n\n"
                "This bot monitors your login sessions and automatically logs out untrusted devices.\n\n"
                "**Commands:**\n"
                "/status - Show monitoring status\n"
                "/sessions - List all active sessions\n"
                "/trust <hash> - Trust a device\n"
                "/untrust <hash> - Remove device from trusted list\n"
                "/trusted - Show trusted devices\n"
                "/stop - Stop monitoring\n"
                "/resume - Resume monitoring"
            )
        
        @self.bot.on(events.NewMessage(pattern='/status', from_users=self.admin_id))
        async def status_handler(event):
            status = "🟢 Active" if self.monitoring else "🔴 Stopped"
            sessions_count = len(self.known_sessions)
            trusted_count = len(self.trusted_devices)
            
            await event.respond(
                f"📊 **Monitor Status:** {status}\n"
                f"📱 **Active Sessions:** {sessions_count}\n"
                f"✅ **Trusted Devices:** {trusted_count}\n"
                f"⏱️ **Scan Interval:** {self.scan_interval}s"
            )
        
        @self.bot.on(events.NewMessage(pattern='/sessions', from_users=self.admin_id))
        async def sessions_handler(event):
            sessions = await self.get_current_sessions()
            if not sessions:
                await event.respond("No active sessions found.")
                return
            
            message = "📱 **Active Sessions:**\n\n"
            for i, (session_hash, auth) in enumerate(sessions.items(), 1):
                trusted = "✅" if session_hash in self.trusted_devices else "❌"
                message += f"{i}. {trusted} **Session {session_hash}**\n"
                message += f"   📱 {auth.device_model} - {auth.app_name}\n"
                message += f"   🌍 {auth.country} - {auth.ip}\n\n"
            
            await event.respond(message)
        
        @self.bot.on(events.NewMessage(pattern=r'/trust (\d+)', from_users=self.admin_id))
        async def trust_handler(event):
            session_hash = int(event.pattern_match.group(1))
            self.trusted_devices.add(session_hash)
            self.save_trusted_devices()
            await event.respond(f"✅ Device {session_hash} is now trusted.")
        
        @self.bot.on(events.NewMessage(pattern=r'/untrust (\d+)', from_users=self.admin_id))
        async def untrust_handler(event):
            session_hash = int(event.pattern_match.group(1))
            self.trusted_devices.discard(session_hash)
            self.save_trusted_devices()
            await event.respond(f"❌ Device {session_hash} is no longer trusted.")
        
        @self.bot.on(events.NewMessage(pattern='/trusted', from_users=self.admin_id))
        async def trusted_handler(event):
            if not self.trusted_devices:
                await event.respond("No trusted devices configured.")
                return
            
            message = "✅ **Trusted Devices:**\n\n"
            for device_hash in self.trusted_devices:
                message += f"• {device_hash}\n"
            
            await event.respond(message)
        
        @self.bot.on(events.NewMessage(pattern='/stop', from_users=self.admin_id))
        async def stop_handler(event):
            self.monitoring = False
            await event.respond("🛑 Session monitoring stopped.")
        
        @self.bot.on(events.NewMessage(pattern='/resume', from_users=self.admin_id))
        async def resume_handler(event):
            if not self.monitoring:
                self.monitoring = True
                await event.respond("▶️ Session monitoring resumed.")
                asyncio.create_task(self.monitor_sessions())
            else:
                await event.respond("ℹ️ Monitoring is already active.")

async def main():
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error("config.json not found. Please create it with your API credentials.")
        return
    except json.JSONDecodeError:
        logger.error("Invalid JSON in config.json")
        return
    
    required_keys = ['api_id', 'api_hash', 'phone', 'bot_token', 'admin_id']
    for key in required_keys:
        if key not in config:
            logger.error(f"Missing required configuration: {key}")
            return
    
    proxy_tuple = None
    proxy_config = config.get('proxy')
    if proxy_config and proxy_config.get('enabled', False):
        host = proxy_config.get('host')
        port = int(proxy_config.get('port'))
        username = proxy_config.get('username')
        password = proxy_config.get('password')
        
        if username and password:
            proxy_tuple = (socks.SOCKS5, host, port, True, username, password)
        else:
            proxy_tuple = (socks.SOCKS5, host, port)
        logger.info(f"SOCKS5 Proxy enabled for {host}:{port}")

    bot = SessionMonitorBot(
        api_id=config['api_id'],
        api_hash=config['api_hash'],
        phone=config['phone'],
        bot_token=config['bot_token'],
        admin_id=config['admin_id'],
        proxy=proxy_tuple
    )
    
    try:
        await bot.start()
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Bot error: {e}")
    finally:
        if bot.client.is_connected():
            await bot.client.disconnect()
        if bot.bot.is_connected():
            await bot.bot.disconnect()

if __name__ == "__main__":
    asyncio.main() if hasattr(asyncio, 'main') else asyncio.run(main())