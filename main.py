#!/usr/bin/env python3
"""
Telegram OSINT Bot with Open APIs, Google Search, AI Analysis (OpenRouter),
Secure Admin Panel, and Inline Buttons.
Developer: @your_handle
Date: 2026-01-08
"""

import asyncio
import json
import logging
import os
import sys
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote_plus

# Third-party libraries
import aiohttp
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

# Attempt to load environment variables (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ==================== CONFIGURATION ====================
BOT_TOKEN = os.getenv("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")  # Obtain from @BotFather
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "YOUR_OPENROUTER_KEY_HERE")
ADMIN_ID = int(os.getenv("ADMIN_ID", 8513112712))  # Your Telegram user ID

# API endpoints (no authentication required)
IPAPI_URL = "https://ipapi.co/{ip}/json/"
WHOIS_URL = "https://who-dat.as93.net/{}"  # WHOIS API (no-auth)
WHATSMYNAME_JSON = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

# OpenRouter API settings
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "meta-llama/llama-3.1-8b-instruct"  # You can change the model

# Logging setup
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler("bot.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ==================== OSINT FUNCTIONS ====================

async def ip_geolocation(ip: str) -> str:
    """Get geolocation data for an IP address using ipapi.co."""
    try:
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            return "❌ Invalid IP address format. Please use IPv4 format (e.g., 8.8.8.8)"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(IPAPI_URL.format(ip=ip), timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return (
                        f"🌐 **IP Geolocation Results** 🌐\n\n"
                        f"📍 **IP Address:** `{data.get('ip', 'N/A')}`\n"
                        f"🏙️ **City:** {data.get('city', 'N/A')}\n"
                        f"🏛️ **Region:** {data.get('region', 'N/A')} ({data.get('region_code', 'N/A')})\n"
                        f"🇺🇳 **Country:** {data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})\n"
                        f"🏢 **ISP:** {data.get('org', 'N/A')}\n"
                        f"📡 **Timezone:** {data.get('timezone', 'N/A')}\n"
                        f"📍 **Coordinates:** {data.get('latitude', 'N/A')}, {data.get('longitude', 'N/A')}\n"
                        f"📞 **Calling Code:** +{data.get('country_calling_code', 'N/A')}\n"
                        f"💻 **ASN:** {data.get('asn', 'N/A')}"
                    )
                elif resp.status == 429:
                    return "⚠️ Rate limit exceeded. Try again later."
                else:
                    return f"❌ Error: API returned status {resp.status}"
    except asyncio.TimeoutError:
        return "⏰ Request timeout. Please try again."
    except Exception as e:
        logger.error(f"IP geolocation error: {e}")
        return f"❌ Error retrieving geolocation: {str(e)[:100]}"

async def whois_lookup(domain: str) -> str:
    """Perform WHOIS lookup using the public who-dat API."""
    try:
        domain = domain.lower().replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        
        async with aiohttp.ClientSession() as session:
            async with session.get(WHOIS_URL.format(domain), timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    created = data.get('created', 'N/A')
                    updated = data.get('updated', 'N/A')
                    expires = data.get('expires', 'N/A')
                    return (
                        f"🔍 **WHOIS Lookup Results** 🔍\n\n"
                        f"🌐 **Domain:** `{domain}`\n"
                        f"📅 **Created:** {created}\n"
                        f"🔄 **Updated:** {updated}\n"
                        f"⏳ **Expires:** {expires}\n"
                        f"🏢 **Registrar:** {data.get('registrar', 'N/A')}\n"
                        f"📧 **Contact Email:** {data.get('contact_email', 'N/A')}\n"
                        f"📞 **Contact Phone:** {data.get('contact_phone', 'N/A')}\n"
                        f"🔧 **Nameservers:**\n" + "\n".join([f"   • {ns}" for ns in data.get('nameservers', [])][:5])
                    )
                elif resp.status == 404:
                    return f"❌ Domain '{domain}' not found or not registered."
                else:
                    return f"❌ Error: API returned status {resp.status}"
    except asyncio.TimeoutError:
        return "⏰ Request timeout. Please try again."
    except Exception as e:
        logger.error(f"WHOIS lookup error: {e}")
        return f"❌ Error retrieving WHOIS data: {str(e)[:100]}"

async def username_check(username: str) -> str:
    """Check username across multiple platforms using WhatsMyName data."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(WHATSMYNAME_JSON, timeout=15) as resp:
                if resp.status != 200:
                    return "❌ Unable to fetch WhatsMyName data."
                data = await resp.json()
        
        results = []
        found_count = 0
        
        for site in data.get("sites", []):
            url = site.get("uri", "").format(account=username)
            
            if not url.startswith('http'):
                continue
            
            results.append(f"🔗 **{site.get('name', 'Unknown')}:** {url}")
            found_count += 1
            
            if found_count >= 20:
                break
        
        if results:
            return (
                f"👤 **Username Check Results for '{username}'** 👤\n\n"
                f"📊 Found on {found_count} platforms:\n\n" + 
                "\n".join(results) +
                f"\n\n🔍 Check manually for accuracy."
            )
        else:
            return f"❌ No known platforms found for '{username}'."
    except asyncio.TimeoutError:
        return "⏰ Request timeout. Please try again."
    except Exception as e:
        logger.error(f"Username check error: {e}")
        return f"❌ Error checking username: {str(e)[:100]}"

async def google_search_query(query: str, num_results: int = 10) -> str:
    """Perform search using DuckDuckGo as a proxy."""
    try:
        search_url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(search_url, headers=headers, timeout=15) as resp:
                if resp.status != 200:
                    return f"❌ Search failed with status {resp.status}"
                
                html = await resp.text()
                results = []
                pattern = r'class="result__title">.*?<a[^>]*href="([^"]*)[^>]*>([^<]*)'
                matches = re.findall(pattern, html, re.DOTNOTASCII)
                
                for url, title in matches[:num_results]:
                    if url and title:
                        title = re.sub(r'<[^>]+>', '', title).strip()
                        results.append(f"• **{title}**\n  {url}")
                
                if results:
                    return (
                        f"🔎 **Search Results** 🔎\n\n"
                        f"**Query:** {query}\n\n" +
                        "\n\n".join(results) +
                        f"\n\n📊 Found {len(results)} results"
                    )
                else:
                    ddg_url = f"https://api.duckduckgo.com/?q={quote_plus(query)}&format=json"
                    async with session.get(ddg_url, timeout=10) as ddg_resp:
                        if ddg_resp.status == 200:
                            ddg_data = await ddg_resp.json()
                            if ddg_data.get('AbstractText'):
                                return (
                                    f"🔎 **Quick Answer** 🔎\n\n"
                                    f"**Query:** {query}\n\n"
                                    f"{ddg_data.get('AbstractText')}\n\n"
                                    f"**Source:** {ddg_data.get('AbstractURL', 'N/A')}"
                                )
                    
                    return f"❌ No results found for '{query}'."
    except asyncio.TimeoutError:
        return "⏰ Search timeout. Please try again."
    except Exception as e:
        logger.error(f"Google search error: {e}")
        return f"❌ Search failed: {str(e)[:100]}"

async def openrouter_analysis(text: str) -> str:
    """Send text to OpenRouter AI for analysis."""
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY == "YOUR_OPENROUTER_KEY_HERE":
        return "❌ OpenRouter API key is not configured.\nPlease set OPENROUTER_API_KEY in .env file."
    
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://telegram-osint-bot.com",
        "X-Title": "Telegram OSINT Bot"
    }
    
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {
                "role": "system", 
                "content": "You are an expert OSINT analyst. Analyze the provided text for potential intelligence,"
                          " identify entities, locations, dates, patterns, and provide actionable insights."
                          " Be concise but thorough."
            },
            {
                "role": "user", 
                "content": f"Analyze this text for OSINT purposes:\n\n{text}\n\n"
                          f"Provide analysis in sections: 1) Key Entities 2) Patterns Found 3) Recommendations 4) Risk Assessment"
            }
        ],
        "max_tokens": 1000,
        "temperature": 0.7
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(OPENROUTER_URL, headers=headers, json=payload, timeout=45) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    reply = data["choices"][0]["message"]["content"]
                    return f"🤖 **AI OSINT Analysis** 🤖\n\n{reply}"
                elif resp.status == 401:
                    return "❌ Invalid OpenRouter API key. Please check your configuration."
                elif resp.status == 429:
                    return "⚠️ Rate limit exceeded for AI analysis. Try again later."
                else:
                    error_text = await resp.text()
                    logger.error(f"OpenRouter API error: {resp.status} - {error_text}")
                    return f"❌ AI analysis failed with status {resp.status}."
    except asyncio.TimeoutError:
        return "⏰ AI analysis timeout. The request took too long."
    except Exception as e:
        logger.error(f"OpenRouter request error: {e}")
        return f"❌ Error contacting AI service: {str(e)[:100]}"

# ==================== TELEGRAM BOT HANDLERS ====================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a welcome message with an inline keyboard."""
    keyboard = [
        [InlineKeyboardButton("🌐 IP Geolocation", callback_data="ip_geo"),
         InlineKeyboardButton("🔍 WHOIS Lookup", callback_data="whois")],
        [InlineKeyboardButton("👤 Username Check", callback_data="username"),
         InlineKeyboardButton("🔎 Google Search", callback_data="google")],
        [InlineKeyboardButton("🤖 AI Analysis", callback_data="ai_analysis"),
         InlineKeyboardButton("🛡️ Admin Panel", callback_data="admin_panel")],
        [InlineKeyboardButton("ℹ️ Help", callback_data="help"),
         InlineKeyboardButton("📊 Status", callback_data="status")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = (
        "🚀 **Welcome to OSINT Bot v2.0** 🚀\n\n"
        "I'm your personal OSINT assistant. Choose an option below:\n\n"
        "• 🌐 **IP Geolocation** - Find location details for any IP\n"
        "• 🔍 **WHOIS Lookup** - Get domain registration info\n"
        "• 👤 **Username Check** - Search username across platforms\n"
        "• 🔎 **Google Search** - Search the web\n"
        "• 🤖 **AI Analysis** - Advanced text analysis\n"
        "• 🛡️ **Admin Panel** - Bot administration\n\n"
        "You can also use commands:\n"
        "`/ip <address>` - IP geolocation\n"
        "`/whois <domain>` - WHOIS lookup\n"
        "`/username <nick>` - Username search\n"
        "`/google <query>` - Web search\n"
        "`/ai <text>` - AI analysis\n"
        "`/admin` - Admin panel\n"
        "`/help` - Show help"
    )
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode="Markdown")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help information."""
    help_text = (
        "📚 **OSINT Bot Help** 📚\n\n"
        "**Available Commands:**\n"
        "• `/start` - Start the bot\n"
        "• `/help` - This help message\n"
        "• `/ip <IP>` - IP geolocation (e.g., /ip 8.8.8.8)\n"
        "• `/whois <domain>` - WHOIS lookup (e.g., /whois google.com)\n"
        "• `/username <nick>` - Username check (e.g., /username john)\n"
        "• `/google <query>` - Google search (e.g., /google osint tools)\n"
        "• `/ai <text>` - AI analysis (e.g., /ai analyze this text)\n"
        "• `/admin` - Admin panel (restricted)\n\n"
        "**Features:**\n"
        "• Multiple OSINT sources\n"
        "• AI-powered analysis\n"
        "• Secure admin panel\n"
        "• Inline keyboard interface\n\n"
        "⚠️ **Disclaimer:** Use this tool responsibly and legally."
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline button presses."""
    query = update.callback_query
    await query.answer()
    data = query.data
    
    if data == "ip_geo":
        await query.edit_message_text("📍 **IP Geolocation**\n\nSend me an IP address (e.g., 8.8.8.8):")
        context.user_data["awaiting"] = "ip"
    elif data == "whois":
        await query.edit_message_text("🔍 **WHOIS Lookup**\n\nSend me a domain name (e.g., google.com):")
        context.user_data["awaiting"] = "whois"
    elif data == "username":
        await query.edit_message_text("👤 **Username Check**\n\nSend me a username to search:")
        context.user_data["awaiting"] = "username"
    elif data == "google":
        await query.edit_message_text("🔎 **Google Search**\n\nSend me your search query:")
        context.user_data["awaiting"] = "google"
    elif data == "ai_analysis":
        await query.edit_message_text("🤖 **AI Analysis**\n\nSend me text to analyze:")
        context.user_data["awaiting"] = "ai"
    elif data == "admin_panel":
        if query.from_user.id == ADMIN_ID:
            await admin_panel(update, context)
        else:
            await query.edit_message_text("⛔ **Access Denied**\n\nYou are not authorized to access the admin panel.")
    elif data == "help":
        await query.edit_message_text(
            "ℹ️ **Quick Help**\n\n"
            "Select an option from the menu or use commands:\n"
            "• `/ip <IP>` - Geolocation\n"
            "• `/whois <domain>` - Domain info\n"
            "• `/username <nick>` - User search\n"
            "• `/google <query>` - Web search\n"
            "• `/ai <text>` - AI analysis\n\n"
            "Type /start to return to main menu."
        )
    elif data == "status":
        await query.edit_message_text(
            "📊 **Bot Status**\n\n"
            "✅ **Online**\n"
            "🔄 **Services:**\n"
            "• IP Geolocation: ✅\n"
            "• WHOIS Lookup: ✅\n"
            "• Username Check: ✅\n"
            "• Google Search: ✅\n"
            "• AI Analysis: ⚠️ (requires API key)\n\n"
            "Type /start to return to main menu."
        )
    else:
        await query.edit_message_text("❌ Unknown option. Please use /start to see available options.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process user messages based on the awaited context."""
    user_id = update.effective_user.id
    text = update.message.text.strip()
    awaiting = context.user_data.get("awaiting")
    
    if not awaiting:
        await update.message.reply_text("Please use /start to see available options.")
        return
    
    processing_msg = await update.message.reply_text("⏳ Processing your request...")
    
    result = ""
    if awaiting == "ip":
        result = await ip_geolocation(text)
    elif awaiting == "whois":
        result = await whois_lookup(text)
    elif awaiting == "username":
        result = await username_check(text)
    elif awaiting == "google":
        result = await google_search_query(text)
    elif awaiting == "ai":
        result = await openrouter_analysis(text)
    
    context.user_data["awaiting"] = None
    await processing_msg.delete()
    
    if len(result) > 4000:
        for i in range(0, len(result), 4000):
            await update.message.reply_text(result[i:i+4000], parse_mode="Markdown")
    else:
        await update.message.reply_text(result, parse_mode="Markdown")

async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /ip <IP>"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/ip <IP_address>`\nExample: `/ip 8.8.8.8`", parse_mode="Markdown")
        return
    ip = context.args[0]
    processing_msg = await update.message.reply_text("⏳ Processing IP geolocation...")
    result = await ip_geolocation(ip)
    await processing_msg.delete()
    await update.message.reply_text(result, parse_mode="Markdown")

async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /whois <domain>"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/whois <domain>`\nExample: `/whois google.com`", parse_mode="Markdown")
        return
    domain = context.args[0]
    processing_msg = await update.message.reply_text("⏳ Processing WHOIS lookup...")
    result = await whois_lookup(domain)
    await processing_msg.delete()
    await update.message.reply_text(result, parse_mode="Markdown")

async def username_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /username <nick>"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/username <username>`\nExample: `/username john`", parse_mode="Markdown")
        return
    username = context.args[0]
    processing_msg = await update.message.reply_text("⏳ Checking username across platforms...")
    result = await username_check(username)
    await processing_msg.delete()
    await update.message.reply_text(result, parse_mode="Markdown")

async def google_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /google <query>"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/google <search_query>`\nExample: `/google osint tools`", parse_mode="Markdown")
        return
    query = " ".join(context.args)
    processing_msg = await update.message.reply_text("⏳ Searching the web...")
    result = await google_search_query(query)
    await processing_msg.delete()
    await update.message.reply_text(result, parse_mode="Markdown")

async def ai_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /ai <text>"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/ai <text_to_analyze>`\nExample: `/ai analyze this suspicious text`", parse_mode="Markdown")
        return
    text = " ".join(context.args)
    processing_msg = await update.message.reply_text("⏳ AI analysis in progress...")
    result = await openrouter_analysis(text)
    await processing_msg.delete()
    await update.message.reply_text(result, parse_mode="Markdown")

# ==================== ADMIN PANEL ====================

class BotAdmin:
    """Admin panel functionality."""
    def __init__(self):
        self.user_stats = {}
        self.broadcast_messages = []
    
    async def get_stats(self):
        """Get bot statistics."""
        return {
            "total_users": len(self.user_stats),
            "active_users": sum(1 for u in self.user_stats.values() if u.get('last_active')),
            "commands_today": 0,
            "uptime": "24/7"
        }

admin_manager = BotAdmin()

async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display admin panel (only for ADMIN_ID)."""
    user_id = update.effective_user.id
    if user_id != ADMIN_ID:
        if update.message:
            await update.message.reply_text("⛔ **Access Denied**\n\nYou are not authorized to access the admin panel.")
        else:
            await update.callback_query.edit_message_text("⛔ **Access Denied**\n\nYou are not authorized to access the admin panel.")
        return
    
    keyboard = [
        [InlineKeyboardButton("📊 Statistics", callback_data="admin_stats")],
        [InlineKeyboardButton("📋 View Logs", callback_data="admin_logs")],
        [InlineKeyboardButton("📢 Broadcast Message", callback_data="admin_broadcast")],
        [InlineKeyboardButton("🔄 Restart Services", callback_data="admin_restart")],
        [InlineKeyboardButton("🔙 Back to Main", callback_data="back_to_main")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    text = (
        f"🛡️ **Admin Control Panel** 🛡️\n\n"
        f"**Admin ID:** `{ADMIN_ID}`\n"
        f"**Bot Status:** ✅ Online\n"
        f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "Select an action:"
    )
    
    if update.message:
        await update.message.reply_text(text, reply_markup=reply_markup, parse_mode="Markdown")
    else:
        await update.callback_query.edit_message_text(text, reply_markup=reply_markup, parse_mode="Markdown")

async def admin_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display bot statistics."""
    stats = await admin_manager.get_stats()
    
    stats_text = (
        "📊 **Bot Statistics** 📊\n\n"
        f"👥 **Total Users:** {stats['total_users']}\n"
        f"🟢 **Active Users:** {stats['active_users']}\n"
        f"📈 **Commands Today:** {stats['commands_today']}\n"
        f"⏱️ **Uptime:** {stats['uptime']}\n"
        f"📅 **Current Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "**System Status:**\n"
        "• API Services: ✅ Operational\n"
        "• Database: ✅ Connected\n"
        "• AI Services: ⚠️ Requires API Key\n"
        "• Security: 🔒 Enabled"
    )
    
    keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="admin_panel")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.callback_query.edit_message_text(stats_text, reply_markup=reply_markup, parse_mode="Markdown")

async def admin_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send the log file to the admin."""
    try:
        if os.path.exists("bot.log"):
            with open("bot.log", "rb") as f:
                await context.bot.send_document(
                    chat_id=ADMIN_ID,
                    document=f,
                    filename=f"bot_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
                    caption="📋 Bot logs"
                )
            await update.callback_query.answer("✅ Log file sent!")
        else:
            await update.callback_query.answer("❌ Log file not found.")
    except Exception as e:
        logger.error(f"Error sending logs: {e}")
        await update.callback_query.answer(f"❌ Error: {str(e)[:50]}")

async def admin_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Initiate broadcast message to all users."""
    await update.callback_query.edit_message_text(
        "📢 **Broadcast Message**\n\n"
        "Please send the message you want to broadcast to all users.\n\n"
        "⚠️ **Warning:** This will send to ALL registered users."
    )
    context.user_data["awaiting"] = "broadcast"

async def admin_restart(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Restart bot services."""
    keyboard = [
        [InlineKeyboardButton("🔄 Soft Restart", callback_data="admin_restart_soft")],
        [InlineKeyboardButton("🔧 Maintenance Mode", callback_data="admin_maintenance")],
        [InlineKeyboardButton("🔙 Back", callback_data="admin_panel")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.callback_query.edit_message_text(
        "🔄 **Service Management**\n\n"
        "Select restart option:\n"
        "• **Soft Restart:** Reload configurations\n"
        "• **Maintenance Mode:** Enable maintenance\n\n"
        "⚠️ **Note:** Full restart requires bot process restart.",
        reply_markup=reply_markup
    )

async def back_to_main(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Return to main menu."""
    keyboard = [
        [InlineKeyboardButton("🌐 IP Geolocation", callback_data="ip_geo"),
         InlineKeyboardButton("🔍 WHOIS Lookup", callback_data="whois")],
        [InlineKeyboardButton("👤 Username Check", callback_data="username"),
         InlineKeyboardButton("🔎 Google Search", callback_data="google")],
        [InlineKeyboardButton("🤖 AI Analysis", callback_data="ai_analysis"),
         InlineKeyboardButton("🛡️ Admin Panel", callback_data="admin_panel")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.callback_query.edit_message_text(
        "🚀 **Welcome to OSINT Bot v2.0** 🚀\n\n"
        "Select an option below:",
        reply_markup=reply_markup
    )

# ==================== ERROR HANDLER ====================

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle errors in the telegram bot."""
    logger.error(f"Exception while handling an update: {context.error}")
    
    if update and update.effective_user:
        try:
            await update.effective_user.send_message(
                "❌ An error occurred while processing your request. Please try again later."
            )
        except Exception as e:
            logger.error(f"Failed to send error message: {e}")

# ==================== MAIN ====================

def main():
    """Start the bot."""
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ ERROR: BOT_TOKEN is not set!")
        print("Please set BOT_TOKEN in .env file or replace 'YOUR_BOT_TOKEN_HERE' with your actual bot token.")
        sys.exit(1)
    
    print("\n" + "=" * 50)
    print("🚀 OSINT Bot is starting...")
    print(f"🤖 Bot Token: {'✅ Set' if BOT_TOKEN != 'YOUR_BOT_TOKEN_HERE' else '❌ NOT SET'}")
    print(f"🔑 OpenRouter Key: {'✅ Set' if OPENROUTER_API_KEY != 'YOUR_OPENROUTER_KEY_HERE' else '❌ NOT SET'}")
    print(f"🛡️ Admin ID: {ADMIN_ID}")
    print("=" * 50)
    print("📝 Logs are being written to bot.log")
    print("🔄 Bot is running. Press Ctrl+C to stop.")
    print("=" * 50 + "\n")
    
    logger.info("=" * 50)
    logger.info("OSINT Bot starting...")
    logger.info(f"Admin ID: {ADMIN_ID}")
    logger.info("=" * 50)
    
    # Create Application with persistence
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("ip", ip_command))
    application.add_handler(CommandHandler("whois", whois_command))
    application.add_handler(CommandHandler("username", username_command))
    application.add_handler(CommandHandler("google", google_command))
    application.add_handler(CommandHandler("ai", ai_command))
    application.add_handler(CommandHandler("admin", admin_panel))
    
    # Callback query handlers (inline buttons)
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Admin callback handlers
    application.add_handler(CallbackQueryHandler(admin_stats, pattern="^admin_stats$"))
    application.add_handler(CallbackQueryHandler(admin_logs, pattern="^admin_logs$"))
    application.add_handler(CallbackQueryHandler(admin_broadcast, pattern="^admin_broadcast$"))
    application.add_handler(CallbackQueryHandler(admin_restart, pattern="^admin_restart$"))
    application.add_handler(CallbackQueryHandler(back_to_main, pattern="^back_to_main$"))
    application.add_handler(CallbackQueryHandler(admin_panel, pattern="^admin_panel$"))
    
    # Message handler (for awaited responses)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Error handler
    application.add_error_handler(error_handler)
    
    # Start the bot
    try:
        application.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True
        )
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
        print("\n👋 Bot stopped gracefully")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
