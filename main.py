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
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Third-party libraries
import aiohttp
import requests
from googlesearch import search as google_search
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
    ReplyKeyboardRemove,
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
    """
    Get geolocation data for an IP address using ipapi.co (no auth needed).
    Rate limit: ~1000 requests/day.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(IPAPI_URL.format(ip=ip), timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return (
                        f"IP: {data.get('ip', 'N/A')}\n"
                        f"City: {data.get('city', 'N/A')}\n"
                        f"Region: {data.get('region', 'N/A')} ({data.get('region_code', 'N/A')})\n"
                        f"Country: {data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})\n"
                        f"ISP: {data.get('org', 'N/A')}\n"
                        f"Timezone: {data.get('timezone', 'N/A')}\n"
                        f"Coordinates: {data.get('latitude', 'N/A')}, {data.get('longitude', 'N/A')}"
                    )
                else:
                    return f"Error: API returned status {resp.status}"
    except Exception as e:
        logger.error(f"IP geolocation error: {e}")
        return f"Error retrieving geolocation: {e}"

async def whois_lookup(domain: str) -> str:
    """
    Perform WHOIS lookup using the public who-dat API (no auth).
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(WHOIS_URL.format(domain), timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Format the response
                    created = data.get('created', 'N/A')
                    updated = data.get('updated', 'N/A')
                    expires = data.get('expires', 'N/A')
                    registrar = data.get('registrar', 'N/A')
                    nameservers = ', '.join(data.get('nameservers', []))
                    return (
                        f"Domain: {domain}\n"
                        f"Created: {created}\n"
                        f"Updated: {updated}\n"
                        f"Expires: {expires}\n"
                        f"Registrar: {registrar}\n"
                        f"Nameservers: {nameservers}"
                    )
                else:
                    return f"Error: API returned status {resp.status}"
    except Exception as e:
        logger.error(f"WHOIS lookup error: {e}")
        return f"Error retrieving WHOIS data: {e}"

async def username_check(username: str) -> str:
    """
    Check username across multiple platforms using WhatsMyName data.
    This downloads the latest JSON and performs local checks.
    """
    try:
        # Download the latest WhatsMyName JSON
        async with aiohttp.ClientSession() as session:
            async with session.get(WHATSMYNAME_JSON, timeout=15) as resp:
                if resp.status != 200:
                    return "Unable to fetch WhatsMyName data."
                data = await resp.json()
        
        results = []
        for site in data.get("sites", []):
            url = site.get("uri", "").format(account=username)
            check_url = site.get("url", "").format(account=username)
            # In a full implementation, you would make asynchronous requests
            # to each check_url and parse the response.
            # Here we just show the possible URLs.
            results.append(f"• {site.get('name', 'Unknown')}: {url}")
        
        if results:
            return f"Possible profiles for '{username}':\n" + "\n".join(results[:15])  # Limit output
        else:
            return f"No known platforms found for '{username}'."
    except Exception as e:
        logger.error(f"Username check error: {e}")
        return f"Error checking username: {e}"

async def google_search_query(query: str, num_results: int = 10) -> str:
    """
    Perform a Google search using the googlesearch-python library.
    Note: This is an unofficial method and may be blocked by Google.
    """
    try:
        results = []
        for url in google_search(query, num_results=num_results, advanced=True):
            results.append(f"• {url.title} - {url.url}")
        if results:
            return f"Top {num_results} results for '{query}':\n" + "\n".join(results)
        else:
            return f"No results found for '{query}'."
    except Exception as e:
        logger.error(f"Google search error: {e}")
        return f"Search failed: {e}"

async def openrouter_analysis(text: str) -> str:
    """
    Send text to OpenRouter AI for analysis (summarization, sentiment, etc.).
    Requires a valid API key.
    """
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY == "YOUR_OPENROUTER_KEY_HERE":
        return "OpenRouter API key is not set. Please configure it in .env file."
    
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": "You are an OSINT analyst assistant. Provide concise, factual analysis."},
            {"role": "user", "content": f"Analyze the following text from an OSINT perspective:\n\n{text}"}
        ],
        "max_tokens": 500
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(OPENROUTER_URL, headers=headers, json=payload, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    reply = data["choices"][0]["message"]["content"]
                    return f"AI Analysis:\n{reply}"
                else:
                    error_text = await resp.text()
                    logger.error(f"OpenRouter API error: {resp.status} - {error_text}")
                    return f"AI analysis failed with status {resp.status}."
    except Exception as e:
        logger.error(f"OpenRouter request error: {e}")
        return f"Error contacting AI service: {e}"

# ==================== TELEGRAM BOT HANDLERS ====================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a welcome message with an inline keyboard."""
    keyboard = [
        [
            InlineKeyboardButton("🌐 IP Geolocation", callback_data="ip_geo"),
            InlineKeyboardButton("🔍 WHOIS Lookup", callback_data="whois"),
        ],
        [
            InlineKeyboardButton("👤 Username Check", callback_data="username"),
            InlineKeyboardButton("🔎 Google Search", callback_data="google"),
        ],
        [
            InlineKeyboardButton("🤖 AI Analysis", callback_data="ai_analysis"),
            InlineKeyboardButton("🛡️ Admin Panel", callback_data="admin_panel"),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "Welcome to the OSINT Bot!\n"
        "Select an option below or use commands:\n"
        "/ip <IP> - IP geolocation\n"
        "/whois <domain> - WHOIS lookup\n"
        "/username <nick> - Check username\n"
        "/google <query> - Google search\n"
        "/ai <text> - AI analysis\n"
        "/admin - Admin panel (if authorized)",
        reply_markup=reply_markup
    )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline button presses."""
    query = update.callback_query
    await query.answer()
    data = query.data
    
    if data == "ip_geo":
        await query.edit_message_text("Send an IP address for geolocation.")
        context.user_data["awaiting"] = "ip"
    elif data == "whois":
        await query.edit_message_text("Send a domain for WHOIS lookup.")
        context.user_data["awaiting"] = "whois"
    elif data == "username":
        await query.edit_message_text("Send a username to check.")
        context.user_data["awaiting"] = "username"
    elif data == "google":
        await query.edit_message_text("Send a search query.")
        context.user_data["awaiting"] = "google"
    elif data == "ai_analysis":
        await query.edit_message_text("Send text for AI analysis.")
        context.user_data["awaiting"] = "ai"
    elif data == "admin_panel":
        if query.from_user.id == ADMIN_ID:
            await admin_panel(update, context)
        else:
            await query.edit_message_text("⛔ Access denied.")
    else:
        await query.edit_message_text("Unknown option.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process user messages based on the awaited context."""
    user_id = update.effective_user.id
    text = update.message.text.strip()
    awaiting = context.user_data.get("awaiting")
    
    if not awaiting:
        await update.message.reply_text("Use /start or choose an option from the menu.")
        return
    
    # Show "processing" status
    processing_msg = await update.message.reply_text("⏳ Processing...")
    
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
    
    # Clear the awaiting state
    context.user_data["awaiting"] = None
    
    # Delete the "processing" message and send the result
    await processing_msg.delete()
    await update.message.reply_text(result[:4000])  # Telegram message limit

# Command handlers (alternative to inline buttons)
async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /ip <IP>"""
    if not context.args:
        await update.message.reply_text("Usage: /ip <IP_address>")
        return
    ip = context.args[0]
    result = await ip_geolocation(ip)
    await update.message.reply_text(result)

async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /whois <domain>"""
    if not context.args:
        await update.message.reply_text("Usage: /whois <domain>")
        return
    domain = context.args[0]
    result = await whois_lookup(domain)
    await update.message.reply_text(result)

async def username_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /username <nick>"""
    if not context.args:
        await update.message.reply_text("Usage: /username <username>")
        return
    username = context.args[0]
    result = await username_check(username)
    await update.message.reply_text(result)

async def google_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /google <query>"""
    if not context.args:
        await update.message.reply_text("Usage: /google <search_query>")
        return
    query = " ".join(context.args)
    result = await google_search_query(query)
    await update.message.reply_text(result)

async def ai_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command: /ai <text>"""
    if not context.args:
        await update.message.reply_text("Usage: /ai <text_to_analyze>")
        return
    text = " ".join(context.args)
    result = await openrouter_analysis(text)
    await update.message.reply_text(result)

# ==================== ADMIN PANEL ====================

async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display admin panel (only for ADMIN_ID)."""
    user_id = update.effective_user.id
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ Access denied.") if update.message else await update.callback_query.edit_message_text("⛔ Access denied.")
        return
    
    keyboard = [
        [InlineKeyboardButton("📊 Statistics", callback_data="admin_stats")],
        [InlineKeyboardButton("📋 Logs", callback_data="admin_logs")],
        [InlineKeyboardButton("📢 Broadcast", callback_data="admin_broadcast")],
        [InlineKeyboardButton("🔄 Restart", callback_data="admin_restart")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    text = (
        "🛡️ **Admin Panel**\n"
        f"Admin ID: {ADMIN_ID}\n"
        "Select an action:"
    )
    
    if update.message:
        await update.message.reply_text(text, reply_markup=reply_markup, parse_mode="Markdown")
    else:
        await update.callback_query.edit_message_text(text, reply_markup=reply_markup, parse_mode="Markdown")

async def admin_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display bot statistics."""
    # Placeholder: In a real bot, you would track metrics
    stats_text = (
        "📊 **Bot Statistics**\n"
        "Users: 0\n"
        "Commands executed: 0\n"
        "Uptime: Not implemented\n"
    )
    await update.callback_query.edit_message_text(stats_text, parse_mode="Markdown")

async def admin_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send the log file to the admin."""
    try:
        with open("bot.log", "rb") as f:
            await context.bot.send_document(chat_id=ADMIN_ID, document=f, filename="bot.log")
        await update.callback_query.answer("Log file sent.")
    except Exception as e:
        await update.callback_query.answer(f"Error sending logs: {e}")

async def admin_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Initiate broadcast message to all users."""
    await update.callback_query.edit_message_text(
        "Send the broadcast message (text only)."
    )
    context.user_data["awaiting"] = "broadcast"

async def admin_restart(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Restart the bot (placeholder)."""
    await update.callback_query.edit_message_text(
        "Restart functionality not implemented in this example."
    )

# ==================== MAIN ====================

def main():
    """Start the bot."""
    # Create Application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("ip", ip_command))
    application.add_handler(CommandHandler("whois", whois_command))
    application.add_handler(CommandHandler("username", username_command))
    application.add_handler(CommandHandler("google", google_command))
    application.add_handler(CommandHandler("ai", ai_command))
    application.add_handler(CommandHandler("admin", admin_panel))
    
    # Callback query handler (inline buttons)
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Message handler (for awaited responses)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Start the bot
    logger.info("Bot starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
