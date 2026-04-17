import discord
import hashlib
import aiohttp
import os
import json
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# delete the message if a bad file is found
DELETE_ON_DETECTION = os.getenv("DELETE_ON_DETECTION", "false").lower() == "true"
# dont send a public warning
SILENT_MODE = os.getenv("SILENT_MODE", "false").lower() == "true"
# channel to log detections to, leave blank to disable
log_ch_id = os.getenv("LOG_CHANNEL_ID", "").strip()
LOG_CHANNEL_ID = int(log_ch_id) if log_ch_id.isdigit() else None

WHITELIST_FILE = "whitelist.json"

# file types we actually care about
WATCHED_EXTENSIONS = [
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
    ".sh", ".run", ".bin", ".appimage",
    ".py", ".js", ".ts", ".jar",
    ".dll", ".so", ".dylib",
    ".dmg", ".pkg", ".deb", ".rpm",
    ".zip", ".rar", ".7z", ".tar", ".gz"
]


def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return []
    f = open(WHITELIST_FILE, "r")
    data = json.load(f)
    f.close()
    hashes = []
    for h in data.get("hashes", []):
        hashes.append(h.lower())
    return hashes


def save_whitelist(hashes):
    hashes = list(set(hashes))
    hashes.sort()
    f = open(WHITELIST_FILE, "w")
    json.dump({"hashes": hashes}, f, indent=2)
    f.close()


def hash_file(data):
    result = hashlib.sha256(data).hexdigest()
    return result


intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print("Bot is online as " + str(bot.user))


@bot.event
async def on_message(message):
    if message.author.bot:
        return

    if len(message.attachments) > 0:
        whitelist = load_whitelist()

        for attachment in message.attachments:
            filename = attachment.filename.lower()
            ext = os.path.splitext(filename)[1]

            # skip if we dont care about this file type
            if ext not in WATCHED_EXTENSIONS:
                continue

            async with aiohttp.ClientSession() as session:
                async with session.get(attachment.url) as resp:
                    file_bytes = await resp.read()

            file_hash = hash_file(file_bytes)

            if file_hash not in whitelist:
                # try to delete the message first
                if DELETE_ON_DETECTION:
                    try:
                        await message.delete()
                    except:
                        pass

                if not SILENT_MODE:
                    warn_msg = "⚠️ **This file is not on the whitelist and may be dangerous.**\n"
                    warn_msg += "```\n"
                    warn_msg += "File: " + attachment.filename + "\n"
                    warn_msg += "SHA-256: " + file_hash + "\n"
                    warn_msg += "```\n"
                    warn_msg += "An admin can allow it with `!whitelist add " + file_hash + "`"

                    if DELETE_ON_DETECTION:
                        # message is gone so we cant reply, ping them instead
                        await message.channel.send(message.author.mention + " " + warn_msg)
                    else:
                        await message.reply(warn_msg)

                # log to the log channel if set
                if LOG_CHANNEL_ID != None:
                    log_channel = bot.get_channel(LOG_CHANNEL_ID)
                    if log_channel != None:
                        log_msg = "🔍 **Detection** in " + message.channel.mention + "\n"
                        log_msg += "User: " + message.author.mention + " (`" + str(message.author) + "`)\n"
                        log_msg += "```\n"
                        log_msg += "File: " + attachment.filename + "\n"
                        log_msg += "SHA-256: " + file_hash + "\n"
                        log_msg += "Deleted: " + str(DELETE_ON_DETECTION) + "\n"
                        log_msg += "```"
                        await log_channel.send(log_msg)

    await bot.process_commands(message)


@bot.command(name="whitelist")
@commands.has_permissions(administrator=True)
async def whitelist_cmd(ctx, action=None, file_hash=None):
    if action is None or file_hash is None:
        await ctx.send("Usage: `!whitelist add <hash>` or `!whitelist remove <hash>`")
        return

    action = action.lower()
    file_hash = file_hash.lower()

    if action == "add":
        # basic check that it looks like a sha256 hash
        valid = True
        if len(file_hash) != 64:
            valid = False
        for c in file_hash:
            if c not in "0123456789abcdef":
                valid = False
                break

        if not valid:
            await ctx.send("That doesn't look like a valid SHA-256 hash.")
            return

        hashes = load_whitelist()
        if file_hash in hashes:
            await ctx.send("That hash is already whitelisted.")
            return
        hashes.append(file_hash)
        save_whitelist(hashes)
        await ctx.send("Added `" + file_hash + "` to the whitelist.")

    elif action == "remove":
        hashes = load_whitelist()
        if file_hash not in hashes:
            await ctx.send("That hash isn't in the whitelist.")
            return
        hashes.remove(file_hash)
        save_whitelist(hashes)
        await ctx.send("Removed `" + file_hash + "` from the whitelist.")

    else:
        await ctx.send("Unknown action. Use `add` or `remove`.")


@bot.command(name="whitelist_list")
@commands.has_permissions(administrator=True)
async def whitelist_list(ctx):
    hashes = load_whitelist()
    if len(hashes) == 0:
        await ctx.send("The whitelist is empty.")
        return
    msg = "**Whitelisted hashes:**\n```\n"
    for h in sorted(hashes):
        msg += h + "\n"
    msg += "```"
    await ctx.send(msg)


@whitelist_cmd.error
@whitelist_list.error
async def on_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You need to be an admin to do that.")


if __name__ == "__main__":
    if not TOKEN:
        print("Error: DISCORD_BOT_TOKEN not set in .env")
        exit(1)
    bot.run(TOKEN)
