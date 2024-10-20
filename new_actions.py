from datetime import datetime, timedelta, timezone
import os
import requests
import re
from pyowm import OWM
from dotenv import load_dotenv
import logging
from pytz import timezone
import json

load_dotenv()
owm_api_key = os.getenv('OPENWEATHER_API_KEY')
owm = OWM(owm_api_key)
newsdata_api_key = os.getenv('NEWSDATA_API_KEY')

DEFAULT_LOCATION = os.getenv('DEFAULT_LOCATION', 'New York')

logging.basicConfig(level=logging.INFO)

SAFE_DIRECTORY = 'user_files'

def get_current_time():
    """Returns the current time."""
    return datetime.now().strftime("%H:%M:%S")

def get_weather(location=DEFAULT_LOCATION):
    """Returns the weather for a specified location, or a default location if none is provided."""
    try:
        weather_mgr = owm.weather_manager()
        observation = weather_mgr.weather_at_place(location)
        weather = observation.weather

        temp = weather.temperature('fahrenheit')['temp']
        status = weather.detailed_status
        wind_speed = weather.wind()['speed']  # Wind speed in m/s

        response = f"Weather in {location}: {status}, {temp}°F, Wind Speed: {wind_speed:.2f} m/s"
        return response

    except Exception as e:
        logging.error(f"Error in get_weather: {e}")
        return "I'm sorry, I couldn't retrieve the weather information."

def get_forecast(location=DEFAULT_LOCATION, duration=1, specific_time=None):
    """Returns a weather forecast for a specified location and duration or a specific time."""
    try:
        forecast_mgr = owm.weather_manager()
        forecast = forecast_mgr.forecast_at_place(location, '3h').forecast

        if specific_time:
            closest_weather = min(forecast, key=lambda w: abs(datetime.fromtimestamp(w.reference_time()) - specific_time))
            return format_weather_info(closest_weather, specific_time)

        end_time = datetime.now() + timedelta(days=duration)
        forecast_info = []
        for weather in forecast:
            weather_time = datetime.fromtimestamp(weather.reference_time())
            if weather_time > end_time:
                break
            forecast_info.append(format_weather_info(weather))

        return "\n".join(forecast_info)

    except Exception as e:
        logging.error(f"Error in get_forecast: {e}")
        return "I'm sorry, I couldn't retrieve the weather forecast."

def format_weather_info(weather, target_time=None):
    """Formats the weather information."""
    time_format = '%Y-%m-%d %H:%M:%S'
    time = target_time.strftime(time_format) if target_time else datetime.fromtimestamp(weather.reference_time()).strftime(time_format)
    status = weather.detailed_status
    temp = weather.temperature('fahrenheit')['temp']
    precipitation = weather.precipitation_probability if hasattr(weather, 'precipitation_probability') else 'N/A'

    return f"{time}: {status}, Temp: {temp}°F, Precipitation chance: {precipitation}%"

def get_weather_condition(prompt, location=DEFAULT_LOCATION):
    location = location if location else DEFAULT_LOCATION

    forecast_needed = 'tomorrow' in prompt.lower() or 'later' in prompt.lower() or 'next' in prompt.lower()

    try:
        weather_mgr = owm.weather_manager()
        if forecast_needed:
            forecast = weather_mgr.forecast_at_place(location, '3h').forecast
            weather = forecast[0]
        else:
            observation = weather_mgr.weather_at_place(location)
            weather = observation.weather

        condition_code = weather.weather_code
        wind_speed = weather.wind()['speed']

        condition_map = {
            'rain': [200, 201, 202, 230, 231, 232, 500, 501, 502, 503, 504, 511, 520, 521, 522, 531],
            'snow': [600, 601, 602, 611, 612, 613, 615, 616, 620, 621, 622],
            'fog': [701, 741],
            'sunny': [800],
            'cloudy': [801, 802, 803, 804],
            'windy': []  # Windy is determined by wind speed
        }

        for condition in condition_map:
            if condition in prompt.lower():
                if condition == 'windy':
                    if wind_speed > 6.94:
                        return f"Yes, it is {('going to be' if forecast_needed else 'currently')} windy in {location}."
                    else:
                        return f"No, it is not {('going to be' if forecast_needed else 'currently')} windy in {location}."
                elif condition_code in condition_map[condition]:
                    return f"Yes, it is {('going to be' if forecast_needed else 'currently')} {condition} in {location}."
                else:
                    return f"No, it is not {('going to be' if forecast_needed else 'currently')} {condition} in {location}."

        return f"I'm not sure about the specific weather condition in {location}."

    except Exception as e:
        logging.error(f"Error in get_weather_condition: {e}")
        return "I'm sorry, I couldn't retrieve the weather condition information."

def get_sun_times(location=DEFAULT_LOCATION, query=''):
    """Returns the sunrise and sunset times for a specified location."""
    try:
        mgr = owm.weather_manager()
        geocoding_mgr = owm.geocoding_manager()
        geocode = geocoding_mgr.geocode(location)[0]
        one_call = mgr.one_call(lat=geocode.lat, lon=geocode.lon)
        local_tz = timezone(one_call.timezone)
        sunrise_utc = datetime.fromtimestamp(one_call.current.sunrise_time(), tz=timezone.utc)
        sunset_utc = datetime.fromtimestamp(one_call.current.sunset_time(), tz=timezone.utc)
        local_sunrise = sunrise_utc.astimezone(local_tz)
        local_sunset = sunset_utc.astimezone(local_tz)

        if 'sunrise' in query.lower() and 'sunset' not in query.lower():
            return f"Sunrise in {location}: {local_sunrise.strftime('%Y-%m-%d %H:%M:%S')}"
        elif 'sunset' in query.lower() and 'sunrise' not in query.lower():
            return f"Sunset in {location}: {local_sunset.strftime('%Y-%m-%d %H:%M:%S')}"
        else:
            return f"Sunrise in {location}: {local_sunrise.strftime('%Y-%m-%d %H:%M:%S')}, Sunset in {location}: {local_sunset.strftime('%Y-%m-%d %H:%M:%S')}"
    except Exception as e:
        logging.error(f"Error in get_sun_times: {e}")
        return "I'm sorry, I couldn't retrieve the sun times."

def get_news(timeframe=None, country=None, category=None):
    base_url = "https://newsdata.io/api/1/news"
    params = {
        'apikey': newsdata_api_key,
        'language': 'en',
    }
    if country:
        params['country'] = country
    if category:
        params['category'] = category
    if timeframe:
        # Parse timeframe into 'from_date' and 'to_date'
        to_date = datetime.utcnow()
        if timeframe.endswith('h'):
            hours = int(timeframe[:-1])
            from_date = to_date - timedelta(hours=hours)
        elif timeframe.endswith('d'):
            days = int(timeframe[:-1])
            from_date = to_date - timedelta(days=days)
        else:
            from_date = to_date - timedelta(days=1)
        params['from_date'] = from_date.strftime('%Y-%m-%d')
        params['to_date'] = to_date.strftime('%Y-%m-%d')

    try:
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            news_items = response.json().get('results', [])
            if not news_items:
                return "No news items found for your query."
            return '\n'.join([f"{item['title']} - {item['source_id']}" for item in news_items[:5]])
        else:
            logging.error(f"Error fetching news: {response.status_code} - {response.text}")
            return "I'm sorry, I couldn't retrieve the news."
    except Exception as e:
        logging.error(f"An error occurred in get_news: {e}")
        return "I'm sorry, I couldn't retrieve the news."

def handle_file_operation(command):
    """Handles creating, deleting, updating, and clearing files based on the command."""
    os.makedirs(SAFE_DIRECTORY, exist_ok=True)
    file_name_pattern = r'\bfile\s+(\w+\.\w{2,4})'  # Example: 'file example.txt'
    content_pattern = r'content\s+(.+$)'  # Captures everything after 'content'

    file_name_match = re.search(file_name_pattern, command, re.IGNORECASE)
    content_match = re.search(content_pattern, command, re.IGNORECASE)

    file_name = file_name_match.group(1) if file_name_match else "notes.txt"
    file_name = re.sub(r'[^a-zA-Z0-9_\-.]', '_', file_name)
    file_path = os.path.join(SAFE_DIRECTORY, file_name)
    content = content_match.group(1).strip() if content_match else ""

    try:
        if "create" in command.lower():
            with open(file_path, 'w') as file:
                file.write(content)
            return f"File '{file_name}' has been created with specified content."

        elif "delete" in command.lower():
            if os.path.exists(file_path):
                os.remove(file_path)
                return f"File '{file_name}' has been deleted."
            else:
                return f"File '{file_name}' does not exist."

        elif "update" in command.lower():
            if os.path.exists(file_path):
                with open(file_path, 'a') as file:
                    file.write(f"\n{content}")
                return f"File '{file_name}' has been updated with new content."
            else:
                return f"File '{file_name}' does not exist."

        elif "clear" in command.lower():
            if os.path.exists(file_path):
                with open(file_path, 'w') as file:
                    file.write('')
                return f"File '{file_name}' has been cleared of all contents."
            else:
                return f"File '{file_name}' does not exist to clear."

        else:
            return "Sorry, the file operation was not recognized. Please specify if you want to create, delete, update, or clear a file."

    except Exception as e:
        logging.error(f"Error in handle_file_operation: {e}")
        return "I'm sorry, I couldn't complete the file operation."

def handle_shopping_list_operation(command):
    shopping_list_file = os.path.join(SAFE_DIRECTORY, 'shopping_list.txt')
    os.makedirs(SAFE_DIRECTORY, exist_ok=True)

    try:
        if "add to shopping list" in command.lower():
            items_str = command.lower().split("add to shopping list", 1)[1]
            items_str = items_str.replace(", and ", ", ").replace(",and ", ", ")
            items = [item.strip() for item in re.split(',| and ', items_str) if item.strip()]
            if items:
                with open(shopping_list_file, 'a') as file:
                    for item in items:
                        file.write(f"{item}\n")
                items_formatted = ", ".join(f"'{item}'" for item in items)
                return f"Added {items_formatted} to the shopping list."
            else:
                return "No items were specified to add to the shopping list."

        elif "remove from shopping list" in command.lower():
            item = command.lower().split("remove from shopping list", 1)[1].strip()
            if os.path.exists(shopping_list_file):
                with open(shopping_list_file, 'r') as file:
                    items = file.readlines()
                items = [line.strip() for line in items if line.strip().lower() != item]
                with open(shopping_list_file, 'w') as file:
                    file.write("\n".join(items))
                return f"Removed '{item}' from the shopping list."
            else:
                return "The shopping list is currently empty."

        elif "clear shopping list" in command.lower():
            open(shopping_list_file, 'w').close()
            return "The shopping list has been cleared."

        elif "show shopping list" in command.lower():
            if os.path.exists(shopping_list_file):
                with open(shopping_list_file, 'r') as file:
                    items = file.read().strip()
                if items:
                    return f"Shopping list items:\n{items}"
                else:
                    return "The shopping list is currently empty."
            else:
                return "The shopping list is currently empty."

        else:
            return "Sorry, I didn't understand the shopping list operation."

    except Exception as e:
        logging.error(f"Error in handle_shopping_list_operation: {e}")
        return "I'm sorry, I couldn't complete the shopping list operation."
