from datetime import datetime, timedelta, timezone
import os
import requests
import re
from pyowm import OWM
from dotenv import load_dotenv

load_dotenv()
owm_api_key = os.getenv('OPENWEATHER_API_KEY')
owm = OWM(owm_api_key)
newsdata_api_key = os.getenv('NEWSDATA_API_KEY')

DEFAULT_LOCATION = os.getenv('DEFAULT_LOCATION')

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
        return f"An error occurred: {e}"

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
        return f"An error occurred: {e}"

def format_weather_info(weather, target_time=None):
    """Formats the weather information."""
    time_format = '%Y-%m-%d %H:%M:%S'
    time = target_time.strftime(time_format) if target_time else datetime.fromtimestamp(weather.reference_time()).strftime(time_format)
    status = weather.detailed_status
    temp = weather.temperature('fahrenheit')['temp']
    precipitation = weather.precipitation_probability if hasattr(weather, 'precipitation_probability') else 'N/A'

    return f"{time}: {status}, Temp: {temp}°F, Precipitation chance: {precipitation}%\n"

def get_weather_condition(prompt, location=DEFAULT_LOCATION):
    location = location if location else DEFAULT_LOCATION

    forecast_needed = 'tomorrow' in prompt.lower() or 'later' in prompt.lower() or 'next' in prompt.lower()

    if forecast_needed:
        weather_data = get_forecast(location)
        rain_times = extract_rain_times(weather_data)
        if 'rain' in prompt.lower():
            if rain_times:
                start_time, end_time = rain_times['start'], rain_times['end']
                start_desc = describe_time_relative_to_now(start_time)
                end_desc = describe_time_relative_to_now(end_time)
                return f"Yes, it will rain in {location}. The rain is expected to start {start_desc} and end {end_desc}."
            else:
                return f"No, it will not rain in {location}."
        if 'snow' in prompt.lower():
            return "Yes, it will snow in " + location + "." if 'snow' in weather_data.lower() else "No, it will not snow in " + location + "."
        if 'fog' in prompt.lower():
            return "Yes, it will be foggy in " + location + "." if 'fog' in weather_data.lower() else "No, it will not be foggy in " + location + "."
        if 'windy' in prompt.lower():
            wind_speed_match = re.search(r'Wind Speed: (\d+\.\d+) m/s', weather_data)
            if wind_speed_match:
                wind_speed = float(wind_speed_match.group(1))
                return "Yes, it will be windy in " + location + "." if wind_speed > 6.94 else "No, it will not be windy in " + location + "."
            return "I couldn't determine the wind speed in " + location + "."
        if 'sunny' in prompt.lower():
            return "Yes, it will be sunny in " + location + "." if 'clear' in weather_data.lower() else "No, it will not be sunny in " + location + "."
        if 'cloudy' in prompt.lower():
            return "Yes, it will be cloudy in " + location + "." if 'clouds' in weather_data.lower() else "No, it will not be cloudy in " + location + "."
    else:
        weather_data = get_weather(location)
        if 'rain' in prompt.lower():
            return "Yes, it is currently raining in " + location + "." if 'rain' in weather_data.lower() else "No, it is not currently raining in " + location + "."
        if 'snow' in prompt.lower():
            return "Yes, it is currently snowing in " + location + "." if 'snow' in weather_data.lower() else "No, it is not currently snowing in " + location + "."
        if 'fog' in prompt.lower():
            return "Yes, it is currently foggy in " + location + "." if 'fog' in weather_data.lower() else "No, it is not currently foggy in " + location + "."
        if 'windy' in prompt.lower():
            wind_speed_match = re.search(r'Wind Speed: (\d+\.\d+) m/s', weather_data)
            if wind_speed_match:
                wind_speed = float(wind_speed_match.group(1))
                return "Yes, it is currently windy in " + location + "." if wind_speed > 6.94 else "No, it is not currently windy in " + location + "."
            return "I couldn't determine the wind speed in " + location + "."
        if 'sunny' in prompt.lower():
            return "Yes, it is currently sunny in " + location + "." if 'clear' in weather_data.lower() else "No, it is not currently sunny in " + location + "."
        if 'cloudy' in prompt.lower():
            return "Yes, it is currently cloudy in " + location + "." if 'clouds' in weather_data.lower() else "No, it is not currently cloudy in " + location + "."

    return f"I'm not sure about the specific weather condition in {location}."

def extract_rain_times(weather_data):
    """Extracts the start and end times for rain from the forecast data."""
    rain_times = {}
    lines = weather_data.split('\n')
    rain_start = None
    rain_end = None

    for line in lines:
        if 'rain' in line.lower():
            if not rain_start:
                try:
                    rain_start = datetime.strptime(line.split(':')[0].strip(), '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
            try:
                rain_end = datetime.strptime(line.split(':')[0].strip(), '%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue

    if rain_start and rain_end:
        rain_times['start'] = rain_start
        rain_times['end'] = rain_end

    return rain_times if rain_times else None

def describe_time_relative_to_now(time):
    """Describes the given time relative to the current time (e.g., 'tomorrow at 14:00')."""
    now = datetime.now()
    if time.date() == now.date():
        return f"today at {time.strftime('%H:%M')}"
    elif time.date() == (now + timedelta(days=1)).date():
        return f"tomorrow at {time.strftime('%H:%M')}"
    else:
        days_from_now = (time.date() - now.date()).days
        return f"in {days_from_now} days at {time.strftime('%H:%M')}"

def get_sun_times(location=DEFAULT_LOCATION, query=''):
    """Returns the sunrise and sunset times for a specified location."""

    try:
        mgr = owm.weather_manager()
        observation = mgr.weather_at_place(location)
        weather = observation.weather

        utc_offset = weather.utc_offset() if callable(weather.utc_offset) else weather.utc_offset

        sunrise_utc = datetime.fromtimestamp(weather.sunrise_time(), tz=timezone.utc)
        sunset_utc = datetime.fromtimestamp(weather.sunset_time(), tz=timezone.utc)

        local_timezone = timezone(timedelta(seconds=utc_offset))

        local_sunrise = sunrise_utc.astimezone(local_timezone)
        local_sunset = sunset_utc.astimezone(local_timezone)

        if 'sunrise' in query.lower() and 'sunset' not in query.lower():
            return f"Sunrise in {location}: {local_sunrise.strftime('%Y-%m-%d %H:%M:%S')}"
        elif 'sunset' in query.lower() and 'sunrise' not in query.lower():
            return f"Sunset in {location}: {local_sunset.strftime('%Y-%m-%d %H:%M:%S')}"
        else:
            return f"Sunrise in {location}: {local_sunrise.strftime('%Y-%m-%d %H:%M:%S')}, Sunset in {location}: {local_sunset.strftime('%Y-%m-%d %H:%M:%S')}"
    except Exception as e:
        return f"An error occurred: {e}"

def get_news(timeframe=None, country=None, category=None):
    base_url = "https://newsdata.io/api/1/news"
    params = {
        'apikey': newsdata_api_key,
        'q': 'top',  # Query for top news
        'language': 'en',  # Specify the language if needed
    }
    
    if timeframe:
        params['timeframe'] = timeframe
    if country:
        params['country'] = country
    if category:
        params['category'] = category

    try:
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            news_items = response.json().get('results', [])
            return '\n'.join([f"{item['title']} - {item['source_id']}" for item in news_items])
        else:
            return f"Error fetching news: {response.json().get('message', 'Unknown error')}"
    except Exception as e:
        return f"An error occurred: {e}"
    
def handle_file_operation(command):
    """Handles creating, deleting, updating, and clearing files based on the command."""

    file_name_pattern = r'\bfile\s+(\w+\.\w{2,4})'  # Example: 'file example.txt'
    content_pattern = r'content\s+(.+$)'  # Captures everything after 'content'
    
    file_name_match = re.search(file_name_pattern, command, re.IGNORECASE)
    content_match = re.search(content_pattern, command, re.IGNORECASE)

    file_name = file_name_match.group(1) if file_name_match else "notes.txt"  # Default file name
    content = content_match.group(1).strip() if content_match else ""

    if "create" in command.lower():
        with open(file_name, 'w') as file:
            file.write(content)
        return f"File '{file_name}' has been created with specified content."
    
    elif "delete" in command.lower():
        if os.path.exists(file_name):
            os.remove(file_name)
            return f"File '{file_name}' has been deleted."
        else:
            return f"File '{file_name}' does not exist."

    elif "update" in command.lower():
        if os.path.exists(file_name):
            with open(file_name, 'a') as file:
                file.write(f"\n{content}")  
            return f"File '{file_name}' has been updated with new content."
        else:
            return f"File '{file_name}' does not exist."

    elif "clear" in command.lower():
        if os.path.exists(file_name):
            with open(file_name, 'w') as file:
                file.write('') 
            return f"File '{file_name}' has been cleared of all contents."
        else:
            return f"File '{file_name}' does not exist to clear."

    else:
        return "Sorry, the file operation was not recognized. Please specify if you want to create, delete, update, or clear a file."

def handle_shopping_list_operation(command):
    shopping_list_file = 'shopping_list.txt'
    
    if "add to shopping list" in command.lower():
        items_str = command.lower().replace("add to shopping list", "", 1).strip()
        items_str = items_str.replace(", and ", ", ").replace(",and ", ", ")
        items = [item.strip() for item in re.split(',| and ', items_str) if item.strip()]
        if items:
            with open(shopping_list_file, 'a') as file:
                for item in items:
                    file.write(f"{item}\n")
            items_formatted = ", ".join(f"'{item}'" for item in items)
            return f"Added {items_formatted} to the shopping list."
    
    elif "remove from shopping list" in command.lower():
        item = command.lower().replace("remove from shopping list", "").strip()
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