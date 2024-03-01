from datetime import datetime, timedelta
import subprocess
import logging
import os
import requests
from pyowm import OWM
from pyowm.utils import timestamps
from dotenv import load_dotenv

# Load the OpenWeatherMap API key from .env file
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

        return f"Weather in {location}: {status}, {temp}°F"
    except Exception as e:
        return f"An error occurred: {e}"

def get_forecast(location=DEFAULT_LOCATION, duration=1, specific_time=None):
    """Returns a weather forecast for a specified location and duration or a specific time."""

    try:
        forecast_mgr = owm.weather_manager()
        forecast_obj = forecast_mgr.forecast_at_place(location, '3h')

        if specific_time:
            # Find the closest weather to the specific time
            closest_weather = None
            smallest_time_diff = float('inf')
            for weather in forecast_obj.forecast:
                time_diff = abs(weather.reference_time() - specific_time.timestamp())
                if time_diff < smallest_time_diff:
                    closest_weather = weather
                    smallest_time_diff = time_diff

            if closest_weather:
                return f"Weather in {location}: " + format_weather_info(closest_weather, specific_time)

        else:
            forecast_info = f"Forecast for {location}:\n"
            end_time = datetime.now() + timedelta(days=duration)
            last_status = ""
            last_temp = None

            for weather in forecast_obj.forecast:
                weather_time = datetime.fromtimestamp(weather.reference_time())
                if weather_time > end_time:
                    break

                status = weather.detailed_status
                temp = weather.temperature('fahrenheit')['temp']
                precipitation = weather.precipitation_probability

                # Check for significant change in weather status or temperature
                if status != last_status or (last_temp is not None and abs(temp - last_temp) >= 5):
                    forecast_info += f"{weather_time.strftime('%Y-%m-%d %H:%M:%S')}: {status}, Temp: {temp}°F, Precipitation chance: {precipitation}%\n"
                    last_status = status
                    last_temp = temp

            return forecast_info.strip()

    except Exception as e:
        return f"An error occurred: {e}"

def format_weather_info(weather, target_time=None):
    """Formats the weather information."""
    time_format = '%Y-%m-%d %H:%M:%S'
    time = target_time.strftime(time_format) if target_time else datetime.fromtimestamp(weather.reference_time()).strftime(time_format)
    status = weather.detailed_status
    temp = weather.temperature('fahrenheit')['temp']
    precipitation = weather.precipitation_probability

    return f"{time}: {status}, Temp: {temp}°F, Precipitation chance: {precipitation}%\n"

def get_weather_condition(prompt, location=DEFAULT_LOCATION):
    location = location if location else DEFAULT_LOCATION

    # Determine if the query is about current weather or a forecast
    if 'tomorrow' in prompt.lower():
        weather_data = get_forecast(location)
    else:
        weather_data = get_weather(location)

    # Parsing the response for specific weather conditions
    if 'snow' in prompt.lower():
        if 'snow' in weather_data.lower():
            return "Yes, it is currently snowing in " + location + "."
        else:
            return "No, it is not snowing in " + location + "."

    elif 'rain' in prompt.lower():
        if 'rain' in weather_data.lower():
            return "Yes, it is currently raining in " + location + "."
        else:
            return "No, it is not raining in " + location + "."

    elif 'fog' in prompt.lower():
        if 'fog' in weather_data.lower():
            return "Yes, it is currently foggy in " + location + "."
        else:
            return "No, it is not foggy in " + location + "."

    return "I'm not sure about the specific weather condition in " + location + "."

def get_sun_times(location=DEFAULT_LOCATION, query=''):
    """Returns the sunrise and sunset times for a specified location."""

    try:
        mgr = owm.weather_manager()
        observation = mgr.weather_at_place(location)
        weather = observation.weather

        # Getting sunrise and sunset times in ISO format
        sunrise_time = weather.sunrise_time(timeformat='iso')
        sunset_time = weather.sunset_time(timeformat='iso')

        if 'sunrise' in query.lower() and 'sunset' not in query.lower():
            return f"Sunrise in {location}: {sunrise_time}"
        elif 'sunset' in query.lower() and 'sunrise' not in query.lower():
            return f"Sunset in {location}: {sunset_time}"
        else:
            return f"Sunrise in {location}: {sunrise_time}, Sunset in {location}: {sunset_time}"
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