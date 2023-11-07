import requests

# Define your API key
api_key = "XXX"

# Define the base URL for the Baidu Map API
base_url = "http://api.map.baidu.com/geocoder/v2/"

# Replace the coordinates with the actual latitude and longitude
lat = 33.812511  # Replace with the actual latitude
lng = -117.918976  # Replace with the actual longitude

# Define the parameters for the request
params = {
    "ak": api_key,  # Your API key
    "output": "json",  # Response format (JSON in this case)
    "location": f"{lat},{lng}",  # Actual coordinates
    "pois": 1  # Whether to show nearby postal addresses within 100m
}

# Make the GET request
response = requests.get(base_url, params=params)

# Check if the request was successful
if response.status_code == 200:
    data = response.json()  # Parse the JSON response
    result = data['result']  # Extract the result
    print(result)
else:
    print("Request failed with status code:", response.status_code)
