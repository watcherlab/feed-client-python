### feed-client-python
* feed client packages designed to easy query and download data from this database
> example:

```python
# Import package
from watcherlab.feed import client


# Create a api object
feed_client = client.Api()


# Free query
# Return dict type result or empty dict
query_result = feed_client.query(data="8.8.8.8")


# Advanced query you need a token in our database, project url: https://feed.watcherlab.com
# Return dict type result or empty dict
query_advanced_result = feed_client.query_advanced(token="token",data="8.8.8.8")


# Download our daily build threat intelligence data
# Parameter token indicate your user token
# Parameter pathname indicate data save path
# Parameter date indicate the data publish time, 1=yesterday(latest), 2=The day before yesterday, and so on
# Return all data items count and successful download items count
# You can call download_list() method to know all data items
data_count, down_count = feed_client.download_advanced(token="token",pathname="./",date=1)

```
