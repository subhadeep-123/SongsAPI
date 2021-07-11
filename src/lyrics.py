import os

try:
    import lyricsgenius
    from configparser import ConfigParser
except ImportError as err:
    print(f'Cannot Import the above Libraries - {err}')


# File Paths
CONFIGURATION_FILE_PATH = 'config/cofig.ini'

if not os.path.isfile(CONFIGURATION_FILE_PATH):
    print("""Change the example.config.ini -> config.ini,
    and fill the empty spaces by your own API credentials.
    Get yours from - https://genius.com/api-clients
    """)
    raise FileNotFoundError('config.ini missing in config directory')

configs = ConfigParser()
configs.read(CONFIGURATION_FILE_PATH)


class GetLyrics(object):
    def __init__(self) -> None:
        super().__init__()
        try:
            self.clientId = configs['GeniusAPI']['clientID']
            self.clientSecret = configs['GeniusAPI']['clientSecret']
            self.clientAccessToken = configs['GeniusAPI']['clientAccessToken']
        except Exception as err:
            print(f"Error logged - {err}")
        else:
            self.genius = lyricsgenius.Genius(self.clientAccessToken)

    def fetch(self, artist_name, song_name):
        artist = self.genius.search_artist(
            artist_name,
            max_songs=1,
            sort="title",
            include_features=True
        )
        print(artist.songs)
        song = artist.song(song_name)
        return song.lyrics[:len(song.lyrics) -
                           len("EmbedShare URLCopyEmbedCopy")]


if __name__ == '__main__':
    obj = GetLyrics()
    obj.fetch('Andy Shauf', 'To You')
