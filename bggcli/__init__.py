import os

if os.environ.get('CI') == 'true':
    # Issues with Sauce Labs and HTTPS
    BGG_BASE_URL = "http://www.boardgamegeek.com"
else:
    BGG_BASE_URL = "https://www.boardgamegeek.com"

UI_ERROR_MSG = "Unexpected error while controlling the UI!\nEither the web pages have " \
               "changed and bggcli must be updated, or the site is down for " \
               "maintenance."

BGG_SUPPORTED_FIELDS = ['objectname', 'objectid', 'rating', 'numplays', 'own',
                        'fortrade', 'want', 'wanttobuy', 'wanttoplay', 'prevowned',
                        'preordered', 'wishlist', 'wishlistpriority', 'wishlistcomment',
                        'comment', 'conditiontext', 'haspartslist', 'wantpartslist',
                        'publisherid', 'imageid', 'year', 'language', 'other', 'barcode', 'pricepaid',
                        'collid', 'baverage', 'average', 'numowned', 'objecttype', 'minplayers',
                        'maxplayers', 'playingtime', 'maxplaytime', 'minplaytime', 'yearpublished',
                        'pp_currency', 'currvalue', 'cv_currency', 'acquisitiondate',
                        'acquiredfrom', 'quantity', 'privatecomment',
                        '_versionid']
