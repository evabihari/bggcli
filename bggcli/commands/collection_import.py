"""
Import a game collection from a CSV file.

Note this action can be used to initialize a new collection, but also to update an existing
collection. Only the fields defined in the file will be updated.

Usage: bggcli [-v] -l <login> -p <password>
              collection-import [--force-new] <file>

Options:
    -v                              Activate verbose logging
    -l, --login <login>             Your login on BGG
    -p, --password <password>       Your password on BGG
    --force-new                     Ignore collid, always insert new items

Arguments:
    <file> The CSV file with games to import
"""
import re
import sys
from urllib import urlencode
import cookielib
import urllib2

from bggcli import BGG_BASE_URL
from bggcli.commands import check_file
from bggcli.util.csvreader import CsvReader
from bggcli.util.logger import Logger


def create_collid(opener, objectid):
    response = opener.open(BGG_BASE_URL + '/geekcollection.php', urlencode({
        'ajax': 1, 'action': 'additem', 'force': 'true',
        'objecttype': 'thing', 'objectid': objectid}))

    if response.code != 200:
        Logger.error("Failed to create item of 'objectid'=%s!" % objectid, sysexit=True)

    # There seems to be no straightforward way to get the collid of the item just created.
    # To work around this we fetch a list of all items of this objectid and scrape it to
    # find the largest collid. This might fail if the collection is concurrently modified.

    response = opener.open(BGG_BASE_URL + '/geekcollection.php?' + urlencode({
        'ajax': 1, 'action': 'module', 'objecttype': 'thing', 'objectid': objectid}))

    return max(int(m.group(1)) for m in re.finditer(
        r"(?i)<input\s+type='hidden'\s+name='collid'\s+value='(\d+)'[^>]*>", response.read()))


def update_collid(opener, collid, fieldname, values):
    values.update({'ajax': 1, 'action': 'savedata',
                   'collid': collid, 'fieldname': fieldname})
    values = { k:unicode(v).encode('utf-8') for k,v in values.iteritems() }
    response = opener.open(BGG_BASE_URL + '/geekcollection.php', urlencode(values))

    if response.code != 200:
        Logger.error("Failed to update 'collid'=%s!" % collid, sysexit=True)


 def game_importer(opener, row, force_new=False):
    collid = row['collid']

    if force_new or not collid:
        objectid = row['objectid']
        if not objectid.isdigit():
            Logger.error("Invalid 'objectid'=%s!" % objectid, sysexit=True)
        collid = create_collid(opener, objectid)

    values = { k:v for k,v in row.iteritems() if k in [
        'own', 'prevowned', 'fortrade', 'want', 'wanttobuy',
        'wishlist', 'wishlistpriority', 'wanttoplay', 'preordered'] }
    if len(values):
        update_collid(opener, collid, 'status', values)

    values = { k:v for k,v in row.iteritems() if k in [
        'pp_currency', 'pricepaid', 'cv_currency', 'currvalue', 'quantity',
        'acquisitiondate', 'acquiredfrom', 'privatecomment', 'invdate', 'invlocation'] }
    if len(values):
        update_collid(opener, collid, 'ownership', values)

    if '_versionid' in row.keys() and row['_versionid'].isdigit():
        update_collid(opener, collid, 'version', {'geekitem_version': 1, 'objectid': row['_versionid']})
    elif 'geekitem_version' in row.keys() and 'objectid' in row.keys() and \
            row['geekitem_version'].isdigit() and int(row['geekitem_version']) == 1:
        update_collid(opener, collid, 'version', {'geekitem_version': 1, 'objectid': row['objectid']})
    else:
        values = { k:v for k,v in row.iteritems() if k in [
            'imageid', 'publisherid', 'languageid', 'year', 'other', 'barcode'] }
        if len(values):
            update_collid(opener, collid, 'version', values)

    if 'objectname' in row.keys():
        update_collid(opener, collid, 'objectname', {'value': row['objectname']})
    if 'rating' in row.keys():
        update_collid(opener, collid, 'rating', {'rating': row['rating']})
    if 'weight' in row.keys():
        update_collid(opener, collid, 'weight', {'weight': row['weight']})
    if 'comment' in row.keys():
        update_collid(opener, collid, 'comment', {'value': row['comment']})
    if 'conditiontext' in row.keys():
        update_collid(opener, collid, 'conditiontext', {'value': row['conditiontext']})
    if 'wantpartslist' in row.keys():
        update_collid(opener, collid, 'wantpartslist', {'value': row['wantpartslist']})
    if 'haspartslist' in row.keys():
        update_collid(opener, collid, 'haspartslist', {'value': row['haspartslist']})
    if 'wishlistcomment' in row.keys():
        update_collid(opener, collid, 'wishlistcomment', {'value': row['wishlistcomment']})
 
 
 def execute(args):    login = args['--login']

    file_path = check_file(args)

    csv_reader = CsvReader(file_path)
    csv_reader.open()

    Logger.info("Importing games for '%s' account..." % login)

    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    Logger.info("Authenticating...", break_line=False)
    opener.open(BGG_BASE_URL + '/login', urlencode({
        'action': 'login', 'username': login, 'password': args['--password']}))
    if not any(cookie.name == "bggusername" for cookie in cj):
        Logger.info(" [error]", append=True)
        Logger.error("Authentication failed for user '%s'!" % login, sysexit=True)
    Logger.info(" [done]", append=True)
 
    Logger.info("Importing %s games..." % csv_reader.rowCount)
    csv_reader.iterate(lambda row: game_importer(opener, row, args['--force-new']))
    Logger.info("Import has finished.")
