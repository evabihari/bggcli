"""
Delete games in your collection from a CSV file. BE CAREFUL, this action is irreversible!
Usage: bggcli [-v] -l <login> -p <password>
              collection-delete [--force] <file>
Options:
    -v                              Activate verbose logging
    -l, --login <login>             Your login on BGG
    -p, --password <password>       Your password on BGG
    --force                         Force deletion, without any confirmation
Arguments:
    <file> The CSV file with games to delete
"""
from urllib import urlencode
import cookielib
import urllib2
import sys

from bggcli import BGG_BASE_URL
from bggcli.commands import check_file
from bggcli.util.csvreader import CsvReader
from bggcli.util.logger import Logger


def game_deleter(opener, row):
    collid = row['collid']
    if not collid:
        return

    response = opener.open(BGG_BASE_URL + '/geekcollection.php', urlencode({
        'ajax': 1, 'action': 'delete', 'collid': collid}))

    if response.code != 200:
        Logger.error("Failed to delete 'collid'=%s!" % collid, sysexit=True)


def execute(args):
    login = args['--login']

    file_path = check_file(args)

    csv_reader = CsvReader(file_path)
    csv_reader.open()

    game_count = csv_reader.rowCount

    if not args['--force']:
        sys.stdout.write(
            "You are about to delete %s games in you collection (%s), "
            "please enter the number of games displayed here to confirm you want to continue: "
            % (game_count, login))

        if raw_input() != game_count.__str__():
            Logger.error('Operation canceled, number does not match (should be %s).' % game_count,
                         sysexit=True)
            return

    Logger.info("Deleting games for '%s' account..." % login)

    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    Logger.info("Authenticating...", break_line=False)
    opener.open(BGG_BASE_URL + '/login', urlencode({
        'action': 'login', 'username': login, 'password': args['--password']}))
    if not any(cookie.name == "bggusername" for cookie in cj):
        Logger.info(" [error]", append=True)
        Logger.error("Authentication failed for user '%s'!" % login, sysexit=True)
    Logger.info(" [done]", append=True)


    Logger.info("Deleting %s games..." % game_count)
    csv_reader.iterate(lambda row: game_deleter(opener, row))
    Logger.info("Deletion has finished.")
