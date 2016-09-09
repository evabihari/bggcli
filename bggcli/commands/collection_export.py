"""
Export a game collection as a CSV file.

Usage: bggcli [-v] -l <login> -p <password> [-c filter=<filter_opt>]
              collection-export [--save-xml-file] <file>

Options:
    -v                              Activate verbose logging
    -l, --login <login>             Your login on BGG
    -p, --password <password>       Your password on BGG
    --save-xml-file                 To store the exported raw XML file in addition (will be
                                    save aside the CSV file, with '.xml' extension
    -c <name=value>                 To specify advanced options, see below

Advanced options:
   filter=<filter_opt>             Filtering the collection against filter_opt value
    
Arguments:
    <file> The CSV file to generate
    <filter_opt> own | rated | played | comment | trade | want | wishlist | preordered | wanttoplay | wanttobuy | prevowned
    
"""
import csv
from urllib import urlencode
import cookielib
import urllib2
import time
import sys
import xml.etree.ElementTree as ET

from bggcli import BGG_BASE_URL, BGG_SUPPORTED_FIELDS
from bggcli.util.logger import Logger
from bggcli.util.xmltocsv import XmlToCsv

# BGG_SESSION_COOKIE_NAME = 'SessionID'
EXPORT_QUERY_INTERVAL = 5
ERROR_FILE_PATH = 'error.txt'


def execute(args, options):
    login = args['--login']
    dest_path = args['<file>']
##    Logger.info("execute args= '%s' " % args)
    Logger.info("execute options= '%s' " % options)
    filter_by=None  
    if args['-c']:
        filter_by = options.get('filter')
        Logger.info("Filter provided with '%s' " % filter_by)

    Logger.info("Exporting collection for '%s' account..." % login)

    # 1. Authentication

    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    Logger.info("Authenticating...", break_line=False)
    opener.open(BGG_BASE_URL + '/login', urlencode({
        'action': 'login', 'username': login, 'password': args['--password']}))
    if not any(cookie.name == "bggusername" for cookie in cj):
        Logger.info(" [error]", append=True)
        Logger.error("Authentication failed for user '%s'!" % login, sysexit=True)
    Logger.info(" [done]", append=True)
    # 2. Export
    # Easier to rely on a client HTTP call rather than Selenium to download a file
    # Just need to pass the session cookie to get the full export with private information

    # Use XML2 API, see https://www.boardgamegeek.com/wiki/page/BGG_XML_API2#Collection
    # Default CSV export doesn't provide version info!

    to_url_encode = {
            'username': login, 'version': 1, 'showprivate': 1, 'stats': 1}
    if filter_by:
            to_url_encode.setdefault(filter_by,1)
    url = BGG_BASE_URL + '/xmlapi2/collection?' + urlencode(to_url_encode)
        
    req = urllib2.Request(url)
 
    # Get a BadStatusLine error most of times without this delay!
    # Related to Selenium, but in some conditions that I have not identified
    time.sleep(8)
    try:
        Logger.info('Launching export...')
        response = default_export(opener, req)
    except Exception as e:
        Logger.error('Error while fetching export file!', e, sysexit=True)
        return

# 3. Store XML file if requested

    if args['--save-xml-file']:
        xml_file_path = write_xml_file(response, dest_path)
        Logger.info("XML file save as %s" % xml_file_path)
        source = open(xml_file_path, 'rU')
        
    else:
        source = response

# 4. Write CSV file
    try:
        write_csv(source, dest_path)
    except Exception as e:
        Logger.error('Error while writing export file in file system!', e, sysexit=True)
        return
    finally:
        source.close()
    
    # End
    Logger.info("Collection has been exported as %s" % dest_path)


## def default_export(req):
##    response = urllib2.urlopen(req)

def default_export(opener, req):
    response = opener.open(req)

    if response.code == 202:
        Logger.info('Export is queued, will retry in %ss' % EXPORT_QUERY_INTERVAL)
        time.sleep(EXPORT_QUERY_INTERVAL)
        return default_export(opener, req)


    if response.code == 200:
        return response

    # Write response in a text file otherwise
    try:
        with open(ERROR_FILE_PATH, "wb") as error_file:
            error_file.write(response.read())
        Logger.error("Unexpected response, content has been written in %s" % ERROR_FILE_PATH)
    except Exception as e:
        raise Exception('Unexpected HTTP response for export request, and cannot write '
                        'response content in %s: %s' % (ERROR_FILE_PATH, e))
    raise Exception('Unexpected HTTP response for export request, response content written in '
                    '%s' % ERROR_FILE_PATH)


def write_xml_file(response, csv_dest_path):
    dest_path = '.'.join(csv_dest_path.split('.')[:-1]) + '.xml'
    with open(dest_path, "wb") as dest_file:
        Xml=response.read()
        dest_file.write(Xml)
        dest_file.close()
    return dest_path


def write_csv(source, dest_path):
    with open(dest_path, "wb") as dest_file:
        csv_writer = csv.DictWriter(dest_file, fieldnames=BGG_SUPPORTED_FIELDS,
                                    quoting=csv.QUOTE_ALL)
        # csv_writer.writeheader() use quotes
        dest_file.write('%s\n' % ','.join(BGG_SUPPORTED_FIELDS))

        for event, elem in ET.iterparse(source, events=['end']):
            if event == 'end':
                if elem.tag == 'item' and elem.attrib.get('subtype') == 'boardgame':
                    row = XmlToCsv.convert_item(elem)
                    csv_writer.writerow(row)

