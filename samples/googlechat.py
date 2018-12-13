import os
import time
from httplib2 import Http
from json import dumps

from pytw import client 

# Setup the webhook for Google Chat
gc_url = "__YOUR_GOOGLE_CHAT_ROOM_WEBHOOK_URL__"
gc_msg_headers = { 'Content-Type': 'application/json; charset=UTF-8'}

# Initialize a ThreatWatch Client instance
pytwc = client.Client('__YOUR_THREATWATCH_EMAIL__', '__YOUR_THREATWATCH_TOKEN__', '__YOUR_THREATWATCH_INSTANCE__')


while(True):
    # Getting vulnerabilities from ThreatWatch
    resultset = pytwc.get_recent_vulns(7)
    if len(resultset) == 0:    # Nothing to post to slack 
        time.sleep(300)
        continue

    for r in resultset:
        if r.get_rating_as_int() < 3:    # Only filter for ratings 3 and above
            continue

        # Compose the message to post 
        msg = ""
        if r.is_new():
            msg += "New "
        else:
            msg += "Updated "
        msg += "vulnerability: "+r.get_id() 
        if r.get_title():
            msg += "\nTitle: "+r.get_title()
        else:
            msg += "\nTitle: "
        msg += "\nRating: "+r.get_rating_as_str()+"\n"
        if r.get_references() and len(r.get_references()) > 0:
            msg += "Reference: "+r.get_references()[0]+"\n"
        if not r.is_new() and r.get_last_change() and len(r.get_last_change()) > 0:
            msg += "Last change: "+''.join(r.get_last_change())+"\n"
        msg += "Advisories: \n"
        adv = r.get_advisories()
        if len(adv) == 0:
           msg += " None\n"
        else:
            for a in adv:
                if a.get_publisher():
                    msg += "  Publisher: "+a.get_publisher()+"\n"
                msg += "  Title: "+a.get_title()+"\n  Rating: "+a.get_rating_as_str()+"\n"
                if a.get_references() and len(a.get_references()) > 0:
                    msg += "  Reference: "+a.get_references()[0]+"\n"
                if not a.is_new and a.get_last_change() and len(a.get_last_change()) > 0:
                    msg += "Last change: "+''.join(a.get_last_change())+"\n"
        msg += "\n"

        # Post to Google Chat Room
        chat_room_msg = { 'text': msg }
        http_obj = Http()
        response = http_obj.request(uri=gc_url, method='POST', headers=gc_msg_headers, body=dumps(chat_room_msg))
