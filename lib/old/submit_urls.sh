#!/bin/bash

cd /opt/url_click/

rm results.log.old
mv results.log results.log.old

# go back 35 minutes as it takes ~ 10-30 minutes for CB results
# to get indexed and appear in splunk. \_(-_-)_/ 
date=$(date -d '75 minutes ago' +'%Y-%m-%d %H:%M:%S')
end_date=$(date -d '15 minutes ago' +'%Y-%m-%d %H:%M:%S')

printf "*************\n\tStarting work at $(date +'%Y-%m-%d %H:%M:%S')\n*************\n" > results.log

#OLD export -n http_proxy && export -n https_proxy && /opt/splunklib/splunk.py -i -c 'splunk.ini' -s "$date" -e "$end_date" --search-file url_clicks.search --json | jq -r '.result[].clicked_url' | while read url; do printf "\nURL: "; echo "$url"; curl -k "https://cloudphish1.local:5000/saq/cloudphish/submit?url=$url&a=1" 2> /dev/null; done >> results.log

export -n http_proxy && export -n https_proxy && /opt/splunklib/splunk.py -i -c 'splunk.ini' -s "$date" -e "$end_date" --search-file url_clicks.search --json | jq -r '.result[] | .clicked_url + ",process_guid=" + .process_guid + ",hostname=" + .computer_name + ",company=" + .company + ",domain=" + .dest_nt_domain  + ",user=" + .user' | while IFS=$',' read url process_guid hostname company domain user; do printf "\nINFO: "; echo "$url&$process_guid&$hostname&$company&$domain&$user"; curl -k --request POST "https://cloudphish1.local:5000/saq/cloudphish/submit?url=$url&$process_guid&$hostname&$company&$domain&$user&a=1" 2> /dev/null; done >> results.log


printf "\n*************\n\tCompleted at $(date +'%Y-%m-%d %H:%M:%S')\n*************\n" >> results.log
