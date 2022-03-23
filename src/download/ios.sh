#!/bin/bash

if [ $# -ne 5 ]; then
    echo -e "usage: "$0" <app_id_list> <ipa_out_dir> <privacy_label_out_dir> <email> <password>"
    exit 1;
fi

err_count=0

for app_id in $(cat "$1" | gshuf)
do
    ipa_out_path="$2/${app_id}.ipa"
    pl_out_path="$3/${app_id}.json"
    if [ ! -f "${ipa_out_path}" ]; then
        if ipatool download --country de --email "$4" --password "$5" -o "${ipa_out_path}" -a "$app_id"; then
            err_count=0

            # To obtain a new token if it expired: Go to any app (like https://apps.apple.com/us/app/facebook/id284882215),
            # and observe the network traffic while clicking the 'See Details' link next to 'App Privacy'.
            STATUSCODE=$( \
                curl --silent --output "$pl_out_path" --write-out "%{http_code}" --request GET \
                    --url "https://amp-api.apps.apple.com/v1/catalog/DE/apps/${app_id}?platform=iphone&extend=privacyDetails&l=en-gb" \
                    --header 'Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlU4UlRZVjVaRFMifQ.eyJpc3MiOiI3TktaMlZQNDhaIiwiaWF0IjoxNjQ3NDc1MzQ1LCJleHAiOjE2NTQ3MzI5NDV9.6IJEuKuZ_dxuZsa2lBkgQcNfvTh7NEdNTsZhBm6cPwxYSNlf_OgICQZfmIXBDQB7sF1vVCkz1qIMIa9m8J3YBQ' \
            )
            # Adapted after: https://superuser.com/a/590170
            if [ $STATUSCODE -ne 200 ] && [ $STATUSCODE -ne 404 ]; then
                echo "Downloading privacy labels failed for $app_id."
                rm -f "$ipa_out_path"
                rm -f "$pl_out_path"
            fi
        else
            err_count=$((err_count + 1))
            echo $err_count
        fi

        if [ $err_count -ge 5 ]; then
            echo "Sleeping…"
            sleep $(( err_count * 60))
        fi
    fi
done
