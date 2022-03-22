#!/bin/bash

if [ $# -ne 2 ]; then
    echo -e "usage: "$0" <app_id_list> <out_dir>\n\n  NOTE: You need to run this from the PlaystoreDownloader directory"
    exit 1;
fi

err_count=0

for app_id in $(cat "$1" | shuf)
do
    out_dir="$2/${app_id}"
    mkdir -p "${out_dir}"
    if [ ! -f "${out_dir}/${app_id}.apk" ]; then
        if pipenv run python3 -m playstoredownloader.cli -sb -o "${out_dir}" "$app_id"; then
            err_count=0
        else
            err_count=$((err_count + 1))
            echo $err_count
        fi

        if [ $err_count -ge 5 ]; then
            echo "Sleeping…"
            sleep 300
        fi
    fi
done
