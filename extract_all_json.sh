#!/bin/bash

wget -N https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip

for json in `ls ./*.json.zip`
do
	echo $json
	unzip $json
done

