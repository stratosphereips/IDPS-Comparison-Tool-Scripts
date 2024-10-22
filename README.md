# Features

This repo contains the following scripts in scripts/ dir consider this branch a different tool.
  *  a script for extracting the accumulated threat levels from slips alerts.json
  *  a script for extracting the ground truth labels for each time window given the conn.log.labeled for a given IP
  *  a script to determine the best threshold for sips based on the extracted threat levels and ground truth 


# Installation

pip3 install -r requirements.txt

---


# Usage


```python3 -m pip install -r requirements.txt```

##### command for generating all zeek files in the dataset/

``` zeek -C -r <pcap>  tcp_inactivity_timeout=60mins tcp_attempt_delay=1min```


##### command for labeling conn.log files

``` python3 netflowlabeler.py -c labels.config -f /path/to/generated/conn.log ```

##### (optional) To label the rest of the Zeek files using an already labeled conn.log file (conn.log.labeled)

```zeek-files-labeler.py -l conn.log.labeled -f folder-with-zeek-log-files```

##### command for extracting max accumulated threat level for all timewindows from an alert.json 

```
python3 -m scripts.max_accumulated_score_extractor_for_slips alerts.json <host_ip> <used_slips_threshold>
```


##### command for getting the best slips threshold given the extracted ground truth labels and max accumulated scores

note: this script assumes the correct ground truth labels are in scripts/extracted_gt_tw_labels.py
and the correct max accumulated scores of slips are in scripts/extracted_levels.py 

* to print the metrics to cli
```
python3 -m scripts.slips_metrics_getter 
```

* to plot the metrics
```
python3 -m scripts.slips_metrics_getter  -p
```

Note: To print and plot the metrics, scripts/extracted_scores/extracted_levels.py must t be updated using the
max_accumulated_score_extractor_for_slips.py script

##### command for extracting ground truth labels from a conn.log.labeled file
note: we only extract the labels per timewindow per ip

```
python3 main.py -gtf conn.log.labeled -i <host_ip>
```


# About
This repo was developed at the Stratosphere Laboratory at the Czech Technical University in Prague.