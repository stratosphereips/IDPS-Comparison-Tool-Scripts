"""
This script extracts the highest accumulated threat level of each time
window in the given alerts.json. it only prints timewindows of the
 given host ip

Usage:
python3 max_accumulated_score_extractor_for_slips.py <slips' alerts.json> <host ip>

"""

import json
import sys
import ipaddress
from typing import (
    List,
    Dict,
    )
from pprint import pp

tws = {}
alertsjson = sys.argv[1]
srcip = sys.argv[2]
# slips detection threshold used for generating this alerts.json
# https://stratospherelinuxips.readthedocs.io/en/develop/features.html#controlling-slips-sensitivity
used_threshold = float(sys.argv[3])
tw_width = 3600
detection_threshold_per_tw = used_threshold * tw_width / 60



def get_max_accumulated_score(
        sorted_tws: Dict[int, List[float]]
    ):
    """
    returns the max acc threat level of each timewindow in the given
    sorted_tw
    dict. somthing like this
    {filename: { 'twid': max_acc_threat_level }}
    
    :param sorted_tws: dict with sorted tws as keys and a list of tw
    threat levels as values
    e.g {
        1: [2, 3, 4, 5, 2, 2, 0],
        2: [1, 2, 3]}
        
    """
    res = {alertsjson: {}}
    for timewindow, scores in sorted_tws.items():
        timewindow: int
        scores: List[float]
        res[alertsjson].update({timewindow: max(scores)})
    return res


def get_index_of_last_occurrence(list, element) -> int:
    """returns the index of the last occurrence of the given element in the
    given list"""
    reversed_list = list[::-1]
    try:
        index = reversed_list.index(element)
    except ValueError:
        # element is not in the list
        index = 0
    actual_index = len(list) - index - 1
    return actual_index


def accumulate_threat_levels(
        sorted_tws: Dict[int, List[float]]
    ):
    """
    When slips is run with a threshold that is not the highest one (999999)
    slips resets the acc threat level after it reaches the detection
    threshold.
    this function gets the mac accumulated threat level as if slips was run
    using 999999
    it works around the resetting of threshold that slips does
    """
    
    res = {alertsjson: {}}
    for timewindow, scores in sorted_tws.items():
        timewindow: int
        scores: List[float]
        number_of_threashold_reaches = scores.count(
            detection_threshold_per_tw)
        max_acc_threat_level = (
                number_of_threashold_reaches * detection_threshold_per_tw)
        # get the idx of the last acc threat level of the last alert.
        # after that index, no more alerts were generated, so the acc
        # thraet level was never reset afterwards
        last_occ = get_index_of_last_occurrence(scores,
                                            detection_threshold_per_tw)
        if last_occ != len(scores) - 1:
            max_acc_threat_level += max(scores[last_occ+1:])
        else:
            # there are no accumulated thresholds that never triggered an
            # alert
            ...
        
        res[alertsjson].update({timewindow: max_acc_threat_level})
    return res
    
    


def get_ip_version(srcip):
    # determine th eversion of the given IP
    try:
        ipaddress.IPv4Address(srcip)
        ip_version = "IP4"
    except ipaddress.AddressValueError:
        ip_version = "IP6"
    return ip_version


def get_attackers(line: dict, ip_version: str) -> List[str]:
    try:
        return line["Source"][0][ip_version]
    except KeyError:
        # detection doesn't match the given ipv4, skip it
        return []


def read_alerts_json():
    ip_version: str = get_ip_version(srcip)
    with open(alertsjson) as f:
        lines_ctr = 0
        while line := f.readline():
            lines_ctr += 1
            line: dict = json.loads(line)
            attackers: List[str] = get_attackers(line, ip_version)
    
            if srcip not in attackers:
                # we only need evidence done by the given srcip
                continue
    
            tl = line['accumulated_threat_level']
            twid = line['timewindow']
    
            if twid not in tws:
                tws.update({twid :  [tl]})
            else:
                tws[twid].append(tl)
    return tws

tws = read_alerts_json()
# sort the dict keys
sorted_tws = dict(sorted(tws.items()))
accumulated_threat_levels: Dict[int, float]
if used_threshold > 99999:
    accumulated_threat_levels = get_max_accumulated_score(sorted_tws)
else:
    accumulated_threat_levels = accumulate_threat_levels(sorted_tws)
pp(accumulated_threat_levels)



