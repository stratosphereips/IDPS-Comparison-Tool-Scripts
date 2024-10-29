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
        acc_threat_level = 0
        for i in range(len(scores)):
            cur = scores[i]
            try:
                nxt = scores[i+1]
            except IndexError:
                # cur is the last element in the list
                acc_threat_level += cur
                break
                
            # basically, when we find a number thats lower than the one
            # before it, we accumulate the one before it to the total acc
            # threat level
            if nxt >= cur:
                continue
            acc_threat_level += cur
        
        res[alertsjson].update({timewindow: acc_threat_level})
    return res
    
def get_attacker(line: dict) -> str:
    try:
        return line["Source"][0]['IP']
    except KeyError:
        # src isnt an ip, skip it
        return []


def read_alerts_json():
    with open(alertsjson) as f:
        lines_ctr = 0
        while line := f.readline():
            lines_ctr += 1
            line: dict = json.loads(line)
            attacker: str = get_attacker(line)
    
            if srcip != attacker:
                # we only need evidence done by the given srcip
                continue
            note: Dict = json.loads(line['Note'])
            tl = note['accumulated_threat_level']
            twid = note['timewindow']
    
            if twid not in tws:
                tws.update({twid :  [tl]})
            else:
                tws[twid].append(tl)
    return tws


tws = read_alerts_json()
# sort the dict keys (sort by timewindows)
sorted_tws = dict(sorted(tws.items()))

accumulated_threat_levels: Dict[int, float]
accumulated_threat_levels = accumulate_threat_levels(sorted_tws)
pp(accumulated_threat_levels)



