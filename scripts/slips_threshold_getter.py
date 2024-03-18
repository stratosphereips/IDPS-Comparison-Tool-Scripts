"""
calculates the TP TN FP FN for each threshold in the range 0..150
this script tries all thresholds on all expirements on all tws

Usage: python3 scripts/slips_threshold_getter.py

"""

from typing import Dict, List
from pprint import pp
from argparse import ArgumentParser

from plot.plot import Plot
from scripts.extracted_levels import extracted_threat_levels
from scripts.extracted_gt_tw_labels import gt_tw_labels
from metrics.calculator import Calculator


def is_tw_malicious(experiment: str, timewindow: int) -> bool:
    """
    checks whether the ground truth label of the given timewindow is malicious
    :param experiment: name of experiment to check
    :param timewindow: number of tw to check
    """
    if timewindow in gt_tw_labels[experiment]:
        # we do have a label for this timewindow
        # Note: If a timewindow was detected by one of the tools, and not
        # detected
        # by the ground truth, for example negative timewindows in slips,
        # we consider the gt label of it as "benign"
        return gt_tw_labels[experiment][timewindow] == 'malicious'
    else:
        # we don't have  lable for this timewindow, probably because there
        # was no flows by host in this timewindow
        # print(f"problem getting the label of {experiment} {timewindow},")
        return False

def print_metrics_summary(threshold: int, metrics_sum: Dict[str, float]):
    """
    Print the summary of metrics for a specific threshold.
    """
    print(f"Threshold: {threshold}:")
    for metric, value in metrics_sum.items():
        print(f" total {metric}: {value}")
        
        
def update_extremes(
    threshold: int,
    metrics_sum: Dict[str, float],
    threshold_with_min_max: Dict[str, Dict]
    ):
    """
    Update the extreme values (max and min) for each metric
    and their corresponding thresholds.
    """
    for metric, value in metrics_sum.items():
        if value > threshold_with_min_max[metric]['max_value']:
            threshold_with_min_max[metric]['max_value'] = value
            threshold_with_min_max[metric]['max_threshold'] = threshold

        if value < threshold_with_min_max[metric]['min_value']:
            threshold_with_min_max[metric]['min_value'] = value
            threshold_with_min_max[metric]['min_threshold'] = threshold

def print_extremes(threshold_with_min_max: Dict[str, Dict]):
    """
    Print the extreme values for each metric and their corresponding thresholds.
    """
    for metric, info in threshold_with_min_max.items():
        print(f"{metric}:")
        print(f"  Min value: {info['min_value']}, Threshold: {info['min_threshold']}")
        print(f"  Max value: {info['max_value']}, Threshold: {info['max_threshold']}")

def metrics_sum(
    metrics: Dict[int, Dict[str, Dict[str, float]]],
    metrics_to_sum: List[str]
    ):
    """
    prints the sum of all tp fp tn fn for all expirements using all
    thresholds
    and the min fp and fn and the mac tp nd tn
    :param metrics: is something like this
    {
        1: {exp1: {TP: 0, FP: 0, TN: 0, FN:}, 'exp2':...}
        2: {exp1: {TP: 0, FP: 0, TN: 0, FN:}, 'exp2':...}
    }
    :param metrics_to_sum: list of what metrics to print the sum of for
    example ["FP", "MCC", etc...]
    """
    threshold_with_min_max = {
        metric: {'min_value': float("inf"),
                 'max_value': 0,
                 'min_threshold': None,
                 'max_threshold': None} for metric in metrics_to_sum}

    for threshold, experiments in metrics.items():
        metrics_sum = {metric: 0 for metric in metrics_to_sum}

        for experiment_metrics in experiments.values():
            for metric in metrics_to_sum:
                metrics_sum[metric] += experiment_metrics[metric]

        print_metrics_summary(threshold, metrics_sum)
        update_extremes(threshold, metrics_sum, threshold_with_min_max)
        
    print_extremes(threshold_with_min_max)

    
def get_confusion_metrics(exp: str,
    scores: Dict[str, float],
    threshold: int) \
        -> Dict[str, float]:
    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for twid, max_threat_level in scores.items():
        twid: str
        max_threat_level: float
        # get the gt label of this twid
        malicious: bool = is_tw_malicious(exp, int(twid))

        if malicious:
            if max_threat_level >= threshold:
                tp += 1
            elif max_threat_level < threshold:
                fn += 1
        else:
            if max_threat_level >= threshold:
                fp +=1
            elif max_threat_level < threshold:
                tn += 1

    confusion_matrix = {
        'TP': tp,
        'FP': fp,
        'TN': tn,
        'FN': fn
    }
    return confusion_matrix

def parse_args():
    parser = ArgumentParser(description='Process some integers.')
    parser.add_argument('-p',
                        '--plot',
                        action='store_true',
                        help='Call plot function')
    return parser.parse_args()
    
def main():
    
    args = parse_args()
    expirements_number = len(extracted_threat_levels)

    metrics: Dict[int, Dict[str, Dict[str, float]]] = {}

    for threshold in range(1, 400):
        metrics[threshold] = {}

        for exp, scores in extracted_threat_levels.items():
            exp: str
            # these are the scores detected by slips
            scores: Dict[str, float]

            confusion_matrix: Dict[str, float] = get_confusion_metrics(
                exp, scores, threshold
            )
            calc = Calculator("slips", f'/tmp/slips_threshold_{threshold}')
            calc.metrics = confusion_matrix
            # calc.calc_all_metrics()
            experiment_metrics = {
                    'MCC': calc.MCC(),
                    'recall': calc.recall(),
                    'precision': calc.precision(),
                    'F1': calc.F1(),
                    'FPR': calc.FPR(),
                    'TPR': calc.TPR(),
                    'FNR': calc.FNR(),
                    'TNR': calc.TNR(),
                    'accuracy': calc.accuracy(),
                }
            experiment_metrics.update(confusion_matrix)
            metrics[threshold].update({exp: experiment_metrics})

    print(f"Total experiments: {expirements_number}")
    if args.plot:
        plot = Plot()
        plot.line(metrics, [
                'TP',
                'TN',
                'FP',
                'FN',
                'MCC',
                'recall',
                'precision',
                'F1',
                'FPR',
                'TPR',
                'FNR',
                'TNR',
                'accuracy'
            ])
    else:
        pp(metrics)
        metrics_sum(
            metrics,
            [
                'TP',
                'TN',
                'FP',
                'FN',
                'MCC',
                'recall',
                'precision',
                'F1',
                'FPR',
                'TPR',
                'FNR',
                'TNR',
                'accuracy'
            ]
        )

if __name__ == "__main__":
    main()


