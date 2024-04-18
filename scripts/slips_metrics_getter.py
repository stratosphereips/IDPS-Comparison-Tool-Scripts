"""
calculates the TP TN FP FN for each threshold in the range 0..150
this script tries all thresholds on all expirements on all tws

Usage: python3 scripts/slips_metrics_getter.py

"""

from typing import Dict, List
from pprint import pp
from argparse import ArgumentParser

from plot.plot import Plot
from scripts.extracted_scores.extracted_levels import extracted_threat_levels
from scripts.extracted_scores.extracted_gt_tw_labels import gt_tw_labels
from metrics.calculator import Calculator


THRESHOLDS_TO_BRUTEFORCE = range(1, 400)

def print_line():
    print("-"*20)

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

def print_metrics_summary(metrics: Dict[str, float]):
    """
    Print the summary of metrics for a specific threshold.
    """
    for metric, value in metrics.items():
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
    print("Below are the minimum and maximum of the 4 error metrics with the threshold that resulted in them.")
    for metric, info in threshold_with_min_max.items():
        print(f"{metric}:")
        print(f"  Min value: {info['min_value']}, Threshold: {info['min_threshold']}")
        print(f"  Max value: {info['max_value']}, Threshold: {info['max_threshold']}")
    print_line()

def get_sum_of_metrics(
    metrics: Dict[int, Dict[str, Dict[str, float]]],
    metrics_to_sum: List[str]
    ) -> Dict[int, Dict[str, float]]:
    """
    prints the sum of all tp fp tn fn for all experiments using all
    thresholds
    and the min fp and fn and the max tp nd tn
    :param metrics: is something like this
    {
        1: {exp1: {TP: 0, FP: 0, TN: 0, FN:}, 'exp2':...}
        2: {exp1: {TP: 0, FP: 0, TN: 0, FN:}, 'exp2':...}
    }
    :param metrics_to_sum: list of what metrics to print the sum of for
    example ["FP", "MCC", etc...]
    returns the following dict
    {
        threshold : {metric: sum}
    }
    """
    
    res: Dict[int, Dict[str, float]] = {}
    for threshold, experiments in metrics.items():
        res[threshold] = {}
        metrics_sum: Dict[str, int] = {metric: 0 for metric in metrics_to_sum}
        
        for experiment_metrics in experiments.values():
            for metric in metrics_to_sum:
                metrics_sum[metric] += experiment_metrics[metric]
                
        for metric in metrics_to_sum:
            res[threshold].update({metric: metrics_sum[metric]})
        
    return res


    
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
    
def avg(values_to_avg: List[float]):
    """returns the avg of the given list"""
    return sum(values_to_avg) / len(values_to_avg)
    
def get_avg_of_metrics(
        metrics: Dict[int, Dict[str, Dict[str, float]]],
        metrics_to_use: List[str],
    ) -> Dict[int, Dict[str, float]]:
    """
    Gathers the values of metrics we need to get the average for
    returns the following dict
    {
        threshold: { MCC: avergae_value, TPR: avergae_value, etc..}
    }
    """
    res: Dict[int, Dict[str, float]] = {}
    for threshold, experiments in metrics.items():
        # for each threshold, we get the avg of
        # the given metrics_to_use
        values_to_avg = {}
        experiments: Dict[str, Dict[str, float]]
        
        for experiment_metrics in experiments.values():
            experiment_metrics: Dict[str, float]
            
            for metric in metrics_to_use:
                matric_val: float = experiment_metrics[metric]
                try:
                    values_to_avg[metric].append(matric_val)
                except KeyError:
                    values_to_avg[metric] = [matric_val]
                    
        for metric, to_avg in values_to_avg.items():
            metric: str
            to_avg: List[float]
            try:
                res[threshold].update({ metric: avg(to_avg)})
            except KeyError:
                res[threshold] = { metric: avg(to_avg)}
    return res
    
def get_extremes(metrics_to_sum: List[str], _sum: Dict[int, Dict[str, float]]):
    """
    prints the thresholds resulting in min FP, FN and max TP, TN
    """
    threshold_with_min_max = {
        metric: {'min_value': float("inf"),
                 'min_threshold': None,
                 'max_value': 0,
                 'max_threshold': None} for metric in metrics_to_sum}
    for threshold, metric_sum in _sum.items():
        update_extremes(threshold, metric_sum, threshold_with_min_max)
    return threshold_with_min_max
    
def main():
    
    args = parse_args()
    expirements_number = len(extracted_threat_levels)

    metrics: Dict[int, Dict[str, Dict[str, float]]] = {}

    for threshold in THRESHOLDS_TO_BRUTEFORCE:
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
                    'precision': calc.precision(),
                    'FPR': calc.FPR(),
                    'TPR': calc.TPR(),
                    'FNR': calc.FNR(),
                    'TNR': calc.TNR(),
                    'accuracy': calc.accuracy(),
                    'F1': calc.F1(),
                }
            experiment_metrics.update(confusion_matrix)
            metrics[threshold].update({exp: experiment_metrics})

    print(f"Total experiments: {expirements_number}")


    pp(metrics)
    print_line()
    error_metrics = [
            'TP',
            'TN',
            'FP',
            'FN',
        ]
    
    sum_of_confusion_matrix_per_threshold: Dict[int, Dict[str, float]] = get_sum_of_metrics(
        metrics,
        error_metrics
    )
    print("Printing total error metrics for all experiments")
    # example of error_rates = {1: {'MCC': 0, 'FPR': 0.2, etc..}}
    error_rates: Dict[int, Dict[str, float]] = {}
    for threshold, confusion_matrix_sum in (
            sum_of_confusion_matrix_per_threshold.items()
    ):
        # this contains the sum of FP TP FN TN for 1 threshold
        confusion_matrix_sum: Dict[str, float]
        
        print(f"\nThreshold: {threshold}:")
        # print the error values only , tp fp tn and fn.
        print_metrics_summary(confusion_matrix_sum)

        # now calc the TPR TNR FPR MCC etc. using the total fp fn tp tn
        # from confusion_matrix_sum.
        calc = Calculator("slips", f'/tmp/slips_threshold_{threshold}')
        calc.metrics = confusion_matrix_sum.copy()
        # store the FPR TNR MCC F1 score etc. ofthe above confusion_matrix_sum
        error_rates.update(
            { threshold: calc.calc_all_metrics() }
        )
        print_metrics_summary(error_rates[threshold])
        print_line()
        
    
    print_extremes(get_extremes(
        error_metrics,
        sum_of_confusion_matrix_per_threshold
        ))
    
    
    if args.plot:
        plot = Plot()
        plot.line(
            sum_of_confusion_matrix_per_threshold,
            "Sum of Errors Over Thresholds",
            y_axis_label="Errors"
            )
        plot.line(
            error_rates,
            "Error Rates Over Thresholds",
            y_axis_label="Rates"
            
        )
        
        

if __name__ == "__main__":
    main()


