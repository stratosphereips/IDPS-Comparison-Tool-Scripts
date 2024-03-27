import seaborn as sns
import matplotlib.pyplot as plt
from typing import Dict, List


class Plot:
    def line(self,
            metrics_per_threshold: Dict[int, Dict[str, float]],
            title: str
            ):
        """
        Each call to this function results in one graph/plot , each metric in
        metrics_to_plot will result in one line in this graph.
        X-axis is determined by the metrics.keys()
        Y-axis is determined by the metrics.values().values()
        
        :param metrics_per_threshold: a dict in the following format:
        {
            1: { 'TP': 4, 'TN': 0, 'FP': 10, 'FN':12}
            2: { 'TP': 4, 'TN': 0, 'FP': 10, 'FN':12} ...
        }
        
        :param title: Title of the plot
        """
        
        # Extract x-axis labels. put all thresholds on the x-axis.
        x_axis = list(metrics_per_threshold.keys())
        # keys(aka metrics to plot) should be identical in all thresholds
        metrics_to_plot: List[str] = list(
            metrics_per_threshold.values()
            )[0].keys()

        for metric in metrics_to_plot:
            # Plot each metric as a separate line
            y_axis = []
            for threshold in x_axis:
                # get the metric value in this threshold
                y_axis.append(metrics_per_threshold[threshold][metric])
            plt.plot(x_axis, y_axis, label=metric)
            

        plt.title(title)
        plt.xlabel('Thresholds')
        plt.ylabel("Metrics")
        plt.legend()
        plt.show()

    
    def scatter(self,
        metrics: Dict[int, Dict[str, Dict[str, float]]],
        metrics_to_plot: List[str]
        ):
        # example of metrics dict {
        #     1: {exp1: {TP: 0, FP: 0, TN: 0, FN:}, 'exp2':...}
        #     2: {exp1: {TP: 0, FP: 0, TN: 0, FN:}, 'exp2':...}
        # }
        
        for metric in metrics_to_plot:
            res = []
            for threshold, expirement_details in metrics.items():
                _sum = 0
                for exp_name, m in expirement_details.items():
                    _sum += m[metric]
                res.append(_sum)
                
            sns.scatterplot(x=metrics.keys(), y=res)
            plt.xlabel('threshold')
            plt.ylabel(metric)
            plt.title(f'{metric} over threshold')
            plt.show()
