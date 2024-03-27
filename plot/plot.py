import seaborn as sns
import matplotlib.pyplot as plt
from typing import Dict, List


class Plot:

    def line(self,
        metrics: Dict[int, Dict[str, Dict[str, float]]],
        metrics_to_plot: List[str]
        ):
    
        # Extract x-axis labels
        x = list(metrics.keys())
        for metric in metrics_to_plot:
            y = []
            # Plot each metric as a separate line
            for threshold, experiments in metrics.items():
                _sum = 0
                for exp_name, exp_values in experiments.items():
                    _sum += exp_values[metric]
                
                y.append(_sum)
            plt.plot(x, y, label=metric)
    
        plt.xlabel('thresholds')
        plt.ylabel("metrics")
        plt.title('Metrics Over Thresholds')
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
