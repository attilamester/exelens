from typing import List

from malflow import CallGraph


def draw_call_depth_diagram(
    cg: CallGraph,
    file_path: str,
):
    sequence = cg.dfs_call_depth_sequence(keep_instructions=False)
    print(f"Drawing call depth diagram with {len(sequence)} points...")
    # print(max(sequence))
    plot_depth_sequence(sequence, file_path)

    # sequence = linear_sample_sequence_smoothed(sequence, fixed_width=512, max_y_value=224, sampling_method='average')




def plot_depth_sequence(depth_sequence: List[int], filename: str):
    """
    Plots the fixed-length call-depth sequence array.
    """
    import matplotlib.pyplot as plt
    N = len(depth_sequence)
    X_axis = list(range(N))
    WIDTH = 512
    HEIGHT = 224
    DPI = 100

    plt.figure(figsize=(WIDTH / DPI, HEIGHT / DPI), dpi=DPI)
    plt.scatter(X_axis, depth_sequence, color='darkblue', s=1)

    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    plt.gca().spines['left'].set_visible(False)
    plt.gca().spines['bottom'].set_visible(False)
    plt.xlim(0, N)
    plt.ylim(0, max(depth_sequence) + 2 if max(depth_sequence) < 50 else 52)
    plt.xticks([])
    plt.yticks([])
    plt.tight_layout()
    plt.savefig(filename, bbox_inches='tight', pad_inches=0.1, format="png")
    plt.close()

import math
import numpy as np
def linear_sample_sequence_smoothed(
        depth_sequence: List[int],
        fixed_width: int,
        max_y_value: int = 50,
        sampling_method: str = 'average'  # Can be 'average' or 'max'
) -> List[int]:
    """
    Scales and smooths the variable-length depth sequence to a fixed width
    using Average or Max Pooling.
    """
    L_sample = len(depth_sequence)
    if L_sample == 0:
        return [0] * fixed_width

    # Convert to numpy array for fast slicing and aggregation
    depth_array = np.array(depth_sequence)

    sampled_data: List[int] = []

    # Calculate the ratio (segment width in the source array)
    ratio = L_sample / fixed_width

    for x_prime in range(fixed_width):
        # Determine the start and end indices of the segment in the source array
        i_start = math.floor(x_prime * ratio)
        i_end = math.floor((x_prime + 1) * ratio)

        # Ensure i_end doesn't exceed the array bounds
        i_end = min(i_end, L_sample)

        # Slice the segment
        segment = depth_array[i_start:i_end]

        if len(segment) == 0:
            # Should only happen if the fixed_width > L_sample and the ratio causes issues
            aggregated_value = 0
        elif sampling_method == 'max':
            # Max Pooling: Captures the highest depth in the window
            aggregated_value = np.max(segment)
        else:  # Default: 'average'
            # Average Pooling: Smoothes the signal
            aggregated_value = np.mean(segment)

        # --- Y-Axis Normalization ---
        # Cap the depth and ensure it's an integer for image generation
        normalized_depth = int(round(min(aggregated_value, max_y_value)))

        sampled_data.append(normalized_depth)

    return sampled_data