"""
ChartFactory - Centralized chart generation utility for IoTSentinel Dashboard
Provides consistent styling and configuration for all Plotly charts.

Author: IoTSentinel Team
Date: 2025-12-28
"""

# Color Schemes - Centralized color definitions
SEVERITY_COLORS = {
    'critical': '#dc3545',
    'high': '#ffc107',
    'medium': '#17a2b8',
    'low': '#28a745'
}

SEVERITY_COLORS_LIST = ['#dc3545', '#ffc107', '#17a2b8', '#28a745']

DEVICE_STATUS_COLORS = {
    'normal': '#28a745',
    'warning': '#ffc107',
    'alert': '#dc3545',
    'unknown': '#6c757d'
}

RISK_COLORS = ['#ffc107', '#dc3545', '#fd7e14', '#dc3545']

# Chart configuration constants
CHART_DEFAULTS = {
    'font_size': 11
}


class ChartFactory:
    """Factory class for generating consistent Plotly charts"""

    @staticmethod
    def _get_base_layout(title='', margin=None):
        """Get base layout configuration for all charts"""
        return {
            'title': title,
            'font': {'size': CHART_DEFAULTS['font_size']},
            'margin': margin or {'l': 50, 'r': 20, 't': 40, 'b': 50}
        }

    @staticmethod
    def create_pie_chart(labels, values, colors=None, title='', hole=0.0, show_legend=True,
                        legend_orientation='h'):
        """
        Create a pie/donut chart

        Args:
            labels: List of category labels
            values: List of numeric values
            colors: List of colors (optional, uses SEVERITY_COLORS if not provided)
            title: Chart title
            hole: Size of center hole (0.0=pie, 0.4=donut)
            show_legend: Show legend
            legend_orientation: 'h' or 'v'

        Returns:
            dict: Plotly figure dictionary
        """
        if not colors:
            colors = SEVERITY_COLORS_LIST[:len(labels)]

        # Adjust top margin based on whether there's a title
        # Increased to 95 to prevent title cutoff
        top_margin = 95 if title else 20
        # Pass empty title to base layout since we'll position it ourselves
        layout = ChartFactory._get_base_layout('', {'l': 20, 'r': 20, 't': top_margin, 'b': 80})
        layout.update({
            'showlegend': show_legend,
            'legend': {
                'orientation': legend_orientation,
                'yanchor': 'bottom',
                'y': -0.2 if legend_orientation == 'h' else 0.5,
                'xanchor': 'center' if legend_orientation == 'h' else 'left',
                'x': 0.5 if legend_orientation == 'h' else 1
            },
            'title': {
                'text': title,
                'x': 0.05,  # Position title on the left
                'xanchor': 'left',
                'font': {'size': 14}
            }
        })

        return {
            'data': [{
                'type': 'pie',
                'labels': labels,
                'values': values,
                'marker': {'colors': colors},
                'hole': hole,
                'textinfo': 'label+percent',
                'textfont': {'size': 12}
            }],
            'layout': layout
        }

    @staticmethod
    def create_bar_chart(x_values, y_values, colors=None, title='', x_title='', y_title='',
                        orientation='v', tick_angle=0):
        """
        Create a bar chart

        Args:
            x_values: List of x-axis values
            y_values: List of y-axis values
            colors: Single color or list of colors
            title: Chart title
            x_title: X-axis title
            y_title: Y-axis title
            orientation: 'v' (vertical) or 'h' (horizontal)
            tick_angle: Angle for x-axis labels (e.g., -30 for rotated)

        Returns:
            dict: Plotly figure dictionary
        """
        bottom_margin = 100 if tick_angle != 0 else 60
        layout = ChartFactory._get_base_layout(title, {'l': 50, 'r': 20, 't': 40, 'b': bottom_margin})
        layout.update({
            'xaxis': {
                'title': x_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'tickangle': tick_angle
            },
            'yaxis': {
                'title': y_title,
                'gridcolor': 'rgba(128,128,128,0.2)'
            }
        })

        return {
            'data': [{
                'type': 'bar',
                'x': x_values,
                'y': y_values,
                'orientation': orientation,
                'marker': {
                    'color': colors if colors else '#17a2b8',
                    'line': {'color': 'rgba(255,255,255,0.2)', 'width': 1}
                }
            }],
            'layout': layout
        }

    @staticmethod
    def create_line_chart(x_values, y_values, line_color='#17a2b8', title='', x_title='',
                         y_title='', mode='lines+markers', fill=None):
        """
        Create a line/scatter chart

        Args:
            x_values: List of x-axis values
            y_values: List of y-axis values
            line_color: Color of the line
            title: Chart title
            x_title: X-axis title
            y_title: Y-axis title
            mode: 'lines', 'markers', or 'lines+markers'
            fill: Fill mode ('tozeroy', 'tonexty', or None)

        Returns:
            dict: Plotly figure dictionary
        """
        layout = ChartFactory._get_base_layout(title)
        layout.update({
            'xaxis': {
                'title': x_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'yaxis': {
                'title': y_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'hovermode': 'x unified'
        })

        data_trace = {
            'type': 'scatter',
            'mode': mode,
            'x': x_values,
            'y': y_values,
            'line': {'color': line_color, 'width': 3},
            'marker': {'size': 8, 'color': line_color}
        }

        if fill:
            data_trace['fill'] = fill
            data_trace['fillcolor'] = f'rgba({int(line_color[1:3], 16)}, {int(line_color[3:5], 16)}, {int(line_color[5:7], 16)}, 0.2)'

        return {
            'data': [data_trace],
            'layout': layout
        }

    @staticmethod
    def create_multi_line_chart(traces_data, title='', x_title='', y_title='',
                               show_legend=True):
        """
        Create a multi-line chart

        Args:
            traces_data: List of dicts with keys: 'x', 'y', 'name', 'color'
            title: Chart title
            x_title: X-axis title
            y_title: Y-axis title
            show_legend: Show legend

        Returns:
            dict: Plotly figure dictionary
        """
        layout = ChartFactory._get_base_layout(title)
        layout.update({
            'xaxis': {
                'title': x_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'yaxis': {
                'title': y_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'hovermode': 'x unified',
            'legend': {
                'orientation': 'h',
                'yanchor': 'bottom',
                'y': 1.02,
                'xanchor': 'right',
                'x': 1
            }
        })

        data = []
        for trace in traces_data:
            data.append({
                'type': 'scatter',
                'mode': 'lines+markers',
                'x': trace['x'],
                'y': trace['y'],
                'name': trace['name'],
                'line': {'color': trace['color'], 'width': 2},
                'marker': {'size': 8}
            })

        return {
            'data': data,
            'layout': layout
        }

    @staticmethod
    def create_stacked_bar_chart(x_values, y_data_list, labels, colors, title='', x_title='',
                                  y_title=''):
        """
        Create a stacked bar chart

        Args:
            x_values: List of x-axis values (shared across all bars)
            y_data_list: List of y-value lists (one list per bar series)
            labels: List of labels for each bar series
            colors: List of colors for each bar series
            title: Chart title
            x_title: X-axis title
            y_title: Y-axis title

        Returns:
            dict: Plotly figure dictionary
        """
        layout = ChartFactory._get_base_layout(title, {'l': 50, 'r': 20, 't': 40, 'b': 60})
        layout.update({
            'barmode': 'stack',
            'xaxis': {
                'title': x_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'yaxis': {
                'title': y_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'hovermode': 'x unified',
            'legend': {
                'orientation': 'h',
                'yanchor': 'bottom',
                'y': 1.02,
                'xanchor': 'right',
                'x': 1
            }
        })

        data = []
        for i, (y_values, label, color) in enumerate(zip(y_data_list, labels, colors)):
            data.append({
                'type': 'bar',
                'x': x_values,
                'y': y_values,
                'name': label,
                'marker': {'color': color}
            })

        return {
            'data': data,
            'layout': layout
        }

    @staticmethod
    def create_empty_chart(message='No data available'):
        """
        Create an empty chart with a message

        Args:
            message: Message to display

        Returns:
            dict: Plotly figure dictionary
        """
        return {
            'data': [],
            'layout': {
                'annotations': [{
                    'text': message,
                    'showarrow': False,
                    'font': {'size': 16}
                }]
            }
        }

    @staticmethod
    def create_radar_chart(categories, your_scores, industry_scores, title=''):
        """
        Create a radar/polar chart for comparison

        Args:
            categories: List of category names
            your_scores: List of scores for "Your Network"
            industry_scores: List of scores for "Industry Avg"
            title: Chart title

        Returns:
            dict: Plotly figure dictionary
        """
        return {
            'data': [
                {
                    'type': 'scatterpolar',
                    'r': your_scores + [your_scores[0]],
                    'theta': categories + [categories[0]],
                    'fill': 'toself',
                    'name': 'Your Network',
                },
                {
                    'type': 'scatterpolar',
                    'r': industry_scores + [industry_scores[0]],
                    'theta': categories + [categories[0]],
                    'fill': 'toself',
                    'name': 'Industry Avg',
                    'line': {'width': 2, 'dash': 'dash'}
                }
            ],
            'layout': {
                'polar': {
                    'radialaxis': {
                        'visible': True,
                        'range': [0, 100],
                    },
                },
                'showlegend': True,
                'legend': {'orientation': 'h', 'yanchor': 'bottom', 'y': -0.2},
                'margin': {'l': 80, 'r': 80, 't': 20, 'b': 80}
            }
        }

    @staticmethod
    def create_area_chart(x_values, y_values, fill_color='#17a2b8', line_color='#0d6efd',
                          title='', x_title='', y_title='', show_line=True):
        """
        Create an area chart for trend visualization

        Args:
            x_values: List of x-axis values (usually time periods)
            y_values: List of y-axis values
            fill_color: Color for the filled area
            line_color: Color for the border line
            title: Chart title
            x_title: X-axis title
            y_title: Y-axis title
            show_line: Show border line on top of area

        Returns:
            dict: Plotly figure dictionary
        """
        layout = ChartFactory._get_base_layout(title)
        layout.update({
            'xaxis': {
                'title': x_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'yaxis': {
                'title': y_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'hovermode': 'x unified'
        })

        return {
            'data': [{
                'type': 'scatter',
                'mode': 'lines' if show_line else 'none',
                'x': x_values,
                'y': y_values,
                'fill': 'tozeroy',
                'fillcolor': fill_color,
                'line': {'color': line_color, 'width': 2} if show_line else {}
            }],
            'layout': layout
        }

    @staticmethod
    def create_trend_chart(x_values, y_values, show_moving_avg=True, ma_period=7,
                          title='', x_title='', y_title='', trend_color='#17a2b8',
                          ma_color='#ffc107'):
        """
        Create a trend chart with optional moving average overlay

        Args:
            x_values: List of x-axis values (time periods)
            y_values: List of y-axis values (actual data)
            show_moving_avg: Show moving average line
            ma_period: Moving average period (default 7)
            title: Chart title
            x_title: X-axis title
            y_title: Y-axis title
            trend_color: Color for actual data line
            ma_color: Color for moving average line

        Returns:
            dict: Plotly figure dictionary
        """
        layout = ChartFactory._get_base_layout(title)
        layout.update({
            'xaxis': {
                'title': x_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'yaxis': {
                'title': y_title,
                'gridcolor': 'rgba(128,128,128,0.2)',
                'showgrid': True
            },
            'hovermode': 'x unified',
            'legend': {
                'orientation': 'h',
                'yanchor': 'bottom',
                'y': 1.02,
                'xanchor': 'right',
                'x': 1
            }
        })

        # Actual data trace
        data = [{
            'type': 'scatter',
            'mode': 'lines+markers',
            'x': x_values,
            'y': y_values,
            'name': 'Actual',
            'line': {'color': trend_color, 'width': 2},
            'marker': {'size': 6}
        }]

        # Calculate and add moving average if requested
        if show_moving_avg and len(y_values) >= ma_period:
            moving_avg = []
            for i in range(len(y_values)):
                if i < ma_period - 1:
                    moving_avg.append(None)
                else:
                    avg = sum(y_values[i-ma_period+1:i+1]) / ma_period
                    moving_avg.append(avg)

            data.append({
                'type': 'scatter',
                'mode': 'lines',
                'x': x_values,
                'y': moving_avg,
                'name': f'{ma_period}-Period MA',
                'line': {'color': ma_color, 'width': 3, 'dash': 'dash'}
            })

        return {
            'data': data,
            'layout': layout
        }

    @staticmethod
    def create_heatmap(x_labels, y_labels, z_values, title='', x_title='', y_title='',
                       colorscale='RdYlGn_r'):
        """
        Create a heatmap for pattern visualization

        Args:
            x_labels: List of x-axis labels
            y_labels: List of y-axis labels
            z_values: 2D array of values (rows = y_labels, cols = x_labels)
            title: Chart title
            x_title: X-axis title
            y_title: Y-axis title
            colorscale: Color scale ('RdYlGn_r' for red-yellow-green reversed)

        Returns:
            dict: Plotly figure dictionary
        """
        layout = ChartFactory._get_base_layout(title, {'l': 100, 'r': 20, 't': 60, 'b': 100})
        layout.update({
            'xaxis': {
                'title': x_title,
                'side': 'bottom'
            },
            'yaxis': {
                'title': y_title
            }
        })

        return {
            'data': [{
                'type': 'heatmap',
                'x': x_labels,
                'y': y_labels,
                'z': z_values,
                'colorscale': colorscale,
                'hoverongaps': False,
                'colorbar': {
                    'title': 'Count',
                    'titleside': 'right'
                }
            }],
            'layout': layout
        }

    @staticmethod
    def create_gauge_chart(value, max_value=100, title='', thresholds=None,
                          colors=None, show_delta=False, delta_reference=None):
        """
        Create an enhanced gauge/indicator chart for KPI visualization with animations

        Args:
            value: Current value
            max_value: Maximum value for the gauge (default 100 for security score)
            title: Gauge title
            thresholds: List of threshold values [low, medium, high]
                       Default: [50, 80, 100] (red 0-49, yellow 50-79, green 80-100)
            colors: List of colors for each threshold range
                   Default: ['#dc3545', '#ffc107', '#28a745'] (red, yellow, green)
            show_delta: Show delta comparison to reference value
            delta_reference: Reference value for delta comparison

        Returns:
            dict: Plotly figure dictionary with animations
        """
        # Security score optimized thresholds
        if thresholds is None:
            thresholds = [50, 80, max_value]
        if colors is None:
            # Red (0-49), Yellow (50-79), Green (80-100)
            colors = ['#dc3545', '#ffc107', '#28a745']

        # Create steps for color ranges (zones)
        steps = []
        prev_threshold = 0
        for i, (threshold, color) in enumerate(zip(thresholds, colors)):
            steps.append({
                'range': [prev_threshold, threshold],
                'color': color,
                'thickness': 0.75
            })
            prev_threshold = threshold

        # Determine bar color based on current value
        bar_color = colors[0]  # Default red
        for i, threshold in enumerate(thresholds):
            if value <= threshold:
                bar_color = colors[i]
                break

        # Build gauge configuration
        gauge_config = {
            'axis': {
                'range': [0, max_value],
                'tickwidth': 2,
                'tickcolor': '#333',
                'tickfont': {'size': 12}
            },
            'bar': {
                'color': bar_color,
                'thickness': 0.8,
                'line': {'width': 0}
            },
            'steps': steps,
            'borderwidth': 2,
            'bordercolor': '#333',
            'shape': 'angular'  # Speedometer style
        }

        # Build indicator data
        indicator_data = {
            'type': 'indicator',
            'mode': 'gauge+number',
            'value': value,
            'title': {
                'text': title,
                'font': {'size': 18, 'weight': 'bold', 'color': '#333'}
            },
            'number': {
                'font': {'size': 36, 'weight': 'bold'},
                'suffix': f'/{max_value}'
            },
            'gauge': gauge_config
        }

        # Add delta if requested
        if show_delta and delta_reference is not None:
            indicator_data['mode'] = 'gauge+number+delta'
            indicator_data['delta'] = {
                'reference': delta_reference,
                'increasing': {'color': '#28a745'},
                'decreasing': {'color': '#dc3545'},
                'font': {'size': 16}
            }

        return {
            'data': [indicator_data],
            'layout': {
                'margin': {'l': 30, 'r': 30, 't': 80, 'b': 30},
                'height': 300,
                'paper_bgcolor': 'rgba(0,0,0,0)',
                'plot_bgcolor': 'rgba(0,0,0,0)',
                'font': {'color': '#333'},
                'transition': {
                    'duration': 800,
                    'easing': 'cubic-in-out'
                }
            },
            'config': {
                'displayModeBar': False
            }
        }

    @staticmethod
    def create_waterfall_chart(categories, values, title='', x_title='', y_title=''):
        """
        Create a waterfall chart showing cumulative changes

        Args:
            categories: List of category labels
            values: List of values (positive or negative changes)
            title: Chart title
            x_title: X-axis title
            y_title: Y-axis title

        Returns:
            dict: Plotly figure dictionary
        """
        layout = ChartFactory._get_base_layout(title, {'l': 50, 'r': 20, 't': 40, 'b': 100})
        layout.update({
            'xaxis': {
                'title': x_title,
                'tickangle': -30
            },
            'yaxis': {
                'title': y_title,
                'gridcolor': 'rgba(128,128,128,0.2)'
            },
            'showlegend': False
        })

        # Calculate measures (relative for changes, total for final)
        measure = ['relative'] * (len(categories) - 1) + ['total']

        # Color code: green for positive, red for negative
        colors = []
        for val in values[:-1]:
            colors.append('#28a745' if val >= 0 else '#dc3545')
        colors.append('#17a2b8')  # Blue for total

        return {
            'data': [{
                'type': 'waterfall',
                'x': categories,
                'y': values,
                'measure': measure,
                'text': [f'{v:+.0f}' if v != values[-1] else f'{v:.0f}' for v in values],
                'textposition': 'outside',
                'connector': {
                    'line': {'color': 'rgba(128,128,128,0.5)', 'width': 2}
                },
                'increasing': {'marker': {'color': '#28a745'}},
                'decreasing': {'marker': {'color': '#dc3545'}},
                'totals': {'marker': {'color': '#17a2b8'}}
            }],
            'layout': layout
        }

    @staticmethod
    def create_box_plot(data_groups, labels, title='', y_title='', show_outliers=True):
        """
        Create a box plot for distribution analysis

        Args:
            data_groups: List of data arrays (one array per box)
            labels: List of labels for each box
            title: Chart title
            y_title: Y-axis title
            show_outliers: Show outlier points

        Returns:
            dict: Plotly figure dictionary
        """
        layout = ChartFactory._get_base_layout(title, {'l': 50, 'r': 20, 't': 40, 'b': 80})
        layout.update({
            'yaxis': {
                'title': y_title,
                'gridcolor': 'rgba(128,128,128,0.2)'
            },
            'showlegend': False
        })

        data = []
        colors = ['#17a2b8', '#28a745', '#ffc107', '#dc3545']
        for i, (values, label) in enumerate(zip(data_groups, labels)):
            data.append({
                'type': 'box',
                'y': values,
                'name': label,
                'marker': {'color': colors[i % len(colors)]},
                'boxpoints': 'outliers' if show_outliers else False
            })

        return {
            'data': data,
            'layout': layout
        }
