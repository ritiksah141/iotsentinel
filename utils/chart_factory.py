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
