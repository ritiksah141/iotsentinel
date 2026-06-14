from dash import html


_OVERLAY_BASE_STYLE = {
    "display": "none",          # hidden when unlocked; callback sets to "flex" when locked
    "position": "absolute",
    "top": 0, "left": 0, "right": 0, "bottom": 0,
    "background": "rgba(15, 23, 42, 0.75)",
    "backdropFilter": "blur(2px)",
    "color": "rgba(255, 255, 255, 0.9)",
    "flexDirection": "column",
    "alignItems": "center",
    "justifyContent": "center",
    "cursor": "pointer",
    "borderRadius": "0.5rem",
    "zIndex": 10,
}


def padlock_overlay(child, feature_id: str, plain_desc: str):
    """
    Wrap *child* in a relative-positioned container that has a lockable overlay.

    The overlay starts hidden.  The `update_lock_states` callback in
    callbacks_padlock.py sets its display to 'flex' when the integration has
    no credentials, revealing the padlock icon.

    Args:
        child:       The Dash component to wrap (e.g. the card button div).
        feature_id:  Unique slug used as the pattern-match key ('email', 'api-hub').
        plain_desc:  Tooltip / aria-label describing what unlocking gives the user.
    """
    return html.Div(
        [
            child,
            html.Div(
                [
                    html.I(className="fa fa-lock fa-xl mb-1"),
                    html.P(
                        "Click to set up",
                        className="mb-0 fw-semibold u-text-xxs",
                    ),
                ],
                id={"type": "padlock-overlay", "feature": feature_id},
                n_clicks=0,
                title=plain_desc,
                style=_OVERLAY_BASE_STYLE.copy(),
            ),
        ], className="position-relative",
    )
