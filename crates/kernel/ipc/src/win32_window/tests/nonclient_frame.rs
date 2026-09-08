//! What a window's own frame takes off its rectangle, and what it draws
//! there. The numbers are the documented frame of each style combination, so
//! a control that loses its sunken border or a dialog that loses its frame
//! fails here rather than on a screen someone is watching.
use super::*;

/// The metric owner's own defaults for the frame dimensions.
const M: FrameMetrics = FrameMetrics { frame: 4, dlg_frame: 3, edge: 2, padded_border: 0 };

const WS_CHILD: u32 = 0x4000_0000;

#[test]
fn a_plain_child_has_no_frame_and_every_border_style_takes_its_own_band() {
    assert_eq!(client_inset(WS_CHILD, 0, M), 0);
    // A bordered control: one line.
    assert_eq!(client_inset(WS_CHILD | WS_BORDER, 0, M), 1);
    // An edit control's sunken client edge: two pixels of edge on top of it.
    assert_eq!(client_inset(WS_CHILD | WS_BORDER, WS_EX_CLIENTEDGE, M), 3);
    assert_eq!(client_inset(WS_CHILD, WS_EX_CLIENTEDGE, M), 2);
    // A static edge is one pixel and replaces nothing else.
    assert_eq!(client_inset(WS_CHILD, WS_EX_STATICEDGE, M), 1);
    // A dialog frame: the raised outer edge, the frame itself, and its line.
    assert_eq!(client_inset(WS_DLGFRAME, 0, M), 3);
    // A sizing frame carries the resize border beyond the dialog frame.
    assert_eq!(client_inset(WS_THICKFRAME | WS_BORDER, 0, M), 2 + (M.frame - M.dlg_frame) + 1);
    // A minimised window has no client area to inset.
    assert_eq!(client_inset(WS_MINIMIZE | WS_THICKFRAME | WS_CAPTION, 0, M), 0);
}

/// A window server that decorates what it manages draws the title bar and the
/// resize border itself. The window draws the rest, and reserves exactly what
/// it draws: a dialog whose frame the server drew and whose client area was
/// inset for it again shows a band of nothing where the frame was counted
/// twice.
#[test]
fn a_decorated_window_keeps_only_the_frame_its_server_does_not_draw() {
    let (style, ex) = own_styles(WS_CAPTION | WS_THICKFRAME | WS_BORDER, WS_EX_DLGMODALFRAME | WS_EX_CLIENTEDGE, true);
    assert_eq!(style & (WS_CAPTION | WS_THICKFRAME | WS_BORDER), 0);
    assert_eq!(ex, WS_EX_CLIENTEDGE);
    assert_eq!(client_inset(style, ex, M), M.edge);
    // Undecorated, the same window draws and reserves its whole frame.
    let (style, ex) = own_styles(WS_CAPTION | WS_THICKFRAME, WS_EX_DLGMODALFRAME, false);
    assert_eq!(client_inset(style, ex, M), 2 + (M.frame - M.dlg_frame) + 1);
    // A child is never decorated by anyone, whatever the flag says.
    assert_eq!(own_styles(WS_CHILD | WS_BORDER, WS_EX_CLIENTEDGE, false), (WS_CHILD | WS_BORDER, WS_EX_CLIENTEDGE));
}

/// A bordered control draws one band of the window-frame colour around its
/// whole rectangle, and the rectangle it leaves is the one its client area
/// starts at.
#[test]
fn a_bordered_control_draws_one_band_and_leaves_the_client_rectangle() {
    let rect = MenuRect { left: 0, top: 0, right: 20, bottom: 10 };
    let mut ops = Vec::new();
    let left = frame_ops(rect, WS_CHILD | WS_BORDER, 0, true, M, &mut ops);
    assert_eq!(left, MenuRect { left: 1, top: 1, right: 19, bottom: 9 });
    assert_eq!(ops.len(), 4, "a border is four bands and nothing else");
    for op in &ops {
        let MenuDrawOp::Fill { color, .. } = op else { panic!("a frame draws fills") };
        assert_eq!(*color, SystemColor::WindowFrame);
    }
    assert_eq!(ops[0], MenuDrawOp::Fill { rect: MenuRect { left: 0, top: 0, right: 20, bottom: 1 }, color: SystemColor::WindowFrame });
    assert_eq!(ops[3], MenuDrawOp::Fill { rect: MenuRect { left: 19, top: 0, right: 20, bottom: 10 }, color: SystemColor::WindowFrame });
}

/// An edit control's sunken client edge is drawn after everything else takes
/// its band, in the two colours a sunken edge is drawn in on each side.
#[test]
fn a_client_edge_draws_a_sunken_edge_inside_whatever_the_frame_left() {
    let rect = MenuRect { left: 2, top: 2, right: 18, bottom: 8 };
    let mut ops = Vec::new();
    let left = client_edge_ops(rect, WS_EX_CLIENTEDGE, &mut ops);
    assert_eq!(left, MenuRect { left: 4, top: 4, right: 16, bottom: 6 });
    assert!(!ops.is_empty());
    let colors: Vec<SystemColor> = ops.iter().map(|op| match op { MenuDrawOp::Fill { color, .. } => *color, _ => panic!("an edge draws fills") }).collect();
    assert!(colors.contains(&SystemColor::ButtonShadow), "the top and left of a sunken edge are shadowed");
    assert!(colors.contains(&SystemColor::ButtonHighlight), "the bottom and right of a sunken edge are highlit");
    // Without the style nothing is drawn and nothing is taken.
    let mut none = Vec::new();
    assert_eq!(client_edge_ops(rect, 0, &mut none), rect);
    assert!(none.is_empty());
}

/// A dialog frame is a raised outer edge with the frame colour inside it, and
/// a sizing frame puts the resize border between the two. The rectangle left
/// over is what the client inset names, so the frame drawn and the band
/// reserved are one answer.
#[test]
fn what_the_frame_draws_and_what_the_client_inset_reserves_agree() {
    for (style, ex) in [(WS_DLGFRAME, 0), (WS_THICKFRAME | WS_BORDER, 0), (WS_CHILD | WS_BORDER, WS_EX_CLIENTEDGE),
        (WS_CHILD, WS_EX_STATICEDGE), (WS_CHILD, WS_EX_CLIENTEDGE), (0, WS_EX_DLGMODALFRAME)] {
        let rect = MenuRect { left: 0, top: 0, right: 60, bottom: 40 };
        let mut ops = Vec::new();
        let left = client_edge_ops(frame_ops(rect, style, ex, true, M, &mut ops), ex, &mut ops);
        assert_eq!(left.left - rect.left, client_inset(style, ex, M), "style {style:#x}/{ex:#x} draws a frame the client inset does not reserve");
        assert_eq!(rect.right - left.right, client_inset(style, ex, M), "style {style:#x}/{ex:#x} draws a right band the client inset does not reserve");
        assert!(!ops.is_empty() || client_inset(style, ex, M) == 0);
    }
}

/// A sizing frame's border follows activation: the two colours are what tells
/// a user which window their keystrokes go to.
#[test]
fn a_sizing_border_is_drawn_in_the_activation_colour() {
    let rect = MenuRect { left: 0, top: 0, right: 40, bottom: 40 };
    for (active, want) in [(true, SystemColor::ActiveBorder), (false, SystemColor::InactiveBorder)] {
        let mut ops = Vec::new();
        frame_ops(rect, WS_THICKFRAME, 0, active, M, &mut ops);
        let colors: Vec<SystemColor> = ops.iter().map(|op| match op { MenuDrawOp::Fill { color, .. } => *color, _ => panic!("a frame draws fills") }).collect();
        assert!(colors.contains(&want), "a {} sizing border is drawn in its own colour", if active { "focused" } else { "background" });
    }
}
