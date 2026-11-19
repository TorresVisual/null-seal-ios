#![allow(clippy::unwrap_used)]

use super::*;
use crate::Url;

/// A login whose listed fields were written at the given stamps.
fn p(fields: &[(&str, &str)], tags: &[(&str, &str)], deleted_tags: &[(&str, &str)]) -> Payload {
    let mut item = Item::default();
    let mut hlc = BTreeMap::new();
    for (k, stamp) in fields {
        hlc.insert((*k).to_owned(), (*stamp).to_owned());
        match *k {
            "title" => item.title = "T".into(),
            "username" => item.username = Some("U".into()),
            "password" => item.password = Some("P".into()),
            "notes" => item.notes = Some("N".into()),
            _ => unreachable!(),
        }
    }
    for (t, stamp) in tags {
        item.tags.push((*t).to_owned());
        hlc.insert(format!("tags:{t}"), (*stamp).to_owned());
    }
    for (t, stamp) in deleted_tags {
        hlc.insert(format!("tags:{t}"), (*stamp).to_owned());
    }
    let mut out = Payload::new_login(item);
    out.fields_hlc = hlc;
    out
}

fn with(mut pl: Payload, f: impl FnOnce(&mut Item)) -> Payload {
    f(&mut pl.data);
    pl
}

fn live<'a>(hlc: &'a str, payload: &'a Payload) -> Side<'a> {
    Side {
        hlc,
        tombstone: false,
        payload,
    }
}

fn tomb<'a>(hlc: &'a str, payload: &'a Payload) -> Side<'a> {
    Side {
        hlc,
        tombstone: true,
        payload,
    }
}

/// Content of the merge in both argument orders; they must agree (convergence).
fn both(a: &Side, b: &Side) -> (Payload, bool) {
    let ab = combine(&normalize(a), &normalize(b), a.hlc > b.hlc);
    let ba = combine(&normalize(b), &normalize(a), b.hlc > a.hlc);
    assert_eq!(ab, ba, "merge must not depend on argument order");
    ab
}

#[test]
fn new_type_fields_merge_per_field_and_codes_as_one_register() {
    let wifi = |hlc: &str, f: fn(&mut Item)| {
        let mut item = Item::default();
        f(&mut item);
        let mut x = Payload::new(crate::ItemType::Wifi, item);
        stamp_changes(None, &mut x, hlc);
        x
    };
    // two devices edit different Wi-Fi fields: both survive, in either order
    let a = wifi("01", |i| i.ssid = Some("Home".into()));
    let b = wifi("02", |i| i.password = Some("pw".into()));
    let (m, _) = both(&live("01", &a), &live("02", &b));
    assert_eq!(
        (m.data.ssid.as_deref(), m.data.password.as_deref()),
        (Some("Home"), Some("pw"))
    );
    assert_eq!(m.item_type, crate::ItemType::Wifi);

    // recovery codes: the newer list wins whole, never a mix of both
    let old = wifi("01", |i| i.codes = vec!["a".into(), "b".into()]);
    let new = wifi("02", |i| i.codes = vec!["c".into()]);
    let (m, _) = both(&live("01", &old), &live("02", &new));
    assert_eq!(m.data.codes, ["c"]);
}

#[test]
fn concurrent_edits_to_different_fields_both_survive() {
    let base = p(&[("title", "01"), ("username", "01")], &[], &[]);
    let a = with(
        {
            let mut x = base.clone();
            x.fields_hlc.insert("password".into(), "05".into());
            x
        },
        |i| i.password = Some("new-pw".into()),
    );
    let b = with(
        {
            let mut x = base.clone();
            x.fields_hlc.insert("notes".into(), "06".into());
            x
        },
        |i| i.notes = Some("new-notes".into()),
    );
    let (m, t) = both(&live("05", &a), &live("06", &b));
    assert!(!t);
    assert_eq!(m.data.password.as_deref(), Some("new-pw"));
    assert_eq!(m.data.notes.as_deref(), Some("new-notes"));
    assert_eq!(m.data.title, "T");
    assert!(matches!(
        merge(&live("05", &a), &live("06", &b)),
        Merged::New { .. }
    ));
}

#[test]
fn same_field_conflict_resolves_to_the_later_stamp_on_every_replica() {
    let mut a = p(&[("title", "05")], &[], &[]);
    a.data.title = "from-a".into();
    let mut b = p(&[("title", "07")], &[], &[]);
    b.data.title = "from-b".into();
    let (m, _) = both(&live("05", &a), &live("07", &b));
    assert_eq!(m.data.title, "from-b");
    // the winner already holds everything: adopt it instead of writing a new record
    assert_eq!(merge(&live("05", &a), &live("07", &b)), Merged::Remote);
    assert_eq!(merge(&live("07", &b), &live("05", &a)), Merged::Local);
}

#[test]
fn equal_stamps_break_ties_by_value_not_by_argument_order() {
    let mut a = p(&[("title", "05")], &[], &[]);
    a.data.title = "aaa".into();
    let mut b = p(&[("title", "05")], &[], &[]);
    b.data.title = "bbb".into();
    assert_eq!(both(&live("05", &a), &live("05", &b)).0.data.title, "bbb");
}

#[test]
fn clearing_a_field_beats_an_older_value_and_loses_to_a_newer_one() {
    let old = p(&[("notes", "03")], &[], &[]);
    let mut cleared = p(&[("title", "02")], &[], &[]);
    cleared.fields_hlc.insert("notes".into(), "05".into()); // notes unset at 05
    assert_eq!(
        both(&live("03", &old), &live("05", &cleared)).0.data.notes,
        None
    );
    let newer = p(&[("notes", "09")], &[], &[]);
    assert_eq!(
        both(&live("09", &newer), &live("05", &cleared))
            .0
            .data
            .notes
            .as_deref(),
        Some("N")
    );
}

#[test]
fn sets_merge_adds_and_removes_by_element_stamp() {
    // a added "work" (04) and removed "old" (05); b added "home" (06), still has "old" from 01
    let a = p(&[], &[("work", "04"), ("keep", "01")], &[("old", "05")]);
    let b = p(&[], &[("home", "06"), ("old", "01"), ("keep", "01")], &[]);
    let (m, _) = both(&live("05", &a), &live("06", &b));
    assert_eq!(m.data.tags, ["keep", "work", "home"]); // ordered by (stamp, name)
    // re-adding after a removal wins when newer
    let readd = p(&[], &[("old", "08")], &[]);
    assert!(
        both(&live("05", &a), &live("08", &readd))
            .0
            .data
            .tags
            .contains(&"old".into())
    );
}

#[test]
fn urls_are_a_set_and_keep_unknown_url_fields() {
    let mut a = p(&[], &[], &[]);
    a.data.urls = vec![Url {
        url: "https://a.example".into(),
        r#match: Some("host".into()),
        ..Url::default()
    }];
    a.fields_hlc
        .insert("urls:https://a.example".into(), "02".into());
    let mut b = p(&[], &[], &[]);
    b.data.urls = vec![Url {
        url: "https://b.example".into(),
        ..Url::default()
    }];
    b.fields_hlc
        .insert("urls:https://b.example".into(), "03".into());
    let (m, _) = both(&live("02", &a), &live("03", &b));
    assert_eq!(m.data.urls.len(), 2);
    assert_eq!(m.data.urls[0].url, "https://a.example"); // first added stays primary
    assert_eq!(m.data.urls[0].r#match.as_deref(), Some("host"));
}

#[test]
fn a_delete_wins_over_older_edits_and_loses_to_newer_ones() {
    let edited = p(&[("title", "01"), ("password", "04")], &[("t", "04")], &[]);
    let gone = Payload::tombstone("07");
    // delete (07) is newer than every edit: tombstone, on both sides of the merge
    let (m, t) = both(&live("04", &edited), &tomb("07", &gone));
    assert!(t && m.data == Item::default());
    assert_eq!(
        merge(&live("04", &edited), &tomb("07", &gone)),
        Merged::Remote
    );
    assert_eq!(
        merge(&tomb("07", &gone), &live("04", &edited)),
        Merged::Local
    );

    // an edit at 09 is newer than the delete: it survives, older fields do not
    let later = p(&[("title", "01"), ("password", "09")], &[("t", "04")], &[]);
    let (m, t) = both(&live("09", &later), &tomb("07", &gone));
    assert!(!t);
    assert_eq!(m.data.password.as_deref(), Some("P"));
    assert_eq!(m.data.title, ""); // stamped 01 < 07: deleted
    assert!(m.data.tags.is_empty());
}

#[test]
fn legacy_tombstones_and_unstamped_items_still_merge() {
    // a tombstone written before barriers existed: its record hlc is the barrier
    let legacy_tomb = Payload::new_login(Item::default());
    let unstamped = Payload::new_login(Item {
        title: "old".into(),
        ..Item::default()
    });
    assert!(both(&live("03", &unstamped), &tomb("05", &legacy_tomb)).1);
    // unstamped data against a stamped edit: the stamped field wins, the rest is kept
    let edit = p(&[("title", "06")], &[], &[]);
    let (m, _) = both(&live("03", &unstamped), &live("06", &edit));
    assert_eq!(m.data.title, "T");
}

#[test]
fn merging_is_idempotent_and_associative_across_a_delete() {
    // three concurrent copies: a delete and two edits on either side of it
    let gone = Payload::tombstone("06");
    let e1 = p(&[("title", "02")], &[], &[]);
    let e2 = p(&[("title", "02"), ("password", "09")], &[], &[]);
    let (a, b, c) = (tomb("06", &gone), live("02", &e1), live("09", &e2));
    let step = |x: &Side, y: &Side| {
        let (m, t) = combine(&normalize(x), &normalize(y), true);
        (m, t)
    };
    let (m_ab, t_ab) = step(&a, &b);
    let (m_bc, t_bc) = step(&b, &c);
    let left = step(
        &Side {
            hlc: "09",
            tombstone: t_ab,
            payload: &m_ab,
        },
        &c,
    );
    let right = step(
        &a,
        &Side {
            hlc: "09",
            tombstone: t_bc,
            payload: &m_bc,
        },
    );
    assert_eq!(left, right);
    assert_eq!(step(&b, &b).0, normalize(&b));
}

#[test]
fn unknown_fields_and_extras_are_not_dropped() {
    let mut a = p(&[("title", "01")], &[], &[]);
    a.data
        .unknown
        .insert("future".into(), Value::String("kept".into()));
    a.fields_hlc.insert("future".into(), "05".into());
    a.extras.insert("src".into(), Value::Bool(true));
    let b = p(&[("title", "02")], &[], &[]);
    let (m, _) = both(&live("05", &a), &live("02", &b));
    assert_eq!(m.data.unknown["future"], "kept");
    assert_eq!(m.extras["src"], true);
}

#[test]
fn stamp_changes_marks_only_what_an_edit_touched() {
    let mut old = p(&[("title", "01"), ("username", "01")], &[("a", "01")], &[]);
    let mut new = old.clone();
    new.data.username = Some("changed".into());
    new.data.tags = vec!["b".into()];
    stamp_changes(Some(&old), &mut new, "09");
    assert_eq!(new.fields_hlc["username"], "09");
    assert_eq!(new.fields_hlc["title"], "01");
    assert_eq!(new.fields_hlc["tags:b"], "09"); // added
    assert_eq!(new.fields_hlc["tags:a"], "09"); // removed: the stamp stays as the removal
    // a brand new item stamps everything it has
    old.fields_hlc.clear();
    let mut fresh = Payload::new_login(Item {
        title: "x".into(),
        ..Item::default()
    });
    stamp_changes(None, &mut fresh, "02");
    assert_eq!(fresh.fields_hlc["title"], "02");
}

#[test]
fn namespaced_unknown_fields_survive_and_tombstones_keep_no_extras() {
    let mut a = p(&[("title", "05")], &[], &[]);
    a.data
        .unknown
        .insert("bw:fields".into(), Value::String("kept".into()));
    a.fields_hlc.insert("bw:fields".into(), "05".into());
    a.extras.insert("secret".into(), Value::Bool(true));
    let b = p(&[("title", "02")], &[], &[]);
    let (m, _) = both(&live("05", &a), &live("02", &b));
    assert_eq!(m.data.unknown["bw:fields"], "kept");

    let mut gone = Payload::tombstone("09");
    gone.extras.insert("secret".into(), Value::Bool(true));
    let (m, t) = both(&live("05", &a), &tomb("09", &gone));
    assert!(t && m.extras.is_empty() && m.unknown.is_empty());
}

#[test]
fn history_is_unioned_capped_and_dropped_on_delete() {
    use crate::{HISTORY_MAX, Version};
    let v = |at: &str| Version {
        at: at.into(),
        data: Item::default(),
    };
    let with_history = |ats: &[&str]| {
        let mut pl = p(&[("title", "01")], &[], &[]);
        pl.history = ats.iter().map(|a| v(a)).collect();
        pl
    };
    // two devices edited concurrently: each kept the version it replaced
    let (a, b) = (with_history(&["05", "03"]), with_history(&["06", "03"]));
    let (m, _) = both(&live("07", &a), &live("08", &b));
    let ats: Vec<_> = m.history.iter().map(|h| h.at.as_str()).collect();
    assert_eq!(ats, ["06", "05", "03"]);

    let many: Vec<String> = (10..30).map(|i| i.to_string()).collect();
    let big = with_history(&many.iter().map(String::as_str).collect::<Vec<_>>());
    let (m, _) = both(&live("40", &big), &live("41", &a));
    assert_eq!(m.history.len(), HISTORY_MAX);
    assert_eq!(m.history[0].at, "29");

    let dead = Payload::tombstone("99");
    let (m, tomb) = both(&tomb("99", &dead), &live("50", &a));
    assert!(tomb && m.history.is_empty());
}
