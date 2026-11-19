//! Folder, tags and favorite of an item (#65). Separate from the content edit so one command
//! serves every item type and a content save never overwrites a concurrent re-filing: the merge
//! stamps `folder`, `favorite` and each tag on their own.

use super::*;

/// Where an item is filed. Whitespace is trimmed; an empty folder means none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub favorite: bool,
    pub folder: String,
    pub tags: Vec<String>,
}

impl Account {
    /// Re-file the item `id` of the active vault. Tags are trimmed, de-duplicated and sorted.
    pub fn set_organization(
        &mut self,
        id: &str,
        o: &Organization,
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let old = self.session.open_record(&self.live(id)?)?;
        let mut payload = old.clone();
        let d = &mut payload.data;
        d.favorite = o.favorite;
        d.folder = Some(o.folder.trim().to_owned()).filter(|f| !f.is_empty());
        let mut tags: Vec<String> = o.tags.iter().map(|t| t.trim().to_owned()).collect();
        tags.retain(|t| !t.is_empty());
        tags.sort();
        tags.dedup();
        d.tags = tags;
        if *d == old.data {
            return Ok(());
        }
        d.updated_at = now_ms;
        self.write(id, Some(&old), Some(payload), now_ms)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const PW: &str = "correct horse battery staple 42!";

    #[test]
    fn filing_is_normalized_listed_and_survives_a_content_edit() {
        let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
        let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
        let mut a = setup.confirm(&code, NOW).unwrap();
        let login = LoginFields {
            title: "Mail".into(),
            username: "me".into(),
            password: "pw".into(),
            url: String::new(),
            notes: String::new(),
        };
        let id = a.save_login(None, &login, NOW + 1).unwrap();
        let other = a.save_login(None, &login, NOW + 1).unwrap();

        let o = Organization {
            favorite: true,
            folder: " Work/Mail ".into(),
            tags: vec!["b".into(), " a ".into(), "b".into(), " ".into()],
        };
        a.set_organization(&id, &o, NOW + 2).unwrap();
        let row = |a: &Account, id: &str| {
            a.list_items()
                .unwrap()
                .into_iter()
                .find(|i| i.id == id)
                .unwrap()
        };
        let r = row(&a, &id);
        assert_eq!(
            (r.favorite, r.folder.as_str(), r.tags),
            (true, "Work/Mail", vec!["a".to_owned(), "b".to_owned()])
        );
        let untouched = row(&a, &other);
        assert!(!untouched.favorite && untouched.folder.is_empty() && untouched.tags.is_empty());

        // editing the content keeps the filing; clearing it empties the fields again
        let edited = LoginFields {
            title: "Mail 2".into(),
            ..login
        };
        a.save_login(Some(&id), &edited, NOW + 3).unwrap();
        assert_eq!(row(&a, &id).folder, "Work/Mail");
        let cleared = Organization {
            favorite: false,
            folder: String::new(),
            tags: vec![],
        };
        a.set_organization(&id, &cleared, NOW + 4).unwrap();
        let r = row(&a, &id);
        assert!(!r.favorite && r.folder.is_empty() && r.tags.is_empty());

        assert!(matches!(
            a.set_organization("nope", &cleared, NOW + 5),
            Err(AccountError::NotFound)
        ));
    }
}
