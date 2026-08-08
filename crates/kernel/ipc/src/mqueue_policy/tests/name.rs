use crate::mqueue_policy::limits::{NAME_MAX, PATH_MAX};
use crate::mqueue_policy::name::check_name;
use alloc::string::String;
use syscall::errno::Errno;

fn rep(n: usize, c: char) -> String { core::iter::repeat(c).take(n).collect() }

#[test]
fn an_ordinary_component_is_accepted() {
    assert_eq!(check_name("oxide_mq"), Ok(()));
    assert_eq!(check_name(&rep(NAME_MAX, 'q')), Ok(()));
}

#[test]
fn the_empty_name_is_enoent_not_einval() {
    // glibc's `mq_open("/")` forwards "" and `getname()` answers ENOENT.
    assert_eq!(check_name(""), Err(Errno::Enoent));
}

#[test]
fn dot_dotdot_and_embedded_slash_are_eacces() {
    // Path-component validation rejects `.`, `..`, and any embedded `/` or NUL.
    assert_eq!(check_name("."), Err(Errno::Eacces));
    assert_eq!(check_name(".."), Err(Errno::Eacces));
    assert_eq!(check_name("a/b"), Err(Errno::Eacces));
    assert_eq!(check_name("/leading"), Err(Errno::Eacces));
    assert_eq!(check_name("trailing/"), Err(Errno::Eacces));
    assert_eq!(check_name("nul\0byte"), Err(Errno::Eacces));
}

#[test]
fn a_dotlike_but_longer_name_is_fine() {
    // Only exactly "." / ".." are rejected; "..." is a legal component.
    assert_eq!(check_name("..."), Ok(()));
    assert_eq!(check_name(".hidden"), Ok(()));
}

#[test]
fn over_name_max_is_enametoolong() {
    // mqueuefs's lookup rejects a component longer than NAME_MAX.
    assert_eq!(check_name(&rep(NAME_MAX + 1, 'q')), Err(Errno::Enametoolong));
}

#[test]
fn getname_length_beats_the_slash_check_but_name_max_does_not() {
    // ORDER contract: `getname()` (PATH_MAX) runs first, then the `/` scan,
    // then `->lookup`'s NAME_MAX. So a 300-char name WITH a slash is EACCES,
    // while a PATH_MAX-long one is ENAMETOOLONG even though it has a slash.
    let mut mid = rep(NAME_MAX + 45, 'q');
    mid.push('/');
    assert_eq!(check_name(&mid), Err(Errno::Eacces));

    let mut huge = rep(PATH_MAX, 'q');
    huge.push('/');
    assert_eq!(check_name(&huge), Err(Errno::Enametoolong));
}
