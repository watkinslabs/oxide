fn main() {
    use windows_console::{input_to_utf16, output_from_utf16, ConsoleCodePage};
    let input = input_to_utf16(ConsoleCodePage::Utf8, "Notepad: Ω😀".as_bytes()).expect("UTF-8 console input");
    let output = output_from_utf16(ConsoleCodePage::Utf8, &input).expect("UTF-16 console output");
    assert_eq!(output, "Notepad: Ω😀".as_bytes());
    println!("windows-console: PASS (strict UTF-8/UTF-16 console boundary)");
}
