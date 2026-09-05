//! Human vs. `--json` output.
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub struct Output {
    pub json: bool,
}

impl Output {
    pub fn emit(
        &self,
        value: serde_json::Value,
        human: impl FnOnce() -> String,
    ) -> anyhow::Result<()> {
        if self.json {
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            Self::print_human(human);
        }
        Ok(())
    }

    /// Like [`Output::emit`], but for payloads carrying key material: the rendered JSON lives in a
    /// buffer that is wiped on drop. The human closure must leave the secret out – the caller
    /// prints it straight from its own wiped buffer.
    pub fn emit_secret(
        &self,
        value: serde_json::Value,
        human: impl FnOnce() -> String,
    ) -> anyhow::Result<()> {
        if self.json {
            let rendered = Zeroizing::new(serde_json::to_string_pretty(&value)?);
            // `serde_json::Value` cannot be wiped, so drop its copy of the secret right away.
            drop(value);
            println!("{}", rendered.as_str());
        } else {
            Self::print_human(human);
        }
        Ok(())
    }

    fn print_human(human: impl FnOnce() -> String) {
        let text = human();
        if !text.is_empty() {
            println!("{text}");
        }
    }
}
