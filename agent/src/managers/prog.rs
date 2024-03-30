pub(crate) struct ProgManager {
    // ...
    pub fn get_prog(&self, id: &str) -> Result<Prog, Error> {
        let prog = self.progs.get(id).ok_or(Error::NotFound)?;
        Ok(prog.clone())
    }
    // ...
}
